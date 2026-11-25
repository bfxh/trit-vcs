//! `trit-sync-v1` 成功事件：核对关联字段、执行阶段与中央仓鉴权前置事件。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::hash::Hash;
use crate::journal::Event;
use crate::sync::SCHEMA;

pub(super) fn check_sync(
    events: &[Event],
    index: usize,
    event: &Event,
    issues: &mut Vec<AuditIssue>,
) {
    let Some(schema) = event.payload.get("schema") else {
        return;
    };
    if schema.as_str() != Some(SCHEMA) {
        bad(issues, event, "schema 不受支持");
        return;
    }
    let action = event.payload.get("action").and_then(Value::as_str);
    if action != Some(event.kind.as_str()) || !matches!(action, Some("publish" | "pull")) {
        bad(issues, event, "action 与事件类型不一致");
    }
    let Some(op_id) = event.payload.get("op_id").and_then(Value::as_str) else {
        bad(issues, event, "缺 op_id");
        return;
    };
    let op_hash = Hash::from_hex(op_id);
    if !crate::sync::valid_op_id(op_id) {
        bad(issues, event, "op_id 不是合法哈希");
    }
    let transport = event.payload.get("transport").and_then(Value::as_str);
    let side = event.payload.get("side").and_then(Value::as_str);
    if !matches!(transport, Some("local" | "http"))
        || !matches!(side, Some("source" | "central" | "client"))
    {
        bad(issues, event, "transport/side 不合法");
    }
    let stage = event.payload.get("stage").and_then(Value::as_str);
    let stage_ok = match (action, transport, side) {
        (Some("publish"), _, Some("source")) => stage == Some("recorded"),
        (Some("publish"), _, Some("central")) => stage == Some("applied"),
        (Some("pull"), _, Some("client")) => stage == Some("applied"),
        (Some("pull"), Some("local"), Some("central")) => stage == Some("prepared"),
        (Some("pull"), Some("http"), Some("central")) => stage == Some("response_sent"),
        _ => false,
    };
    if !stage_ok {
        bad(issues, event, "stage 与 action/transport/side 不一致");
    }
    let request_id = event.payload.get("request_id");
    match transport {
        Some("http") if parse_hash(request_id).is_none() => {
            bad(issues, event, "HTTP 同步缺合法 request_id");
        }
        Some("local") if !request_id.is_some_and(Value::is_null) => {
            bad(issues, event, "本地同步不得伪造 request_id");
        }
        _ => {}
    }
    let actor = event.payload.get("actor").and_then(Value::as_str);
    match (transport, side) {
        (Some("http"), Some("central")) if !actor.is_some_and(valid_actor) => {
            bad(issues, event, "中央仓 HTTP 同步缺合法 actor");
        }
        (Some("local"), _) if !event.payload.get("actor").is_some_and(Value::is_null) => {
            bad(issues, event, "本地同步不得伪造 actor");
        }
        (_, Some("source" | "client"))
            if !event.payload.get("actor").is_some_and(Value::is_null) =>
        {
            bad(issues, event, "source/client 不得自报服务端 actor");
        }
        _ => {}
    }
    if event
        .payload
        .get("name")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || parse_hash(event.payload.get("commit")).is_none()
        || parse_hash(event.payload.get("state_before")).is_none()
        || parse_hash(event.payload.get("state_after")).is_none()
    {
        bad(issues, event, "缺 name/commit/state_before/state_after");
    }
    if let (Some("http"), Some("central"), Some(request_id)) =
        (transport, side, parse_hash(request_id))
        && !events[..index].iter().any(|prior| {
            prior.kind == "auth"
                && prior.payload.get("schema").and_then(Value::as_str) == Some("trit-auth-v2")
                && prior.payload.get("decision").and_then(Value::as_str) == Some("allowed")
                && parse_hash(prior.payload.get("request_id")) == Some(request_id)
                && prior.payload.get("actor").and_then(Value::as_str) == actor
                && prior.payload.get("method").and_then(Value::as_str)
                    == Some(if action == Some("publish") {
                        "POST"
                    } else {
                        "GET"
                    })
                && prior.payload.get("path").and_then(Value::as_str)
                    == Some(if action == Some("publish") {
                        "/v1/publish"
                    } else {
                        "/v1/pull"
                    })
        })
    {
        issues.push(AuditIssue::new(
            "sync_auth_missing",
            format!(
                "第 {} 条中央仓同步找不到同 request_id 的放行鉴权事件",
                event.seq
            ),
        ));
    }
    if events.iter().enumerate().any(|(other_index, other)| {
        other_index != index
            && other.payload.get("schema").and_then(Value::as_str) == Some(SCHEMA)
            && op_hash.is_some_and(|op| {
                other
                    .payload
                    .get("op_id")
                    .and_then(Value::as_str)
                    .and_then(Hash::from_hex)
                    == Some(op)
            })
            && other.payload.get("side").and_then(Value::as_str) == side
    }) {
        issues.push(AuditIssue::new(
            "sync_duplicate",
            format!("第 {} 条同步的 op_id/side 重复", event.seq),
        ));
    }
}

fn valid_actor(actor: &str) -> bool {
    !actor.is_empty() && actor.len() <= 128 && !actor.chars().any(char::is_control)
}

fn bad(issues: &mut Vec<AuditIssue>, event: &Event, detail: &str) {
    issues.push(AuditIssue::new(
        "sync_bad",
        format!("第 {} 条 {} {detail}", event.seq, event.kind),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;
    use serde_json::json;

    fn event(seq: u64, kind: &str, payload: Value) -> Event {
        Event {
            seq,
            at_ms: seq,
            kind: kind.to_string(),
            hash: Hash::of(format!("{seq}:{kind}").as_bytes()),
            payload,
            prev: None,
        }
    }

    fn sync(seq: u64, action: &str, transport: &str, side: &str) -> Event {
        let request_id = (transport == "http").then(|| Hash::of(b"request").to_hex());
        let actor = (transport == "http" && side == "central").then(|| "qoder:ci".to_string());
        let stage = match (action, transport, side) {
            ("publish", _, "source") => "recorded",
            ("publish", _, "central") => "applied",
            ("pull", "local", "central") => "prepared",
            ("pull", "http", "central") => "response_sent",
            _ => "applied",
        };
        event(
            seq,
            action,
            json!({
                "schema": SCHEMA,
                "action": action,
                "op_id": Hash::of(b"op").to_hex(),
                "transport": transport,
                "side": side,
                "request_id": request_id,
                "actor": actor,
                "name": "main",
                "commit": Hash::of(b"commit").to_hex(),
                "stage": stage,
                "state_before": Hash::of(b"before").to_hex(),
                "state_after": Hash::of(b"after").to_hex(),
            }),
        )
    }

    fn issues(events: &[Event]) -> Vec<AuditIssue> {
        let mut out = Vec::new();
        check_sync(events, events.len() - 1, events.last().unwrap(), &mut out);
        out
    }

    #[test]
    fn legacy_sync_event_without_schema_stays_compatible() {
        assert!(issues(&[event(1, "publish", json!({"name": "main"}))]).is_empty());
    }

    #[test]
    fn valid_http_source_and_client_events_need_no_local_auth() {
        for (action, side) in [("publish", "source"), ("pull", "client")] {
            assert!(issues(&[sync(1, action, "http", side)]).is_empty());
        }
    }

    #[test]
    fn central_http_event_must_follow_matching_allowed_auth() {
        let request_id = Hash::of(b"request").to_hex();
        let auth = event(
            1,
            "auth",
            json!({
                "schema": "trit-auth-v2",
                "decision": "allowed",
                "request_id": request_id.to_uppercase(),
                "actor": "qoder:ci",
                "method": "POST",
                "path": "/v1/publish",
            }),
        );
        let publish = sync(2, "publish", "http", "central");
        assert!(issues(&[auth, publish.clone()]).is_empty());
        assert!(issues(&[publish])[0].kind == "sync_auth_missing");
    }

    #[test]
    fn local_sync_rejects_remote_identity_fields() {
        let mut publish = sync(1, "publish", "local", "central");
        publish.payload["request_id"] = json!(Hash::of(b"request").to_hex());
        assert!(
            issues(&[publish])
                .iter()
                .any(|issue| issue.kind == "sync_bad")
        );
    }

    #[test]
    fn duplicate_op_id_on_the_same_side_is_red() {
        let op_id = Hash::of(b"op").to_hex();
        let mut first = sync(1, "publish", "http", "source");
        first.payload["op_id"] = json!(op_id);
        let mut second = sync(2, "publish", "http", "source");
        second.payload["op_id"] = json!(op_id.to_uppercase());
        assert!(
            issues(&[first, second])
                .iter()
                .any(|issue| issue.kind == "sync_duplicate")
        );
        let pull = sync(2, "pull", "local", "central");
        assert!(
            issues(&[sync(1, "publish", "local", "central"), pull])
                .iter()
                .any(|issue| issue.kind == "sync_duplicate")
        );
    }

    #[test]
    fn invalid_correlation_shapes_are_red() {
        let mut publish = sync(1, "publish", "http", "source");
        publish.payload["op_id"] = json!("broken");
        assert!(
            issues(&[publish.clone()])
                .iter()
                .any(|issue| issue.kind == "sync_bad")
        );

        let mut wrapped = sync(1, "publish", "http", "source");
        let op_id = Hash::of(b"op").to_hex();
        wrapped.payload["op_id"] = json!(format!("\r\n{op_id}\r\n"));
        assert!(
            issues(&[wrapped])
                .iter()
                .any(|issue| issue.kind == "sync_bad")
        );

        let mut pull = sync(1, "pull", "http", "client");
        pull.payload["request_id"] = json!(null);
        assert!(issues(&[pull]).iter().any(|issue| issue.kind == "sync_bad"));

        let mut local = sync(1, "publish", "local", "source");
        local.payload["actor"] = json!("qoder:ci");
        assert!(
            issues(&[local])
                .iter()
                .any(|issue| issue.kind == "sync_bad")
        );
    }

    #[test]
    fn unknown_schema_and_wrong_stage_are_red() {
        let mut publish = sync(1, "publish", "http", "source");
        publish.payload["schema"] = json!("trit-sync-v99");
        assert!(issues(&[publish])[0].kind == "sync_bad");
        let mut pull = sync(1, "pull", "http", "client");
        pull.payload["stage"] = json!("response_sent");
        assert!(issues(&[pull]).iter().any(|issue| issue.kind == "sync_bad"));
    }
}
