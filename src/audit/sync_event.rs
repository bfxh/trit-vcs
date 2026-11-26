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
    check_view(events, index, event, transport, side, issues);
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

/// 客户端视图/pin 只允许出现在 source/client 的 HTTP 同步上；其它组合只能留空。
fn check_view(
    events: &[Event],
    index: usize,
    event: &Event,
    transport: Option<&str>,
    side: Option<&str>,
    issues: &mut Vec<AuditIssue>,
) {
    let remote = event.payload.get("remote");
    let view = event.payload.get("view");
    let is_client_http = transport == Some("http") && matches!(side, Some("source" | "client"));
    if !is_client_http {
        let remote_set = remote.is_some_and(|value| !value.is_null());
        let view_set = view.is_some_and(|value| !value.is_null());
        if remote_set || view_set {
            view_bad(issues, event, "中央仓/本地同步不得携带 remote/view");
        }
        return;
    }
    if remote.is_none() && view.is_none() {
        return;
    }
    let Some(remote) = remote.and_then(Value::as_str) else {
        view_bad(issues, event, "带视图的同步缺 remote");
        return;
    };
    if !crate::view::valid_remote(remote) {
        view_bad(issues, event, "remote 不是 http://host:port");
        return;
    }
    let Some(view_value) = view.filter(|value| !value.is_null()) else {
        // `--no-pin` 的显式降级：只记 remote，不记视图。
        return;
    };
    let snapshot = match crate::view::Snapshot::from_evidence(view_value) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            view_bad(issues, event, &format!("view 形状不合法：{err}"));
            return;
        }
    };
    if snapshot.tip != parse_hash(event.payload.get("commit")) {
        view_bad(issues, event, "view.tip 与 commit 不一致");
    }
    let status = view_value.get("pin_status").and_then(Value::as_str);
    let pin_before = view_value.get("pin_before");
    match status {
        Some("first") => {
            if !pin_before.is_some_and(Value::is_null) {
                view_bad(issues, event, "首次 pin 的 pin_before 必须为空");
            }
        }
        Some("unchanged" | "advanced") => {
            let Some(pin_value) = pin_before else {
                view_bad(issues, event, "非首次 pin 缺 pin_before");
                return;
            };
            let pin = match crate::view::Pin::from_json(pin_value) {
                Ok(pin) => pin,
                Err(err) => {
                    view_bad(issues, event, &format!("pin_before 形状不合法：{err}"));
                    return;
                }
            };
            if pin.height > snapshot.height {
                view_bad(issues, event, "pin_before 比本次视图还长");
            } else if pin.height == snapshot.height && pin.root != snapshot.root {
                view_bad(issues, event, "同高度的 pin_before 与视图根不同");
            } else if status == Some("unchanged") && pin.height != snapshot.height {
                view_bad(issues, event, "unchanged 的 pin_before 高度必须与视图相同");
            } else if status == Some("advanced") && pin.height == snapshot.height {
                view_bad(issues, event, "advanced 的视图必须比 pin_before 长");
            }
        }
        _ => view_bad(issues, event, "pin_status 不合法"),
    }

    // 同一 remote/ref 的已落账视图只能单调往后长：先找最近一条同键事件。
    for prior in events[..index].iter().rev() {
        if prior.payload.get("schema").and_then(Value::as_str) != Some(SCHEMA)
            || !matches!(prior.kind.as_str(), "publish" | "pull")
            || prior.payload.get("transport").and_then(Value::as_str) != Some("http")
            || !matches!(
                prior.payload.get("side").and_then(Value::as_str),
                Some("source" | "client")
            )
            || prior.payload.get("remote").and_then(Value::as_str) != Some(remote)
            || prior.payload.get("name").and_then(Value::as_str)
                != Some(event.payload["name"].as_str().unwrap_or_default())
        {
            continue;
        }
        let Some(prior_view) = prior.payload.get("view") else {
            continue;
        };
        let Ok(prior) = crate::view::Snapshot::from_evidence(prior_view) else {
            continue;
        };
        if snapshot.height < prior.height {
            issues.push(AuditIssue::new(
                "sync_view_rollback",
                format!(
                    "第 {} 条同步的视图高度 {} 小于同 remote/ref 上一条 {}",
                    event.seq, snapshot.height, prior.height
                ),
            ));
        } else if snapshot.height == prior.height
            && (snapshot.root != prior.root || snapshot.head != prior.head)
        {
            view_bad(issues, event, "同高度视图换根/换头，已落账的 pin 被改写");
        }
        break;
    }
}

fn view_bad(issues: &mut Vec<AuditIssue>, event: &Event, detail: &str) {
    issues.push(AuditIssue::new(
        "sync_view_bad",
        format!("第 {} 条 {} {detail}", event.seq, event.kind),
    ));
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

    fn snapshot_json(height: usize, tip: Hash) -> Value {
        let leaves: Vec<Hash> = (0..height)
            .map(|i| Hash::of(format!("view-e{i}").as_bytes()))
            .collect();
        json!({
            "schema": crate::view::SCHEMA,
            "height": height,
            "head": leaves.last().map(|id| id.to_hex()),
            "root": crate::checkpoint::merkle_root(&leaves).to_hex(),
            "tip": tip.to_hex(),
            "pin_before": null,
            "pin_status": "first",
        })
    }

    fn view_event(seq: u64, height: usize, remote: &str, prompt: &str) -> Event {
        let mut event = sync(seq, "publish", "http", "source");
        event.payload["op_id"] = json!(Hash::of(prompt.as_bytes()).to_hex());
        event.payload["remote"] = json!(remote);
        event.payload["view"] = snapshot_json(height, Hash::of(b"commit"));
        event
    }

    #[test]
    fn valid_client_view_evidence_passes() {
        let event = view_event(1, 3, "http://127.0.0.1:7878", "op-valid");
        assert!(issues(&[event]).is_empty(), "合法的 pin 证据不该报红");
    }

    #[test]
    fn central_and_local_events_must_not_carry_view() {
        let mut central = sync(1, "publish", "http", "central");
        central.payload["remote"] = json!("http://127.0.0.1:7878");
        central.payload["view"] = snapshot_json(2, Hash::of(b"commit"));
        assert!(
            issues(&[central])
                .iter()
                .any(|issue| issue.kind == "sync_view_bad")
        );
    }

    #[test]
    fn view_height_must_not_go_backwards() {
        let first = view_event(1, 3, "http://127.0.0.1:7878", "op-first");
        let second = view_event(2, 2, "http://127.0.0.1:7878", "op-second");
        assert!(
            issues(&[first, second])
                .iter()
                .any(|issue| issue.kind == "sync_view_rollback")
        );
    }

    #[test]
    fn pin_status_must_match_height_relation() {
        let first = view_event(1, 3, "http://127.0.0.1:7878", "op-first");
        let mut pin = first.payload["view"].clone();
        let object = pin.as_object_mut().unwrap();
        object.remove("schema");
        object.remove("pin_before");
        object.remove("pin_status");

        let mut advanced = view_event(2, 3, "http://127.0.0.1:7878", "op-same-height");
        advanced.payload["view"]["pin_before"] = pin.clone();
        advanced.payload["view"]["pin_status"] = json!("advanced");
        assert!(
            issues(&[first.clone(), advanced])
                .iter()
                .any(|issue| issue.kind == "sync_view_bad")
        );

        let mut unchanged = view_event(2, 4, "http://127.0.0.1:7878", "op-grew");
        unchanged.payload["view"]["pin_before"] = pin;
        unchanged.payload["view"]["pin_status"] = json!("unchanged");
        assert!(
            issues(&[first, unchanged])
                .iter()
                .any(|issue| issue.kind == "sync_view_bad")
        );
    }

    #[test]
    fn view_tip_must_match_commit_and_remote_must_be_narrow() {
        let mut event = view_event(1, 3, "http://127.0.0.1:7878", "op-bad-tip");
        event.payload["view"]["tip"] = json!(Hash::of(b"other").to_hex());
        assert!(
            issues(&[event])
                .iter()
                .any(|issue| issue.kind == "sync_view_bad")
        );

        let event = view_event(1, 3, "http://127.0.0.1:7878/path", "op-bad-remote");
        assert!(
            issues(&[event])
                .iter()
                .any(|issue| issue.kind == "sync_view_bad")
        );
    }
}
