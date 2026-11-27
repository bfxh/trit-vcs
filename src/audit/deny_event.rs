//! `deny` 事件的语义检查：业务拒绝必须写清入口、原因与请求形状。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::journal::Event;

pub(super) fn check_deny(
    events: &[Event],
    index: usize,
    event: &Event,
    issues: &mut Vec<AuditIssue>,
    warnings: &mut Vec<AuditIssue>,
) {
    if event
        .payload
        .get("action")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        issues.push(AuditIssue::new(
            "deny_bad",
            format!("第 {} 条 deny 事件缺 action", event.seq),
        ));
    }
    if event.payload.get("decision").and_then(Value::as_str) != Some("denied") {
        issues.push(AuditIssue::new(
            "deny_bad",
            format!("第 {} 条 deny 事件的 decision 不是 denied", event.seq),
        ));
    }
    if event
        .payload
        .get("reason")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        issues.push(AuditIssue::new(
            "deny_bad",
            format!("第 {} 条 deny 事件缺 reason", event.seq),
        ));
    }
    if event
        .payload
        .get("message")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        issues.push(AuditIssue::new(
            "deny_bad",
            format!("第 {} 条 deny 事件缺 message", event.seq),
        ));
    }
    let detail = event.payload.get("detail").and_then(Value::as_object);
    let source = detail.and_then(|detail| detail.get("source"));
    if let Some(source) = source
        && let Some(detail) = detail
    {
        if !valid_source(source) {
            issues.push(AuditIssue::new(
                "deny_bad",
                format!("第 {} 条 deny 事件的 source 不是合法 IP", event.seq),
            ));
        } else {
            check_auth_binding(events, index, event, detail, issues);
        }
    }
    if parse_hash(event.payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "deny_no_state",
            format!("第 {} 条 deny 事件没有可解析的 state_after", event.seq),
        ));
    }
}

fn check_auth_binding(
    events: &[Event],
    index: usize,
    event: &Event,
    detail: &serde_json::Map<String, Value>,
    issues: &mut Vec<AuditIssue>,
) {
    let Some(request_id) = detail
        .get("request_id")
        .and_then(|value| parse_hash(Some(value)))
    else {
        issues.push(AuditIssue::new(
            "deny_unbound",
            format!(
                "第 {} 条带 source 的 deny 事件缺合法 request_id，无法对上放行鉴权",
                event.seq
            ),
        ));
        return;
    };
    let auth = events[..index].iter().rev().find(|prior| {
        prior.kind == "auth"
            && prior.payload.get("decision").and_then(Value::as_str) == Some("allowed")
            && prior
                .payload
                .get("request_id")
                .and_then(|value| parse_hash(Some(value)))
                == Some(request_id)
    });
    let Some(auth) = auth else {
        issues.push(AuditIssue::new(
            "deny_unbound",
            format!(
                "第 {} 条 deny 的 request_id {} 找不到前面的放行鉴权",
                event.seq,
                request_id.short()
            ),
        ));
        return;
    };
    if let (Some(deny_source), Some(auth_source)) = (
        detail.get("source").and_then(Value::as_str),
        auth.payload.get("source").and_then(Value::as_str),
    ) && deny_source != auth_source
    {
        issues.push(AuditIssue::new(
            "deny_unbound",
            format!(
                "第 {} 条 deny 的 source {deny_source} 与放行鉴权 {} 不一致",
                event.seq, auth.seq
            ),
        ));
    }
    if let (Some(deny_actor), Some(auth_actor)) = (
        detail.get("actor").and_then(Value::as_str),
        auth.payload.get("actor").and_then(Value::as_str),
    ) && deny_actor != auth_actor
    {
        issues.push(AuditIssue::new(
            "deny_unbound",
            format!(
                "第 {} 条 deny 的 actor {deny_actor} 与放行鉴权 {} 不一致",
                event.seq, auth.seq
            ),
        ));
    }
}

fn valid_source(value: &Value) -> bool {
    value
        .as_str()
        .is_some_and(|raw| raw.parse::<std::net::IpAddr>().is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;

    const REQUEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";

    fn auth(source: &str, actor: &str) -> Event {
        Event {
            seq: 1,
            at_ms: 1,
            kind: "auth".to_string(),
            hash: Hash::of(b"auth"),
            payload: serde_json::json!({
                "schema": "trit-auth-v2",
                "action": "auth",
                "decision": "allowed",
                "method": "GET",
                "path": "/v1/health",
                "request_id": REQUEST,
                "actor": actor,
                "source": source,
                "state_before": Hash::of(b"state").to_hex(),
                "state_after": Hash::of(b"state").to_hex(),
            }),
            prev: None,
        }
    }

    fn deny(source: Value) -> Event {
        Event {
            seq: 2,
            at_ms: 2,
            kind: "deny".to_string(),
            hash: Hash::of(b"deny"),
            payload: serde_json::json!({
                "action": "pull",
                "decision": "denied",
                "reason": "bad_ref",
                "message": "bad",
                "detail": { "source": source, "request_id": REQUEST, "actor": "qoder:ci" },
                "state_after": Hash::of(b"state").to_hex(),
            }),
            prev: None,
        }
    }

    fn check(events: &[Event], index: usize) -> Vec<AuditIssue> {
        let mut issues = Vec::new();
        let mut warnings = Vec::new();
        check_deny(events, index, &events[index], &mut issues, &mut warnings);
        issues
    }

    #[test]
    fn deny_source_must_be_an_ip_when_present() {
        let events = [
            auth("2001:db8::1", "qoder:ci"),
            deny(Value::from("2001:db8::1")),
        ];
        assert!(check(&events, 1).is_empty(), "{:?}", check(&events, 1));

        let issues = check(&[deny(Value::from("not-an-ip"))], 0);
        assert!(
            issues
                .iter()
                .any(|issue| issue.kind == "deny_bad" && issue.detail.contains("source")),
            "{issues:?}"
        );
    }

    #[test]
    fn source_bearing_deny_must_match_preceding_allowed_auth() {
        let events = [
            auth("127.0.0.1", "qoder:ci"),
            deny(Value::from("127.0.0.1")),
        ];
        assert!(check(&events, 1).is_empty(), "{:?}", check(&events, 1));

        let missing = check(&[deny(Value::from("127.0.0.1"))], 0);
        assert!(
            missing
                .iter()
                .any(|issue| issue.kind == "deny_unbound" && issue.detail.contains("request_id")),
            "{missing:?}"
        );

        let source_mismatch = [auth("10.0.0.1", "qoder:ci"), deny(Value::from("127.0.0.1"))];
        assert!(
            check(&source_mismatch, 1)
                .iter()
                .any(|issue| issue.kind == "deny_unbound" && issue.detail.contains("source")),
            "source 不一致必须判红"
        );

        let actor_mismatch = [
            auth("127.0.0.1", "qoder:other"),
            deny(Value::from("127.0.0.1")),
        ];
        assert!(
            check(&actor_mismatch, 1)
                .iter()
                .any(|issue| issue.kind == "deny_unbound" && issue.detail.contains("actor")),
            "actor 不一致必须判红"
        );
    }
}
