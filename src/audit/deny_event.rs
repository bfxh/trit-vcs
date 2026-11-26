//! `deny` 事件的语义检查：业务拒绝必须写清入口、原因与请求形状。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::journal::Event;

pub(super) fn check_deny(
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
    if event
        .payload
        .get("detail")
        .and_then(Value::as_object)
        .and_then(|detail| detail.get("source"))
        .is_some_and(|source| !valid_source(source))
    {
        issues.push(AuditIssue::new(
            "deny_bad",
            format!("第 {} 条 deny 事件的 source 不是合法 IP", event.seq),
        ));
    }
    if parse_hash(event.payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "deny_no_state",
            format!("第 {} 条 deny 事件没有可解析的 state_after", event.seq),
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

    fn event(source: Value) -> Event {
        Event {
            seq: 1,
            at_ms: 1,
            kind: "deny".to_string(),
            hash: Hash::of(b"deny"),
            payload: serde_json::json!({
                "action": "pull",
                "decision": "denied",
                "reason": "bad_ref",
                "message": "bad",
                "detail": { "source": source },
                "state_after": Hash::of(b"state").to_hex(),
            }),
            prev: None,
        }
    }

    #[test]
    fn deny_source_must_be_an_ip_when_present() {
        let mut issues = Vec::new();
        let mut warnings = Vec::new();
        check_deny(
            &event(Value::from("2001:db8::1")),
            &mut issues,
            &mut warnings,
        );
        assert!(
            issues.iter().all(|issue| issue.kind != "deny_bad"),
            "{issues:?}"
        );

        let mut issues = Vec::new();
        check_deny(&event(Value::from("not-an-ip")), &mut issues, &mut warnings);
        assert!(
            issues
                .iter()
                .any(|issue| issue.kind == "deny_bad" && issue.detail.contains("source")),
            "{issues:?}"
        );
    }
}
