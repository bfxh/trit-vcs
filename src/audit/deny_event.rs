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
    if parse_hash(event.payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "deny_no_state",
            format!("第 {} 条 deny 事件没有可解析的 state_after", event.seq),
        ));
    }
}
