//! `key` 事件的语义检查：信任表变更必须写清 action、key_id、principal 和状态。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::journal::Event;

pub(super) fn check_key(
    event: &Event,
    issues: &mut Vec<AuditIssue>,
    warnings: &mut Vec<AuditIssue>,
) {
    let payload = &event.payload;
    let action = payload.get("action").and_then(Value::as_str);
    if !matches!(action, Some("add" | "revoke")) {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key 事件的 action 不是 add/revoke", event.seq),
        ));
    }
    for field in ["key_id", "principal", "role", "session"] {
        if payload
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            issues.push(AuditIssue::new(
                "key_bad",
                format!("第 {} 条 key 事件缺 {field}", event.seq),
            ));
        }
    }
    if action == Some("revoke")
        && payload
            .get("reason")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key revoke 事件缺 reason", event.seq),
        ));
    }
    if parse_hash(payload.get("keystore_hash")).is_none() {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key 事件缺可解析的 keystore_hash", event.seq),
        ));
    }
    if parse_hash(payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "key_no_state",
            format!("第 {} 条 key 事件没有可解析的 state_after", event.seq),
        ));
    }
}
