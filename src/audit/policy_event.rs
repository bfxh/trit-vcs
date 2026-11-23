//! `policy` 事件的语义检查：策略变更不能只写文件，必须能说明谁改了什么。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::journal::Event;

pub(super) fn check_policy(
    event: &Event,
    issues: &mut Vec<AuditIssue>,
    warnings: &mut Vec<AuditIssue>,
) {
    let session = event.payload.get("session").and_then(Value::as_str);
    if session.is_none_or(str::is_empty) {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条 policy 事件缺 session", event.seq),
        ));
    }
    if event
        .payload
        .get("require_witness")
        .and_then(Value::as_bool)
        .is_none()
        || event
            .payload
            .get("require_intent")
            .and_then(Value::as_bool)
            .is_none()
    {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条 policy 事件缺策略布尔值", event.seq),
        ));
    }
    if parse_hash(event.payload.get("policy_hash")).is_none() {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条 policy 事件缺 policy_hash", event.seq),
        ));
    }
    if parse_hash(event.payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "policy_no_state",
            format!("第 {} 条 policy 事件没有可解析的 state_after", event.seq),
        ));
    }
}
