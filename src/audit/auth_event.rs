//! `auth` 事件的语义检查：鉴权失败也必须说清请求形状，不能只写一句“被拒”。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::journal::Event;

pub(super) fn check_auth(
    event: &Event,
    issues: &mut Vec<AuditIssue>,
    warnings: &mut Vec<AuditIssue>,
) {
    if event.payload.get("decision").and_then(Value::as_str) != Some("denied") {
        issues.push(AuditIssue::new(
            "auth_bad",
            format!("第 {} 条 auth 事件的 decision 不是 denied", event.seq),
        ));
    }
    if event
        .payload
        .get("reason")
        .and_then(Value::as_str)
        .is_none()
    {
        issues.push(AuditIssue::new(
            "auth_bad",
            format!("第 {} 条 auth 事件缺 reason", event.seq),
        ));
    }
    if event
        .payload
        .get("method")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
        || event
            .payload
            .get("path")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        issues.push(AuditIssue::new(
            "auth_bad",
            format!("第 {} 条 auth 事件缺 method/path", event.seq),
        ));
    }
    if event.payload.get("status").and_then(Value::as_u64) != Some(401) {
        issues.push(AuditIssue::new(
            "auth_bad",
            format!("第 {} 条 auth 事件的 status 不是 401", event.seq),
        ));
    }
    if parse_hash(event.payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "auth_no_state",
            format!("第 {} 条 auth 事件没有可解析的 state_after", event.seq),
        ));
    }
}
