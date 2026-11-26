//! `auth` 事件的语义检查：拒绝要保留请求形状，放行要绑定服务端 actor 与 request id。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::journal::Event;

pub(super) fn check_auth(
    event: &Event,
    issues: &mut Vec<AuditIssue>,
    warnings: &mut Vec<AuditIssue>,
) {
    let versioned = event.payload.get("schema").and_then(Value::as_str) == Some("trit-auth-v2");
    if event
        .payload
        .get("schema")
        .is_some_and(|schema| schema.as_str() != Some("trit-auth-v2"))
    {
        issues.push(AuditIssue::new(
            "auth_bad",
            format!("第 {} 条 auth 事件的 schema 不受支持", event.seq),
        ));
    }
    if versioned && parse_hash(event.payload.get("request_id")).is_none() {
        issues.push(AuditIssue::new(
            "auth_bad",
            format!("第 {} 条 auth 事件缺合法 request_id", event.seq),
        ));
    }
    if event
        .payload
        .get("source")
        .is_some_and(|source| !valid_source(source))
    {
        issues.push(AuditIssue::new(
            "auth_bad",
            format!("第 {} 条 auth 事件的 source 不是合法 IP", event.seq),
        ));
    }
    match event.payload.get("decision").and_then(Value::as_str) {
        Some("denied") => check_denied(event, issues),
        Some("allowed") => {
            if !versioned {
                issues.push(AuditIssue::new(
                    "auth_bad",
                    format!("第 {} 条放行 auth 事件缺 trit-auth-v2", event.seq),
                ));
            }
            if !event
                .payload
                .get("actor")
                .and_then(Value::as_str)
                .is_some_and(valid_actor)
            {
                issues.push(AuditIssue::new(
                    "auth_bad",
                    format!("第 {} 条放行 auth 事件缺合法 actor", event.seq),
                ));
            }
        }
        _ => issues.push(AuditIssue::new(
            "auth_bad",
            format!(
                "第 {} 条 auth 事件的 decision 不是 denied/allowed",
                event.seq
            ),
        )),
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
    if parse_hash(event.payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "auth_no_state",
            format!("第 {} 条 auth 事件没有可解析的 state_after", event.seq),
        ));
    }
}

fn check_denied(event: &Event, issues: &mut Vec<AuditIssue>) {
    if event
        .payload
        .get("reason")
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        issues.push(AuditIssue::new(
            "auth_bad",
            format!("第 {} 条 auth 事件缺 reason", event.seq),
        ));
    }
    if event.payload.get("status").and_then(Value::as_u64) != Some(401) {
        issues.push(AuditIssue::new(
            "auth_bad",
            format!("第 {} 条 auth 事件的 status 不是 401", event.seq),
        ));
    }
}

fn valid_actor(actor: &str) -> bool {
    !actor.is_empty() && actor.len() <= 128 && !actor.chars().any(char::is_control)
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

    fn event(payload: Value) -> Event {
        Event {
            seq: 1,
            at_ms: 1,
            kind: "auth".to_string(),
            hash: Hash::of(b"auth"),
            payload,
            prev: None,
        }
    }

    fn base_payload() -> Value {
        serde_json::json!({
            "schema": "trit-auth-v2",
            "action": "auth",
            "decision": "allowed",
            "method": "GET",
            "path": "/v1/health",
            "request_id": Hash::of(b"request").to_hex(),
            "actor": "test:actor",
            "state_after": Hash::of(b"state").to_hex(),
        })
    }

    #[test]
    fn source_must_be_an_ip_when_present() {
        let mut issues = Vec::new();
        let mut payload = base_payload();
        payload["source"] = Value::from("127.0.0.1");
        let mut warnings = Vec::new();
        check_auth(&event(payload), &mut issues, &mut warnings);
        assert!(
            issues.iter().all(|issue| issue.kind != "auth_bad"),
            "{issues:?}"
        );

        let mut payload = base_payload();
        payload["source"] = Value::from("127.0.0.1:8080");
        let mut issues = Vec::new();
        check_auth(&event(payload), &mut issues, &mut warnings);
        assert!(
            issues
                .iter()
                .any(|issue| issue.kind == "auth_bad" && issue.detail.contains("source")),
            "{issues:?}"
        );
    }
}
