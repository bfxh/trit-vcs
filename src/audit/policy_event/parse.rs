//! `policy` 事件字段的容错解析：schema 决定哪些字段参与语义与签名复算。

use std::collections::BTreeMap;

use serde_json::Value;

use crate::audit::AuditIssue;
use crate::journal::Event;
use crate::policy::{
    MAX_POLICY_THRESHOLD, POLICY_SCHEMA, POLICY_SCHEMA_V2, POLICY_SCHEMA_V3, POLICY_SCHEMA_V4,
    POLICY_SCHEMA_V5, POLICY_SCHEMA_V6, normalize_policy_roles,
};

pub(crate) fn require_signed_witness(event: &Event) -> bool {
    let versioned = matches!(
        event.payload.get("schema").and_then(Value::as_str),
        Some(schema) if schema == POLICY_SCHEMA || schema == POLICY_SCHEMA_V2 || schema == POLICY_SCHEMA_V3 || schema == POLICY_SCHEMA_V4 || schema == POLICY_SCHEMA_V5 || schema == POLICY_SCHEMA_V6
    );
    match event.payload.get("require_signed_witness") {
        Some(Value::Bool(value)) => *value,
        None => versioned,
        Some(_) => true,
    }
}

pub(crate) fn require_signed_claims(event: &Event) -> bool {
    let versioned = matches!(
        event.payload.get("schema").and_then(Value::as_str),
        Some(schema) if schema == POLICY_SCHEMA || schema == POLICY_SCHEMA_V2 || schema == POLICY_SCHEMA_V3 || schema == POLICY_SCHEMA_V4 || schema == POLICY_SCHEMA_V5 || schema == POLICY_SCHEMA_V6
    );
    event
        .payload
        .get("require_signed_claims")
        .and_then(Value::as_bool)
        .unwrap_or(versioned)
}

pub(crate) struct ReasonFields<'a> {
    pub(super) require: bool,
    pub(super) reason: &'a str,
    pub(super) ticket: Option<&'a str>,
}

pub(crate) fn check_reason<'a>(
    event: &'a Event,
    require_reason: bool,
    issues: &mut Vec<AuditIssue>,
) -> ReasonFields<'a> {
    let v6 = event.payload.get("schema").and_then(Value::as_str) == Some(POLICY_SCHEMA_V6);
    let require_policy_reason = event_require_policy_reason(event);
    if v6
        && event
            .payload
            .get("require_policy_reason")
            .is_some_and(|value| !value.is_boolean())
    {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条 policy 事件的 require_policy_reason 不是布尔值",
                event.seq
            ),
        ));
    }
    if v6 && event.payload.get("require_policy_reason").is_none() {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条 policy 事件缺 require_policy_reason", event.seq),
        ));
    }
    let policy_reason = if v6 {
        match event_policy_reason(event) {
            Ok(reason) => reason,
            Err(err) => {
                issues.push(AuditIssue::new(
                    "policy_bad",
                    format!(
                        "第 {} 条 policy 事件的 policy_reason 非法：{err}",
                        event.seq
                    ),
                ));
                ""
            }
        }
    } else {
        ""
    };
    let policy_ticket = if v6 {
        match event_policy_ticket(event) {
            Ok(ticket) => ticket,
            Err(err) => {
                issues.push(AuditIssue::new(
                    "policy_bad",
                    format!(
                        "第 {} 条 policy 事件的 policy_ticket 非法：{err}",
                        event.seq
                    ),
                ));
                None
            }
        }
    } else {
        None
    };
    if require_reason && (!v6 || policy_reason.trim().is_empty()) {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条 policy 事件在 require_policy_reason 下缺非空 policy_reason",
                event.seq
            ),
        ));
    }

    ReasonFields {
        require: require_policy_reason,
        reason: policy_reason,
        ticket: policy_ticket,
    }
}

pub(super) fn event_threshold(event: &Event) -> u8 {
    event
        .payload
        .get("policy_threshold")
        .and_then(Value::as_u64)
        .filter(|value| (1..=u64::from(MAX_POLICY_THRESHOLD)).contains(value))
        .map(|value| value as u8)
        .unwrap_or(1)
}

pub(super) fn event_policy_roles(event: &Event) -> Result<Vec<String>, String> {
    normalize_policy_roles(&event_policy_roles_raw(event)?).map_err(|err| err.to_string())
}

pub(super) fn event_policy_roles_raw(event: &Event) -> Result<Vec<String>, String> {
    let schema = event.payload.get("schema").and_then(Value::as_str);
    if schema != Some(POLICY_SCHEMA_V3)
        && schema != Some(POLICY_SCHEMA_V4)
        && schema != Some(POLICY_SCHEMA_V5)
        && schema != Some(POLICY_SCHEMA_V6)
    {
        return Ok(vec!["auditor".into()]);
    }
    let Some(values) = event.payload.get("policy_roles").and_then(Value::as_array) else {
        return Err("policy_roles 缺失或不是数组".to_string());
    };
    let mut roles = Vec::new();
    for value in values {
        let Some(role) = value.as_str() else {
            return Err("policy_roles 含非字符串项".to_string());
        };
        roles.push(role.to_string());
    }
    Ok(roles)
}

pub(super) fn event_policy_principal_quorum(event: &Event) -> bool {
    let schema = event.payload.get("schema").and_then(Value::as_str);
    if schema != Some(POLICY_SCHEMA_V4)
        && schema != Some(POLICY_SCHEMA_V5)
        && schema != Some(POLICY_SCHEMA_V6)
    {
        return false;
    }
    event
        .payload
        .get("policy_principal_quorum")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

pub(super) fn event_policy_role_thresholds(event: &Event) -> Result<BTreeMap<String, u8>, String> {
    let schema = event.payload.get("schema").and_then(Value::as_str);
    if schema != Some(POLICY_SCHEMA_V5) && schema != Some(POLICY_SCHEMA_V6) {
        return Ok(BTreeMap::new());
    }
    let Some(value) = event.payload.get("policy_role_thresholds") else {
        return Err("policy_role_thresholds 缺失".to_string());
    };
    let Some(object) = value.as_object() else {
        return Err("policy_role_thresholds 不是对象".to_string());
    };
    let mut thresholds = BTreeMap::new();
    for (role, value) in object {
        let Some(threshold) = value.as_u64() else {
            return Err(format!("角色 {role} 的签名阈值不是整数"));
        };
        if !(1..=u64::from(MAX_POLICY_THRESHOLD)).contains(&threshold) {
            return Err(format!(
                "角色 {role} 的签名阈值超出 1..={MAX_POLICY_THRESHOLD}"
            ));
        }
        thresholds.insert(role.clone(), threshold as u8);
    }
    Ok(thresholds)
}

pub(super) fn event_require_policy_reason(event: &Event) -> bool {
    let schema = event.payload.get("schema").and_then(Value::as_str);
    schema == Some(POLICY_SCHEMA_V6)
        && event
            .payload
            .get("require_policy_reason")
            .and_then(Value::as_bool)
            .unwrap_or(false)
}

pub(super) fn event_policy_reason(event: &Event) -> Result<&str, String> {
    let schema = event.payload.get("schema").and_then(Value::as_str);
    if schema != Some(POLICY_SCHEMA_V6) {
        return Ok("");
    }
    event
        .payload
        .get("policy_reason")
        .and_then(Value::as_str)
        .ok_or_else(|| "policy_reason 缺失或不是字符串".to_string())
}

pub(super) fn event_policy_ticket(event: &Event) -> Result<Option<&str>, String> {
    let schema = event.payload.get("schema").and_then(Value::as_str);
    if schema != Some(POLICY_SCHEMA_V6) {
        return Ok(None);
    }
    match event.payload.get("policy_ticket") {
        Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err("policy_ticket 不是字符串或 null".to_string()),
        None => Err("policy_ticket 缺失".to_string()),
    }
}
