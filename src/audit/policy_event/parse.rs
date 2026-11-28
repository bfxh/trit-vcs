//! `policy` 事件字段的容错解析：schema 决定哪些字段参与语义与签名复算。

use std::collections::BTreeMap;

use serde_json::Value;

use crate::journal::Event;
use crate::policy::{
    MAX_POLICY_THRESHOLD, POLICY_SCHEMA_V3, POLICY_SCHEMA_V4, POLICY_SCHEMA_V5,
    normalize_policy_roles,
};

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
    if schema != Some(POLICY_SCHEMA_V4) && schema != Some(POLICY_SCHEMA_V5) {
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
    if schema != Some(POLICY_SCHEMA_V5) {
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
