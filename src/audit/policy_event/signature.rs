//! v2/v3/v4/v5 策略事件的签名项验证：阈值按不同有效 key 或主体计数，
//! 角色覆盖、角色最低签名数与主体分离单独检查。

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::Value;

use crate::audit::AuditIssue;
use crate::journal::Event;
use crate::policy::{
    Policy, policy_statement_v2_bytes, policy_statement_v3_bytes, policy_statement_v4_bytes,
    policy_statement_v5_bytes,
};

use super::{SignedFields, verify_one_signer};

#[allow(clippy::too_many_arguments)]
pub(super) fn check_v2_signatures(
    repo: &crate::repo::Repo,
    event: &Event,
    required_signatures: usize,
    required_roles: &[String],
    required_role_mins: &BTreeMap<String, usize>,
    require_principals: bool,
    fields: Option<&SignedFields<'_>>,
    issues: &mut Vec<AuditIssue>,
) {
    check_versioned_signatures(
        repo,
        event,
        required_signatures,
        required_roles,
        required_role_mins,
        require_principals,
        fields,
        2,
        issues,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn check_v3_signatures(
    repo: &crate::repo::Repo,
    event: &Event,
    required_signatures: usize,
    required_roles: &[String],
    required_role_mins: &BTreeMap<String, usize>,
    require_principals: bool,
    fields: Option<&SignedFields<'_>>,
    issues: &mut Vec<AuditIssue>,
) {
    check_versioned_signatures(
        repo,
        event,
        required_signatures,
        required_roles,
        required_role_mins,
        require_principals,
        fields,
        3,
        issues,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn check_v4_signatures(
    repo: &crate::repo::Repo,
    event: &Event,
    required_signatures: usize,
    required_roles: &[String],
    required_role_mins: &BTreeMap<String, usize>,
    require_principals: bool,
    fields: Option<&SignedFields<'_>>,
    issues: &mut Vec<AuditIssue>,
) {
    check_versioned_signatures(
        repo,
        event,
        required_signatures,
        required_roles,
        required_role_mins,
        require_principals,
        fields,
        4,
        issues,
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn check_v5_signatures(
    repo: &crate::repo::Repo,
    event: &Event,
    required_signatures: usize,
    required_roles: &[String],
    required_role_mins: &BTreeMap<String, usize>,
    require_principals: bool,
    fields: Option<&SignedFields<'_>>,
    issues: &mut Vec<AuditIssue>,
) {
    check_versioned_signatures(
        repo,
        event,
        required_signatures,
        required_roles,
        required_role_mins,
        require_principals,
        fields,
        5,
        issues,
    );
}

#[allow(clippy::too_many_arguments)]
fn check_versioned_signatures(
    repo: &crate::repo::Repo,
    event: &Event,
    required_signatures: usize,
    required_roles: &[String],
    required_role_mins: &BTreeMap<String, usize>,
    require_principals: bool,
    fields: Option<&SignedFields<'_>>,
    version: u8,
    issues: &mut Vec<AuditIssue>,
) {
    let Some(fields) = fields else {
        return;
    };
    let entries = match event.payload.get("signatures") {
        None => {
            if required_signatures > 0 {
                issues.push(AuditIssue::new(
                    "policy_unsigned",
                    format!(
                        "第 {} 条 policy 事件在 require_signed_policy 下没有签名",
                        event.seq
                    ),
                ));
            }
            return;
        }
        Some(Value::Array(entries)) if entries.is_empty() => {
            if required_signatures > 0 {
                issues.push(AuditIssue::new(
                    "policy_unsigned",
                    format!(
                        "第 {} 条 policy 事件在 require_signed_policy 下没有签名",
                        event.seq
                    ),
                ));
            }
            return;
        }
        Some(Value::Array(entries)) => entries,
        Some(_) => {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!("第 {} 条 policy 事件的 signatures 不是数组", event.seq),
            ));
            return;
        }
    };
    if event.payload.get("action").and_then(Value::as_str) != Some("set") {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条签名 policy 事件的 action 不是 set", event.seq),
        ));
    }
    if event.payload.get("algorithm").and_then(Value::as_str) != Some("ed25519") {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条签名 policy 事件的 algorithm 不是 ed25519",
                event.seq
            ),
        ));
        return;
    }
    if !fields.previous_present {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条签名 policy 事件缺 previous_policy_hash", event.seq),
        ));
    }

    let policy = Policy {
        require_witness: fields.witness,
        require_intent: fields.intent,
        require_signed_claims: fields.signed_claims,
        require_signed_witness: fields.signed_witness,
        require_signed_policy: fields.signed_policy,
        policy_threshold: fields.policy_threshold,
        policy_roles: fields.policy_roles.clone(),
        policy_role_thresholds: fields.policy_role_thresholds.clone(),
        policy_principal_quorum: fields.policy_principal_quorum,
    };
    let mut seen = HashSet::new();
    let mut valid = 0usize;
    let mut covered = HashSet::new();
    let mut role_counts: HashMap<String, usize> = HashMap::new();
    let mut principal_roles: HashMap<String, String> = HashMap::new();
    for entry in entries {
        let Some(value) = entry.as_object() else {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!("第 {} 条 policy 事件的签名项不是对象", event.seq),
            ));
            continue;
        };
        let key_id = value
            .get("key_id")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let signature = value
            .get("signature")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let Some(signed_at_ms) = value.get("signed_at_ms").and_then(Value::as_u64) else {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!("第 {} 条 policy 事件的签名项缺 signed_at_ms", event.seq),
            ));
            continue;
        };
        if key_id.is_empty() || signature.is_empty() {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!("第 {} 条 policy 事件的签名项缺 key_id/signature", event.seq),
            ));
            continue;
        }
        if !seen.insert(key_id.to_string()) {
            issues.push(AuditIssue::new(
                "policy_signature_duplicate",
                format!("第 {} 条 policy 事件重复使用签名 key {key_id}", event.seq),
            ));
            continue;
        }
        let statement = match version {
            5 => policy_statement_v5_bytes(
                fields.session,
                &policy,
                fields.previous_text,
                fields.policy_hash_text,
                signed_at_ms,
                key_id,
            ),
            4 => policy_statement_v4_bytes(
                fields.session,
                &policy,
                fields.previous_text,
                fields.policy_hash_text,
                signed_at_ms,
                key_id,
            ),
            3 => policy_statement_v3_bytes(
                fields.session,
                &policy,
                fields.previous_text,
                fields.policy_hash_text,
                signed_at_ms,
                key_id,
            ),
            _ => policy_statement_v2_bytes(
                fields.session,
                &policy,
                fields.previous_text,
                fields.policy_hash_text,
                signed_at_ms,
                key_id,
            ),
        };
        let statement = match statement {
            Ok(bytes) => bytes,
            Err(err) => {
                issues.push(AuditIssue::new(
                    "policy_bad",
                    format!("第 {} 条签名 policy 的载荷编码失败：{err}", event.seq),
                ));
                continue;
            }
        };
        if let Some((role, principal)) = verify_one_signer(
            repo,
            event,
            key_id,
            signature,
            signed_at_ms,
            required_roles,
            &statement,
            issues,
        ) {
            valid += 1;
            if let Some(existing_role) = principal_roles.get(&principal)
                && existing_role != &role
            {
                issues.push(AuditIssue::new(
                    "policy_role_principal",
                    format!(
                        "第 {} 条 policy 事件由同一主体 {principal} 同时覆盖 {existing_role} 与 {role}",
                        event.seq
                    ),
                ));
                continue;
            }
            principal_roles.insert(principal, role.clone());
            *role_counts.entry(role.clone()).or_default() += 1;
            covered.insert(role);
        }
    }
    if valid < required_signatures {
        issues.push(AuditIssue::new(
            "policy_signature_insufficient",
            format!(
                "第 {} 条 policy 事件有 {valid} 个有效签名，要求 {required_signatures} 个",
                event.seq
            ),
        ));
    }
    if require_principals && principal_roles.len() < required_signatures {
        issues.push(AuditIssue::new(
            "policy_principal_insufficient",
            format!(
                "第 {} 条 policy 事件只覆盖 {} 个不同主体，要求 {required_signatures} 个",
                event.seq,
                principal_roles.len()
            ),
        ));
    }
    push_missing_roles(event, required_roles, &covered, issues);
    for (role, minimum) in required_role_mins {
        let count = role_counts.get(role).copied().unwrap_or(0);
        if count < *minimum {
            issues.push(AuditIssue::new(
                "policy_role_threshold_insufficient",
                format!(
                    "第 {} 条 policy 事件在角色 {role} 上只有 {count} 个有效签名，要求至少 {minimum} 个",
                    event.seq
                ),
            ));
        }
    }
}

pub(super) fn push_missing_roles(
    event: &Event,
    required_roles: &[String],
    covered: &HashSet<String>,
    issues: &mut Vec<AuditIssue>,
) {
    for role in required_roles {
        if !covered.contains(role) {
            issues.push(AuditIssue::new(
                "policy_role_missing",
                format!(
                    "第 {} 条 policy 事件缺少 {} 角色的有效签名",
                    event.seq, role
                ),
            ));
        }
    }
}
