//! `policy` 事件的语义检查：策略变更不能只写文件，必须能说明谁改了什么。
//!
//! v1 保留旧单签形状；v2 增加 `policy_threshold` 与 `signatures[]`，允许多把
//! `auditor` key 共同签名。v3 增加角色集合，v4 增加主体计票，v5 增加每角色最低签名数。
//! 重放时按“旧阈值与新阈值的较大者”、角色最低数合计与角色覆盖要求本次签名，
//! 所以调低阈值或降低角色最低数也必须先满足旧策略。

use std::collections::{BTreeMap, HashSet};

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::hash::Hash;
use crate::journal::Event;
use crate::keys::public_key_id;
use crate::policy::{
    MAX_POLICY_THRESHOLD, POLICY_SCHEMA, POLICY_SCHEMA_V2, POLICY_SCHEMA_V3, POLICY_SCHEMA_V4,
    POLICY_SCHEMA_V5, POLICY_SCHEMA_V6, Policy, policy_quorum, policy_role_mins_for_change,
    policy_roles_for_change, policy_statement_bytes,
};
use crate::repo::Repo;
use crate::signing;

mod parse;
mod signature;
use parse::{
    check_reason, event_policy_principal_quorum, event_policy_role_thresholds, event_policy_roles,
    event_policy_roles_raw, event_require_policy_reason, event_threshold,
};
pub(super) use parse::{require_signed_claims, require_signed_witness};
use signature::{
    check_v2_signatures, check_v3_signatures, check_v4_signatures, check_v5_signatures,
    check_v6_signatures, push_missing_roles,
};

#[derive(Default)]
pub(super) struct PolicyReplay {
    require_signature: bool,
    require_reason: bool,
    threshold: u8,
    roles: Vec<String>,
    role_thresholds: BTreeMap<String, u8>,
    principal_quorum: bool,
    last_hash: Option<Hash>,
}

impl PolicyReplay {
    pub(super) fn observe(
        &mut self,
        repo: &Repo,
        event: &Event,
        issues: &mut Vec<AuditIssue>,
        warnings: &mut Vec<AuditIssue>,
    ) {
        let next_require = event
            .payload
            .get("require_signed_policy")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let next_threshold = event_threshold(event);
        let next_roles = event_policy_roles(event).unwrap_or_else(|_| vec!["auditor".into()]);
        let next_role_thresholds = event_policy_role_thresholds(event).unwrap_or_default();
        let next_principal_quorum = event_policy_principal_quorum(event);
        let next_require_reason = event_require_policy_reason(event);
        let required_roles = policy_roles_for_change(
            self.require_signature,
            &self.roles,
            next_require,
            &next_roles,
        );
        let required_role_mins = policy_role_mins_for_change(
            self.require_signature,
            &self.role_thresholds,
            next_require,
            &next_role_thresholds,
            &required_roles,
        );
        let required = policy_quorum(
            self.require_signature,
            self.threshold,
            next_require,
            next_threshold,
        )
        .max(required_roles.len())
        .max(required_role_mins.values().sum());
        let require_principals = self.principal_quorum || next_principal_quorum;
        check_policy(
            repo,
            event,
            required,
            &required_roles,
            &required_role_mins,
            require_principals,
            self.require_reason || next_require_reason,
            self.last_hash,
            issues,
            warnings,
        );
        self.require_signature = next_require;
        self.require_reason = next_require_reason;
        self.threshold = next_threshold;
        self.roles = next_roles;
        self.role_thresholds = next_role_thresholds;
        self.principal_quorum = next_principal_quorum;
        if let Some(hash) = parse_hash(event.payload.get("policy_hash")) {
            self.last_hash = Some(hash);
        }
    }
}

struct SignedFields<'a> {
    session: &'a str,
    witness: bool,
    intent: bool,
    signed_claims: bool,
    signed_witness: bool,
    signed_policy: bool,
    require_policy_reason: bool,
    previous_present: bool,
    previous_text: Option<&'a str>,
    policy_hash_text: &'a str,
    policy_threshold: u8,
    policy_roles: Vec<String>,
    policy_role_thresholds: BTreeMap<String, u8>,
    policy_principal_quorum: bool,
    policy_reason: &'a str,
    policy_ticket: Option<&'a str>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn check_policy(
    repo: &Repo,
    event: &Event,
    required_signatures: usize,
    required_roles: &[String],
    required_role_mins: &BTreeMap<String, usize>,
    require_principals: bool,
    require_reason: bool,
    last_policy_hash: Option<Hash>,
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
    let witness = event
        .payload
        .get("require_witness")
        .and_then(Value::as_bool);
    let intent = event.payload.get("require_intent").and_then(Value::as_bool);
    if witness.is_none() || intent.is_none() {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条 policy 事件缺策略布尔值", event.seq),
        ));
    }
    let schema = event.payload.get("schema").and_then(Value::as_str);
    let v2 = schema == Some(POLICY_SCHEMA_V2);
    let v3 = schema == Some(POLICY_SCHEMA_V3);
    let v4 = schema == Some(POLICY_SCHEMA_V4);
    let v5 = schema == Some(POLICY_SCHEMA_V5);
    let v6 = schema == Some(POLICY_SCHEMA_V6);
    let versioned = schema == Some(POLICY_SCHEMA) || v2 || v3 || v4 || v5 || v6;
    if event.payload.get("schema").is_some()
        && schema.is_none_or(|schema| {
            schema != POLICY_SCHEMA
                && schema != POLICY_SCHEMA_V2
                && schema != POLICY_SCHEMA_V3
                && schema != POLICY_SCHEMA_V4
                && schema != POLICY_SCHEMA_V5
                && schema != POLICY_SCHEMA_V6
        })
    {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条 policy 事件的 schema 不受支持", event.seq),
        ));
    }
    let signed_claims = event
        .payload
        .get("require_signed_claims")
        .and_then(Value::as_bool);
    if signed_claims.is_none()
        && (versioned || event.payload.get("require_signed_claims").is_some())
    {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条 policy 事件的 require_signed_claims 不是布尔值",
                event.seq
            ),
        ));
    }
    let signed_witness = event
        .payload
        .get("require_signed_witness")
        .and_then(Value::as_bool);
    if signed_witness.is_none()
        && (versioned || event.payload.get("require_signed_witness").is_some())
    {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条 policy 事件的 require_signed_witness 不是布尔值",
                event.seq
            ),
        ));
    }
    let signed_policy = event
        .payload
        .get("require_signed_policy")
        .and_then(Value::as_bool);
    if signed_policy.is_none()
        && (v2 || v3 || v4 || v5 || v6 || event.payload.get("require_signed_policy").is_some())
    {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条 policy 事件的 require_signed_policy 不是布尔值",
                event.seq
            ),
        ));
    }
    if (v4 || v5 || v6) && event.payload.get("policy_principal_quorum").is_none() {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条 policy 事件缺 policy_principal_quorum", event.seq),
        ));
    }
    if (v4 || v5 || v6)
        && event
            .payload
            .get("policy_principal_quorum")
            .is_some_and(|value| !value.is_boolean())
    {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条 policy 事件的 policy_principal_quorum 不是布尔值",
                event.seq
            ),
        ));
    }

    let policy_hash = parse_hash(event.payload.get("policy_hash"));
    let policy_hash_text = event
        .payload
        .get("policy_hash")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if policy_hash.is_none() {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条 policy 事件缺 policy_hash", event.seq),
        ));
    }

    let previous_present = event.payload.get("previous_policy_hash").is_some();
    let previous_text = match event.payload.get("previous_policy_hash") {
        Some(Value::Null) => None,
        Some(value) => match value.as_str() {
            Some(text) => {
                if parse_hash(Some(value)).is_none() {
                    issues.push(AuditIssue::new(
                        "policy_bad",
                        format!(
                            "第 {} 条 policy 事件的 previous_policy_hash 不是合法摘要",
                            event.seq
                        ),
                    ));
                }
                Some(text)
            }
            None => {
                issues.push(AuditIssue::new(
                    "policy_bad",
                    format!(
                        "第 {} 条 policy 事件的 previous_policy_hash 不是字符串或 null",
                        event.seq
                    ),
                ));
                None
            }
        },
        None => None,
    };
    if let Some(last) = last_policy_hash
        && previous_present
        && previous_text.and_then(Hash::from_hex) != Some(last)
    {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条 policy 事件的 previous_policy_hash 没有接上前一条 policy",
                event.seq
            ),
        ));
    }

    let policy_threshold = if v2 || v3 || v4 || v5 || v6 {
        match event
            .payload
            .get("policy_threshold")
            .and_then(Value::as_u64)
        {
            Some(value) if (1..=u64::from(MAX_POLICY_THRESHOLD)).contains(&value) => value as u8,
            Some(value) => {
                issues.push(AuditIssue::new(
                    "policy_bad",
                    format!(
                        "第 {} 条 policy 事件的 policy_threshold 超出 1..={MAX_POLICY_THRESHOLD}：{value}",
                        event.seq
                    ),
                ));
                1
            }
            None => {
                issues.push(AuditIssue::new(
                    "policy_bad",
                    format!(
                        "第 {} 条 policy 事件的 policy_threshold 不是合法整数",
                        event.seq
                    ),
                ));
                1
            }
        }
    } else {
        1
    };
    let raw_policy_roles = if v3 || v4 || v5 || v6 {
        event_policy_roles_raw(event).ok()
    } else {
        None
    };
    let policy_roles = if v3 || v4 || v5 || v6 {
        match event_policy_roles(event) {
            Ok(roles) => roles,
            Err(err) => {
                issues.push(AuditIssue::new(
                    "policy_bad",
                    format!("第 {} 条 policy 事件的 policy_roles 非法：{err}", event.seq),
                ));
                vec!["auditor".into()]
            }
        }
    } else {
        vec!["auditor".into()]
    };
    if v3 || v4 || v5 || v6 {
        if raw_policy_roles
            .as_ref()
            .is_some_and(|raw| raw != &policy_roles)
        {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!(
                    "第 {} 条 policy 事件的 policy_roles 不是规范顺序",
                    event.seq
                ),
            ));
        }
        if policy_threshold < policy_roles.len() as u8 {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!(
                    "第 {} 条 policy 事件的 policy_threshold {} 小于角色数 {}",
                    event.seq,
                    policy_threshold,
                    policy_roles.len()
                ),
            ));
        }
    }

    let policy_principal_quorum = if v4 || v5 || v6 {
        event_policy_principal_quorum(event)
    } else {
        false
    };

    let policy_role_thresholds = if v5 || v6 {
        match event_policy_role_thresholds(event) {
            Ok(thresholds) => thresholds,
            Err(err) => {
                issues.push(AuditIssue::new(
                    "policy_bad",
                    format!(
                        "第 {} 条 policy 事件的 policy_role_thresholds 非法：{err}",
                        event.seq
                    ),
                ));
                BTreeMap::new()
            }
        }
    } else {
        BTreeMap::new()
    };
    if v5 || v6 {
        if policy_role_thresholds
            .values()
            .any(|threshold| *threshold == 1)
        {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!(
                    "第 {} 条 policy 事件的 policy_role_thresholds 不应记录值为 1 的角色",
                    event.seq
                ),
            ));
        }
        if let Some(role) = policy_role_thresholds
            .keys()
            .find(|role| !policy_roles.contains(role))
        {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!(
                    "第 {} 条 policy 事件的 policy_role_thresholds 含未知角色 {role}",
                    event.seq
                ),
            ));
        }
        let role_min_sum = policy_roles
            .iter()
            .map(|role| u16::from(policy_role_thresholds.get(role).copied().unwrap_or(1)))
            .sum::<u16>();
        if role_min_sum > u16::from(MAX_POLICY_THRESHOLD) {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!(
                    "第 {} 条 policy 事件的每角色最低签名合计 {role_min_sum} 超过 {}",
                    event.seq, MAX_POLICY_THRESHOLD
                ),
            ));
        } else if policy_threshold < role_min_sum as u8 {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!(
                    "第 {} 条 policy 事件的 policy_threshold {} 小于每角色最低签名合计 {role_min_sum}",
                    event.seq, policy_threshold
                ),
            ));
        }
    }

    let reason = check_reason(event, require_reason, issues);

    let fields = match (
        session,
        witness,
        intent,
        signed_claims,
        signed_witness,
        signed_policy,
        policy_hash,
    ) {
        (
            Some(session),
            Some(witness),
            Some(intent),
            Some(signed_claims),
            Some(signed_witness),
            Some(signed_policy),
            Some(_),
        ) => Some(SignedFields {
            session,
            witness,
            intent,
            signed_claims,
            signed_witness,
            signed_policy,
            require_policy_reason: reason.require,
            previous_present,
            previous_text,
            policy_hash_text,
            policy_threshold,
            policy_roles: policy_roles.clone(),
            policy_role_thresholds: policy_role_thresholds.clone(),
            policy_principal_quorum,
            policy_reason: reason.reason,
            policy_ticket: reason.ticket,
        }),
        _ => None,
    };

    if v2 {
        check_v2_signatures(
            repo,
            event,
            required_signatures,
            required_roles,
            required_role_mins,
            require_principals,
            fields.as_ref(),
            issues,
        );
    } else if v3 {
        check_v3_signatures(
            repo,
            event,
            required_signatures,
            required_roles,
            required_role_mins,
            require_principals,
            fields.as_ref(),
            issues,
        );
    } else if v4 {
        check_v4_signatures(
            repo,
            event,
            required_signatures,
            required_roles,
            required_role_mins,
            require_principals,
            fields.as_ref(),
            issues,
        );
    } else if v5 {
        check_v5_signatures(
            repo,
            event,
            required_signatures,
            required_roles,
            required_role_mins,
            require_principals,
            fields.as_ref(),
            issues,
        );
    } else if v6 {
        check_v6_signatures(
            repo,
            event,
            required_signatures,
            required_roles,
            required_role_mins,
            require_principals,
            fields.as_ref(),
            issues,
        );
    } else {
        let signature_fields = ["algorithm", "key_id", "signature", "signed_at_ms"];
        let any_signature_field = signature_fields
            .iter()
            .any(|field| event.payload.get(*field).is_some());
        let signed = signature_fields
            .iter()
            .all(|field| event.payload.get(*field).is_some());
        if any_signature_field && !signed {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!("第 {} 条 policy 事件的签名字段不完整", event.seq),
            ));
        }
        if signed {
            if let Some(fields) = fields.as_ref() {
                check_v1_signature(
                    repo,
                    event,
                    required_signatures,
                    required_roles,
                    required_role_mins,
                    fields,
                    issues,
                );
            }
        } else if required_signatures > 0 {
            issues.push(AuditIssue::new(
                "policy_unsigned",
                format!(
                    "第 {} 条 policy 事件在 require_signed_policy 下没有签名",
                    event.seq
                ),
            ));
        }
    }

    if parse_hash(event.payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "policy_no_state",
            format!("第 {} 条 policy 事件没有可解析的 state_after", event.seq),
        ));
    }
}

fn check_v1_signature(
    repo: &Repo,
    event: &Event,
    required_signatures: usize,
    required_roles: &[String],
    _required_role_mins: &BTreeMap<String, usize>,
    fields: &SignedFields<'_>,
    issues: &mut Vec<AuditIssue>,
) {
    if event.payload.get("action").and_then(Value::as_str) != Some("set") {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条签名 policy 事件的 action 不是 set", event.seq),
        ));
    }
    if !fields.previous_present {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条签名 policy 事件缺 previous_policy_hash", event.seq),
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
    let key_id = event
        .payload
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let signature = event
        .payload
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(signed_at_ms) = event.payload.get("signed_at_ms").and_then(Value::as_u64) else {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条签名 policy 事件缺 signed_at_ms", event.seq),
        ));
        return;
    };
    if key_id.is_empty() || signature.is_empty() {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条签名 policy 事件缺 key_id/signature", event.seq),
        ));
        return;
    }
    let policy = Policy {
        require_witness: fields.witness,
        require_intent: fields.intent,
        require_signed_claims: fields.signed_claims,
        require_signed_witness: fields.signed_witness,
        require_signed_policy: fields.signed_policy,
        require_policy_reason: false,
        policy_threshold: 1,
        policy_roles: vec!["auditor".into()],
        policy_principal_quorum: false,
        policy_role_thresholds: BTreeMap::new(),
    };
    let statement = match policy_statement_bytes(
        fields.session,
        &policy,
        fields.previous_text,
        fields.policy_hash_text,
        signed_at_ms,
        key_id,
    ) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(AuditIssue::new(
                "policy_bad",
                format!("第 {} 条签名 policy 的载荷编码失败：{err}", event.seq),
            ));
            return;
        }
    };
    let valid_role = verify_one_signer(
        repo,
        event,
        key_id,
        signature,
        signed_at_ms,
        required_roles,
        &statement,
        issues,
    );
    let mut covered = HashSet::new();
    if let Some((role, _)) = valid_role {
        covered.insert(role);
    }
    if !covered.is_empty() && (1 < required_signatures || required_roles.len() > 1) {
        issues.push(AuditIssue::new(
            "policy_signature_insufficient",
            format!(
                "第 {} 条 policy 事件只有 1 个有效签名，要求 {required_signatures} 个并覆盖角色 {}",
                event.seq,
                required_roles.join("/")
            ),
        ));
    }
    push_missing_roles(event, required_roles, &covered, issues);
}

#[allow(clippy::too_many_arguments)]
fn verify_one_signer(
    repo: &Repo,
    event: &Event,
    key_id: &str,
    signature: &str,
    signed_at_ms: u64,
    required_roles: &[String],
    statement: &[u8],
    issues: &mut Vec<AuditIssue>,
) -> Option<(String, String)> {
    let keys = match repo.keys() {
        Ok(keys) => keys,
        Err(err) => {
            issues.push(AuditIssue::new(
                "policy_signer_untrusted",
                format!("第 {} 条签名 policy 读不到信任表：{err}", event.seq),
            ));
            return None;
        }
    };
    let Some(entry) = keys.keys.get(key_id) else {
        issues.push(AuditIssue::new(
            "policy_signer_untrusted",
            format!("第 {} 条签名 policy 的 key {key_id} 不在信任表", event.seq),
        ));
        return None;
    };
    if !required_roles.is_empty() && !required_roles.iter().any(|role| role == &entry.role) {
        issues.push(AuditIssue::new(
            "policy_signer_role",
            format!(
                "第 {} 条签名 policy 的 key {key_id} 角色是 {}，要求角色 {}",
                event.seq,
                entry.role,
                required_roles.join("/")
            ),
        ));
        return None;
    }
    let Some(public) = entry.public_key.as_deref() else {
        issues.push(AuditIssue::new(
            "policy_signer_untrusted",
            format!("第 {} 条签名 policy 的 key {key_id} 没有公钥", event.seq),
        ));
        return None;
    };
    let public_bytes = match signing::public_key_bytes(public) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(AuditIssue::new(
                "policy_signer_untrusted",
                format!("第 {} 条签名 policy 的公钥不合法：{err}", event.seq),
            ));
            return None;
        }
    };
    if public_key_id(&public_bytes) != key_id {
        issues.push(AuditIssue::new(
            "policy_signer_untrusted",
            format!("第 {} 条签名 policy 的 key_id 与公钥指纹不一致", event.seq),
        ));
        return None;
    }
    if let Some(revoked_at) = entry.revoked_at_ms
        && signed_at_ms > revoked_at
    {
        issues.push(AuditIssue::new(
            "policy_signer_revoked",
            format!(
                "第 {} 条签名 policy 签名时 key {key_id} 已吊销（{} > {}）",
                event.seq, signed_at_ms, revoked_at
            ),
        ));
        return None;
    }
    if let Err(err) = signing::verify_signature(public, signature, statement) {
        issues.push(AuditIssue::new(
            "policy_signature_invalid",
            format!("第 {} 条签名 policy 验签失败：{err}", event.seq),
        ));
        return None;
    }
    Some((entry.role.clone(), entry.principal.clone()))
}

#[cfg(test)]
mod tests;
