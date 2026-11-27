//! `policy` 事件的语义检查：策略变更不能只写文件，必须能说明谁改了什么。
//!
//! v1 保留旧单签形状；v2 增加 `policy_threshold` 与 `signatures[]`，允许多把
//! `auditor` key 共同签名。重放时按“旧阈值与新阈值的较大者”要求本次签名，
//! 所以调低阈值也必须先满足旧阈值。

use std::collections::HashSet;

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::hash::Hash;
use crate::journal::Event;
use crate::keys::public_key_id;
use crate::policy::{
    MAX_POLICY_THRESHOLD, POLICY_SCHEMA, POLICY_SCHEMA_V2, Policy, policy_quorum,
    policy_statement_bytes, policy_statement_v2_bytes,
};
use crate::repo::Repo;
use crate::signing;

pub(super) fn require_signed_witness(event: &Event) -> bool {
    let versioned = matches!(
        event.payload.get("schema").and_then(Value::as_str),
        Some(schema) if schema == POLICY_SCHEMA || schema == POLICY_SCHEMA_V2
    );
    match event.payload.get("require_signed_witness") {
        Some(Value::Bool(value)) => *value,
        None => versioned,
        Some(_) => true,
    }
}

pub(super) fn require_signed_claims(event: &Event) -> bool {
    let versioned = matches!(
        event.payload.get("schema").and_then(Value::as_str),
        Some(schema) if schema == POLICY_SCHEMA || schema == POLICY_SCHEMA_V2
    );
    event
        .payload
        .get("require_signed_claims")
        .and_then(Value::as_bool)
        .unwrap_or(versioned)
}

#[derive(Default)]
pub(super) struct PolicyReplay {
    require_signature: bool,
    threshold: u8,
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
        let required = policy_quorum(
            self.require_signature,
            self.threshold,
            next_require,
            next_threshold,
        );
        check_policy(repo, event, required, self.last_hash, issues, warnings);
        self.require_signature = next_require;
        self.threshold = next_threshold;
        if let Some(hash) = parse_hash(event.payload.get("policy_hash")) {
            self.last_hash = Some(hash);
        }
    }
}

fn event_threshold(event: &Event) -> u8 {
    event
        .payload
        .get("policy_threshold")
        .and_then(Value::as_u64)
        .filter(|value| (1..=u64::from(MAX_POLICY_THRESHOLD)).contains(value))
        .map(|value| value as u8)
        .unwrap_or(1)
}

struct SignedFields<'a> {
    session: &'a str,
    witness: bool,
    intent: bool,
    signed_claims: bool,
    signed_witness: bool,
    signed_policy: bool,
    previous_present: bool,
    previous_text: Option<&'a str>,
    policy_hash_text: &'a str,
    policy_threshold: u8,
}

pub(super) fn check_policy(
    repo: &Repo,
    event: &Event,
    required_signatures: usize,
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
    let versioned = schema == Some(POLICY_SCHEMA) || v2;
    if event.payload.get("schema").is_some()
        && schema.is_none_or(|schema| schema != POLICY_SCHEMA && schema != POLICY_SCHEMA_V2)
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
    if signed_policy.is_none() && (v2 || event.payload.get("require_signed_policy").is_some()) {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条 policy 事件的 require_signed_policy 不是布尔值",
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

    let policy_threshold = if v2 {
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
            previous_present,
            previous_text,
            policy_hash_text,
            policy_threshold,
        }),
        _ => None,
    };

    if v2 {
        check_v2_signatures(repo, event, required_signatures, fields.as_ref(), issues);
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
                check_v1_signature(repo, event, required_signatures, fields, issues);
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
        policy_threshold: 1,
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
    let valid = verify_one_signer(
        repo,
        event,
        key_id,
        signature,
        signed_at_ms,
        required_signatures > 0,
        &statement,
        issues,
    );
    if valid && 1 < required_signatures {
        issues.push(AuditIssue::new(
            "policy_signature_insufficient",
            format!(
                "第 {} 条 policy 事件只有 1 个有效签名，要求 {required_signatures} 个",
                event.seq
            ),
        ));
    }
}

fn check_v2_signatures(
    repo: &Repo,
    event: &Event,
    required_signatures: usize,
    fields: Option<&SignedFields<'_>>,
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
    };
    let mut seen = HashSet::new();
    let mut valid = 0usize;
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
        let statement = match policy_statement_v2_bytes(
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
                continue;
            }
        };
        if verify_one_signer(
            repo,
            event,
            key_id,
            signature,
            signed_at_ms,
            required_signatures > 0,
            &statement,
            issues,
        ) {
            valid += 1;
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
}

#[allow(clippy::too_many_arguments)]
fn verify_one_signer(
    repo: &Repo,
    event: &Event,
    key_id: &str,
    signature: &str,
    signed_at_ms: u64,
    require_auditor: bool,
    statement: &[u8],
    issues: &mut Vec<AuditIssue>,
) -> bool {
    let keys = match repo.keys() {
        Ok(keys) => keys,
        Err(err) => {
            issues.push(AuditIssue::new(
                "policy_signer_untrusted",
                format!("第 {} 条签名 policy 读不到信任表：{err}", event.seq),
            ));
            return false;
        }
    };
    let Some(entry) = keys.keys.get(key_id) else {
        issues.push(AuditIssue::new(
            "policy_signer_untrusted",
            format!("第 {} 条签名 policy 的 key {key_id} 不在信任表", event.seq),
        ));
        return false;
    };
    if require_auditor && entry.role != "auditor" {
        issues.push(AuditIssue::new(
            "policy_signer_role",
            format!(
                "第 {} 条签名 policy 的 key {key_id} 角色是 {}，require_signed_policy 要求 auditor",
                event.seq, entry.role
            ),
        ));
        return false;
    }
    let Some(public) = entry.public_key.as_deref() else {
        issues.push(AuditIssue::new(
            "policy_signer_untrusted",
            format!("第 {} 条签名 policy 的 key {key_id} 没有公钥", event.seq),
        ));
        return false;
    };
    let public_bytes = match signing::public_key_bytes(public) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(AuditIssue::new(
                "policy_signer_untrusted",
                format!("第 {} 条签名 policy 的公钥不合法：{err}", event.seq),
            ));
            return false;
        }
    };
    if public_key_id(&public_bytes) != key_id {
        issues.push(AuditIssue::new(
            "policy_signer_untrusted",
            format!("第 {} 条签名 policy 的 key_id 与公钥指纹不一致", event.seq),
        ));
        return false;
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
        return false;
    }
    if let Err(err) = signing::verify_signature(public, signature, statement) {
        issues.push(AuditIssue::new(
            "policy_signature_invalid",
            format!("第 {} 条签名 policy 验签失败：{err}", event.seq),
        ));
        return false;
    }
    true
}

#[cfg(test)]
mod tests;
