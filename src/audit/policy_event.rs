//! `policy` 事件的语义检查：策略变更不能只写文件，必须能说明谁改了什么。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::hash::Hash;
use crate::journal::Event;
use crate::keys::public_key_id;
use crate::policy::{POLICY_SCHEMA, Policy, policy_statement_bytes};
use crate::repo::Repo;
use crate::signing;

pub(super) fn require_signed_witness(event: &Event) -> bool {
    let versioned = event.payload.get("schema").and_then(Value::as_str) == Some(POLICY_SCHEMA);
    match event.payload.get("require_signed_witness") {
        Some(Value::Bool(value)) => *value,
        None => versioned,
        Some(_) => true,
    }
}

#[derive(Default)]
pub(super) struct PolicyReplay {
    require_signature: bool,
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
        check_policy(
            repo,
            event,
            self.require_signature || next_require,
            self.last_hash,
            issues,
            warnings,
        );
        self.require_signature = next_require;
        if let Some(hash) = parse_hash(event.payload.get("policy_hash")) {
            self.last_hash = Some(hash);
        }
    }
}

pub(super) fn check_policy(
    repo: &Repo,
    event: &Event,
    require_signature: bool,
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
    let versioned = event.payload.get("schema").and_then(Value::as_str) == Some(POLICY_SCHEMA);
    if let Some(schema) = event.payload.get("schema")
        && schema.as_str() != Some(POLICY_SCHEMA)
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
    if signed_policy.is_none() && event.payload.get("require_signed_policy").is_some() {
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
        check_signed_policy(
            repo,
            event,
            require_signature,
            session.unwrap_or_default(),
            witness,
            intent,
            signed_claims,
            signed_witness,
            signed_policy,
            previous_present,
            previous_text,
            policy_hash_text,
            policy_hash.is_some(),
            issues,
        );
    } else if require_signature {
        issues.push(AuditIssue::new(
            "policy_unsigned",
            format!(
                "第 {} 条 policy 事件在 require_signed_policy 下没有签名",
                event.seq
            ),
        ));
    }

    if parse_hash(event.payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "policy_no_state",
            format!("第 {} 条 policy 事件没有可解析的 state_after", event.seq),
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn check_signed_policy(
    repo: &Repo,
    event: &Event,
    require_signature: bool,
    session: &str,
    witness: Option<bool>,
    intent: Option<bool>,
    signed_claims: Option<bool>,
    signed_witness: Option<bool>,
    signed_policy: Option<bool>,
    previous_present: bool,
    previous_text: Option<&str>,
    policy_hash_text: &str,
    policy_hash_valid: bool,
    issues: &mut Vec<AuditIssue>,
) {
    if event.payload.get("action").and_then(Value::as_str) != Some("set") {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条签名 policy 事件的 action 不是 set", event.seq),
        ));
    }
    if !previous_present {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!("第 {} 条签名 policy 事件缺 previous_policy_hash", event.seq),
        ));
    }
    if signed_policy.is_none() {
        issues.push(AuditIssue::new(
            "policy_bad",
            format!(
                "第 {} 条签名 policy 事件缺 require_signed_policy 布尔值",
                event.seq
            ),
        ));
    }
    let (
        Some(witness),
        Some(intent),
        Some(signed_claims),
        Some(signed_witness),
        Some(signed_policy),
    ) = (
        witness,
        intent,
        signed_claims,
        signed_witness,
        signed_policy,
    )
    else {
        return;
    };
    if !policy_hash_valid {
        return;
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

    let keys = match repo.keys() {
        Ok(keys) => keys,
        Err(err) => {
            issues.push(AuditIssue::new(
                "policy_signer_untrusted",
                format!("第 {} 条签名 policy 读不到信任表：{err}", event.seq),
            ));
            return;
        }
    };
    let Some(entry) = keys.keys.get(key_id) else {
        issues.push(AuditIssue::new(
            "policy_signer_untrusted",
            format!("第 {} 条签名 policy 的 key {key_id} 不在信任表", event.seq),
        ));
        return;
    };
    if require_signature && entry.role != "auditor" {
        issues.push(AuditIssue::new(
            "policy_signer_role",
            format!(
                "第 {} 条签名 policy 的 key {key_id} 角色是 {}，require_signed_policy 要求 auditor",
                event.seq, entry.role
            ),
        ));
        return;
    }
    let Some(public) = entry.public_key.as_deref() else {
        issues.push(AuditIssue::new(
            "policy_signer_untrusted",
            format!("第 {} 条签名 policy 的 key {key_id} 没有公钥", event.seq),
        ));
        return;
    };
    let public_bytes = match signing::public_key_bytes(public) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(AuditIssue::new(
                "policy_signer_untrusted",
                format!("第 {} 条签名 policy 的公钥不合法：{err}", event.seq),
            ));
            return;
        }
    };
    if public_key_id(&public_bytes) != key_id {
        issues.push(AuditIssue::new(
            "policy_signer_untrusted",
            format!("第 {} 条签名 policy 的 key_id 与公钥指纹不一致", event.seq),
        ));
        return;
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
        return;
    }

    let policy = Policy {
        require_witness: witness,
        require_intent: intent,
        require_signed_claims: signed_claims,
        require_signed_witness: signed_witness,
        require_signed_policy: signed_policy,
    };
    let statement = match policy_statement_bytes(
        session,
        &policy,
        previous_text,
        policy_hash_text,
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
    if let Err(err) = signing::verify_signature(public, signature, &statement) {
        issues.push(AuditIssue::new(
            "policy_signature_invalid",
            format!("第 {} 条签名 policy 验签失败：{err}", event.seq),
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::TrustEntry;
    use crate::signing::KeyFile;
    use serde_json::json;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trit-vcs-policy-audit-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn signed_event(name: &str) -> (std::path::PathBuf, Repo, Event) {
        signed_event_with(name, "auditor", true)
    }

    fn signed_event_with(
        name: &str,
        role: &str,
        require_signed_policy: bool,
    ) -> (std::path::PathBuf, Repo, Event) {
        let root = temp(name);
        let mut repo = Repo::init(&root).unwrap();
        let key = KeyFile::generate().unwrap();
        let key_path = root.join("policy.key");
        key.save_new(&key_path).unwrap();
        repo.add_key(
            TrustEntry {
                key_id: key.key_id.clone(),
                principal: "qoder:policy".to_string(),
                role: role.to_string(),
                added_at_ms: 1_000,
                public_key: Some(key.public.clone()),
                rotated_from: None,
                revoked_at_ms: None,
                revoke_reason: None,
            },
            "qoder:admin",
            1_000,
        )
        .unwrap();
        repo.set_policy_with_signer(
            &Policy {
                require_signed_policy,
                ..Default::default()
            },
            "qoder:policy",
            2_000,
            Some(&key_path),
        )
        .unwrap();
        let event = repo
            .journal()
            .events()
            .iter()
            .rev()
            .find(|event| event.kind == "policy")
            .unwrap()
            .clone();
        (root, repo, event)
    }

    fn issues(repo: &Repo, event: &Event, require_signature: bool) -> Vec<AuditIssue> {
        let mut issues = Vec::new();
        let mut warnings = Vec::new();
        check_policy(
            repo,
            event,
            require_signature,
            None,
            &mut issues,
            &mut warnings,
        );
        issues
    }

    #[test]
    fn signed_policy_event_rejects_tampered_signature_and_required_flag() {
        let (root, repo, event) = signed_event("tamper");
        assert!(issues(&repo, &event, true).is_empty());

        let mut bad_signature = event.clone();
        bad_signature.payload["signature"] = json!("00".repeat(64));
        assert!(
            issues(&repo, &bad_signature, true)
                .iter()
                .any(|issue| issue.kind == "policy_signature_invalid")
        );

        let mut bad_flag = event.clone();
        bad_flag.payload["require_signed_policy"] = json!(false);
        assert!(
            issues(&repo, &bad_flag, true)
                .iter()
                .any(|issue| issue.kind == "policy_signature_invalid"),
            "require_signed_policy 必须被签名覆盖"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unsigned_policy_event_is_red_once_policy_requires_signature() {
        let (root, repo, event) = signed_event("unsigned");
        let mut unsigned = event;
        unsigned.payload.as_object_mut().unwrap().remove("action");
        unsigned
            .payload
            .as_object_mut()
            .unwrap()
            .remove("algorithm");
        unsigned.payload.as_object_mut().unwrap().remove("key_id");
        unsigned
            .payload
            .as_object_mut()
            .unwrap()
            .remove("signature");
        unsigned
            .payload
            .as_object_mut()
            .unwrap()
            .remove("signed_at_ms");
        assert!(
            issues(&repo, &unsigned, true)
                .iter()
                .any(|issue| issue.kind == "policy_unsigned")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_policy_rejects_non_auditor_signer() {
        let (root, repo, event) = signed_event_with("role", "author", false);
        assert!(
            issues(&repo, &event, false).is_empty(),
            "未开 require_signed_policy 时非 auditor 签名仍可审计"
        );
        assert!(
            issues(&repo, &event, true)
                .iter()
                .any(|issue| issue.kind == "policy_signer_role"),
            "require_signed_policy 生效时必须要求 auditor 角色"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
