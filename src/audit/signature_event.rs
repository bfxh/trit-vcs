//! `signature` 事件：用信任表里的 Ed25519 公钥验提交字节，而不是只信事件自称。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::journal::Event;
use crate::keys::public_key_id;
use crate::repo::Repo;
use crate::signing;

pub(super) fn check_signature(
    repo: &Repo,
    event: &Event,
    issues: &mut Vec<AuditIssue>,
    warnings: &mut Vec<AuditIssue>,
) {
    let payload = &event.payload;
    let Some(commit) = parse_hash(payload.get("commit")) else {
        issues.push(AuditIssue::new(
            "signature_bad",
            format!("第 {} 条 signature 事件缺可解析的 commit", event.seq),
        ));
        return;
    };
    let key_id = payload
        .get("key_id")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let signature = payload
        .get("signature")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let signed_at = payload.get("signed_at_ms").and_then(Value::as_u64);
    if key_id.is_empty() || signature.is_empty() || signed_at.is_none() {
        issues.push(AuditIssue::new(
            "signature_bad",
            format!(
                "第 {} 条 signature 事件缺 key_id/signature/signed_at_ms",
                event.seq
            ),
        ));
        return;
    }
    if payload.get("algorithm").and_then(Value::as_str) != Some("ed25519") {
        issues.push(AuditIssue::new(
            "signature_bad",
            format!(
                "第 {} 条 signature 事件的 algorithm 不是 ed25519",
                event.seq
            ),
        ));
        return;
    }
    let bytes = match repo.store().get_chunk(&commit) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(AuditIssue::new(
                "signature_commit_missing",
                format!(
                    "第 {} 条 signature 指向的提交 {} 读不出来：{err}",
                    event.seq,
                    commit.short()
                ),
            ));
            return;
        }
    };
    let keys = match repo.keys() {
        Ok(keys) => keys,
        Err(err) => {
            issues.push(AuditIssue::new(
                "signer_untrusted",
                format!("第 {} 条 signature 读不到信任表：{err}", event.seq),
            ));
            return;
        }
    };
    let Some(entry) = keys.keys.get(key_id) else {
        issues.push(AuditIssue::new(
            "signer_untrusted",
            format!("第 {} 条 signature 的 key {key_id} 不在信任表", event.seq),
        ));
        return;
    };
    let Some(public) = entry.public_key.as_deref() else {
        issues.push(AuditIssue::new(
            "signer_untrusted",
            format!("第 {} 条 signature 的 key {key_id} 没有公钥", event.seq),
        ));
        return;
    };
    let public_bytes = match signing::public_key_bytes(public) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(AuditIssue::new(
                "signer_untrusted",
                format!("第 {} 条 signature 的公钥不合法：{err}", event.seq),
            ));
            return;
        }
    };
    if public_key_id(&public_bytes) != key_id {
        issues.push(AuditIssue::new(
            "signer_untrusted",
            format!("第 {} 条 signature 的 key_id 与公钥指纹不一致", event.seq),
        ));
        return;
    }
    let signed_at = signed_at.unwrap_or(0);
    if let Some(revoked_at) = entry.revoked_at_ms
        && signed_at > revoked_at
    {
        issues.push(AuditIssue::new(
            "signer_revoked",
            format!(
                "第 {} 条 signature 签名时 key {key_id} 已吊销（{} > {}）",
                event.seq, signed_at, revoked_at
            ),
        ));
        return;
    }
    if let Err(err) = signing::verify_signature(public, signature, &bytes) {
        issues.push(AuditIssue::new(
            "signature_invalid",
            format!("第 {} 条 signature 验签失败：{err}", event.seq),
        ));
    }
    if parse_hash(payload.get("state_before")).is_none()
        || parse_hash(payload.get("state_after")).is_none()
    {
        warnings.push(AuditIssue::new(
            "signature_no_state",
            format!(
                "第 {} 条 signature 事件缺可解析的 state_before/state_after",
                event.seq
            ),
        ));
    }
}
