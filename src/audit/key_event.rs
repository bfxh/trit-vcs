//! `key` 事件的语义检查：信任表变更必须写清 action、key_id、principal 和状态。
//!
//! `add`/`revoke` 检查形状；`rotate` 还要求旧钥和新钥共同签同一份轮换声明，
//! 并把信任表里的新旧记录对回来。这样手改一条 rotate 事件不能只改字段了事。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::journal::Event;
use crate::keys::{public_key_id, rotation_statement};
use crate::repo::Repo;
use crate::signing::{public_key_bytes, verify_signature};

pub(super) fn check_key(
    repo: &Repo,
    event: &Event,
    issues: &mut Vec<AuditIssue>,
    warnings: &mut Vec<AuditIssue>,
) {
    let payload = &event.payload;
    let action = payload.get("action").and_then(Value::as_str);
    if !matches!(action, Some("add" | "revoke" | "rotate")) {
        issues.push(AuditIssue::new(
            "key_bad",
            format!(
                "第 {} 条 key 事件的 action 不是 add/revoke/rotate",
                event.seq
            ),
        ));
    }
    for field in ["key_id", "principal", "role", "session"] {
        if payload
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
        {
            issues.push(AuditIssue::new(
                "key_bad",
                format!("第 {} 条 key 事件缺 {field}", event.seq),
            ));
        }
    }
    if action == Some("revoke") && text(payload, "reason").is_none() {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key revoke 事件缺 reason", event.seq),
        ));
    }
    if action == Some("rotate") {
        check_rotation(repo, event, issues);
    }
    if parse_hash(payload.get("keystore_hash")).is_none() {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key 事件缺可解析的 keystore_hash", event.seq),
        ));
    }
    if parse_hash(payload.get("state_after")).is_none() {
        warnings.push(AuditIssue::new(
            "key_no_state",
            format!("第 {} 条 key 事件没有可解析的 state_after", event.seq),
        ));
    }
}

fn check_rotation(repo: &Repo, event: &Event, issues: &mut Vec<AuditIssue>) {
    let payload = &event.payload;
    let Some(old_key_id) = text(payload, "old_key_id") else {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key rotate 事件缺 old_key_id", event.seq),
        ));
        return;
    };
    let Some(new_key_id) = text(payload, "key_id") else {
        return;
    };
    let Some(principal) = text(payload, "principal") else {
        return;
    };
    let Some(role) = text(payload, "role") else {
        return;
    };
    let Some(rotated_at) = payload.get("rotated_at_ms").and_then(Value::as_u64) else {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key rotate 事件缺 rotated_at_ms", event.seq),
        ));
        return;
    };
    let Some(reason) = text(payload, "reason") else {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key rotate 事件缺 reason", event.seq),
        ));
        return;
    };
    let Some(old_public) = text(payload, "old_public") else {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key rotate 事件缺 old_public", event.seq),
        ));
        return;
    };
    let Some(new_public) = text(payload, "new_public") else {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key rotate 事件缺 new_public", event.seq),
        ));
        return;
    };
    let Some(old_signature) = text(payload, "old_signature") else {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key rotate 事件缺 old_signature", event.seq),
        ));
        return;
    };
    let Some(new_signature) = text(payload, "new_signature") else {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key rotate 事件缺 new_signature", event.seq),
        ));
        return;
    };

    if old_key_id == new_key_id {
        issues.push(AuditIssue::new(
            "key_rotation_mismatch",
            format!("第 {} 条 key rotate 的旧钥和新钥是同一个 id", event.seq),
        ));
    }

    let old_public_bytes = match public_key_bytes(old_public) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(AuditIssue::new(
                "key_rotation_mismatch",
                format!(
                    "第 {} 条 key rotate 的 old_public 不合法：{err}",
                    event.seq
                ),
            ));
            return;
        }
    };
    if public_key_id(&old_public_bytes) != old_key_id {
        issues.push(AuditIssue::new(
            "key_rotation_mismatch",
            format!(
                "第 {} 条 key rotate 的 old_key_id 与 old_public 指纹不一致",
                event.seq
            ),
        ));
    }
    let new_public_bytes = match public_key_bytes(new_public) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(AuditIssue::new(
                "key_rotation_mismatch",
                format!(
                    "第 {} 条 key rotate 的 new_public 不合法：{err}",
                    event.seq
                ),
            ));
            return;
        }
    };
    if public_key_id(&new_public_bytes) != new_key_id {
        issues.push(AuditIssue::new(
            "key_rotation_mismatch",
            format!(
                "第 {} 条 key rotate 的 key_id 与 new_public 指纹不一致",
                event.seq
            ),
        ));
    }

    let statement = rotation_statement(old_key_id, new_key_id, principal, role, rotated_at);
    for (label, public, signature) in [
        ("旧钥", old_public, old_signature),
        ("新钥", new_public, new_signature),
    ] {
        if verify_signature(public, signature, &statement).is_err() {
            issues.push(AuditIssue::new(
                "key_rotation_mismatch",
                format!(
                    "第 {} 条 key rotate 的{label}签名验不过轮换声明",
                    event.seq
                ),
            ));
        }
    }

    let store = match repo.keys() {
        Ok(store) => store,
        Err(err) => {
            issues.push(AuditIssue::new(
                "key_rotation_mismatch",
                format!("第 {} 条 key rotate 读不到信任表：{err}", event.seq),
            ));
            return;
        }
    };
    let Some(old_entry) = store.keys.get(old_key_id) else {
        issues.push(AuditIssue::new(
            "key_rotation_mismatch",
            format!("第 {} 条 key rotate 的旧钥不在信任表", event.seq),
        ));
        return;
    };
    let Some(new_entry) = store.keys.get(new_key_id) else {
        issues.push(AuditIssue::new(
            "key_rotation_mismatch",
            format!("第 {} 条 key rotate 的新钥不在信任表", event.seq),
        ));
        return;
    };
    if old_entry
        .public_key
        .as_deref()
        .is_none_or(|public| !public.eq_ignore_ascii_case(old_public))
    {
        issues.push(AuditIssue::new(
            "key_rotation_mismatch",
            format!("第 {} 条 key rotate 的旧钥公钥与信任表不一致", event.seq),
        ));
    }
    let expected_reason = format!("rotated to {new_key_id}");
    if old_entry.revoked_at_ms != Some(rotated_at)
        || old_entry.revoke_reason.as_deref() != Some(expected_reason.as_str())
    {
        issues.push(AuditIssue::new(
            "key_rotation_mismatch",
            format!(
                "第 {} 条 key rotate 的旧钥吊销时间/原因是 {:?}/{:?}，与事件不一致",
                event.seq, old_entry.revoked_at_ms, old_entry.revoke_reason
            ),
        ));
    }
    if new_entry
        .public_key
        .as_deref()
        .is_none_or(|public| !public.eq_ignore_ascii_case(new_public))
        || new_entry.rotated_from.as_deref() != Some(old_key_id)
        || new_entry.added_at_ms != rotated_at
        || new_entry
            .revoked_at_ms
            .is_some_and(|revoked_at| revoked_at < rotated_at)
        || new_entry.principal != principal
        || new_entry.role != role
    {
        issues.push(AuditIssue::new(
            "key_rotation_mismatch",
            format!("第 {} 条 key rotate 的新钥记录与事件不一致", event.seq),
        ));
    }
    if reason.is_empty() {
        issues.push(AuditIssue::new(
            "key_bad",
            format!("第 {} 条 key rotate 事件缺 reason", event.seq),
        ));
    }
}

fn text<'a>(payload: &'a Value, field: &str) -> Option<&'a str> {
    payload.get(field).and_then(Value::as_str)
}
