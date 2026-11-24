//! `attestation` 事件：复核 sidecar 的提交绑定、操作、信任、吊销与 Ed25519 签名。

use std::collections::BTreeMap;

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::attestation::{ALGORITHM, Attestation, EVENT_KIND, SCHEMA};
use crate::hash::Hash;
use crate::journal::Event;
use crate::keys::public_key_id;
use crate::model::Commit;
use crate::repo::Repo;
use crate::signing;

pub(crate) fn track_commit(
    id: Hash,
    index: usize,
    commit: &Commit,
    required: bool,
    commits: &mut BTreeMap<Hash, usize>,
    issues: &mut Vec<AuditIssue>,
) {
    if !required {
        return;
    }
    if commit.witness.is_some() {
        commits.insert(id, index);
    } else {
        issues.push(AuditIssue::new(
            "attestation_missing",
            format!("提交 {} 在严格见证策略生效后缺 witness", id.short()),
        ));
    }
}

pub(crate) fn operation_states_match(
    event: &Event,
    begin: &Event,
    result: &Event,
) -> Result<(), String> {
    let before = parse_hash(event.payload.get("state_before"))
        .ok_or_else(|| "attestation 缺合法 state_before".to_string())?;
    let after = parse_hash(event.payload.get("state_after"))
        .ok_or_else(|| "attestation 缺合法 state_after".to_string())?;
    if parse_hash(begin.payload.get("state_before")) != Some(before) {
        return Err("attestation state_before 与 op_begin 不一致".to_string());
    }
    if parse_hash(result.payload.get("state_after")) != Some(after) {
        return Err("attestation state_after 与 op_result 不一致".to_string());
    }
    Ok(())
}

pub(super) fn check_required(
    events: &[Event],
    required: &std::collections::BTreeMap<Hash, usize>,
    issues: &mut Vec<AuditIssue>,
) {
    for (id, commit_index) in required {
        if !events.iter().enumerate().any(|(index, candidate)| {
            index > *commit_index
                && candidate.kind == EVENT_KIND
                && candidate.payload.get("commit").and_then(Value::as_str)
                    == Some(id.to_hex().as_str())
        }) {
            issues.push(AuditIssue::new(
                "attestation_missing",
                format!(
                    "提交 {} 在严格见证策略生效后有 witness 但无 attestation",
                    id.short()
                ),
            ));
        }
    }
}

pub(super) fn check_attestation(
    repo: &Repo,
    events: &[Event],
    index: usize,
    event: &Event,
    issues: &mut Vec<AuditIssue>,
) {
    let payload = &event.payload;
    let Some(id) = parse_hash(payload.get("commit")) else {
        bad(issues, event, "缺合法 commit");
        return;
    };
    if events.iter().take(index).any(|prior| {
        prior.kind == EVENT_KIND
            && prior.payload.get("commit").and_then(Value::as_str) == Some(id.to_hex().as_str())
    }) {
        issues.push(AuditIssue::new(
            "attestation_duplicate",
            format!("第 {} 条 attestation 重复签署同一提交", event.seq),
        ));
    }
    let Some(operation) = parse_hash(payload.get("operation")) else {
        bad(issues, event, "缺合法 operation");
        return;
    };
    let Some(digest) = parse_hash(payload.get("attestation")) else {
        bad(issues, event, "缺合法 attestation 对象摘要");
        return;
    };
    if payload.get("schema").and_then(Value::as_str) != Some(SCHEMA)
        || payload.get("algorithm").and_then(Value::as_str) != Some(ALGORITHM)
    {
        bad(issues, event, "schema 或 algorithm 不受支持");
        return;
    }
    let Some(begin) = events.iter().find(|candidate| candidate.hash == operation) else {
        bad(issues, event, "operation 不存在");
        return;
    };
    if begin.kind != "op_begin"
        || begin.payload.get("op").and_then(Value::as_str) != Some("attest")
        || begin.seq >= event.seq
    {
        bad(
            issues,
            event,
            "operation 不是先于 sidecar 的 attest op_begin",
        );
        return;
    }
    if begin
        .payload
        .get("args")
        .and_then(|args| args.get("commit"))
        .and_then(Value::as_str)
        != Some(id.to_hex().as_str())
        || begin
            .payload
            .get("args")
            .and_then(|args| args.get("witness"))
            .and_then(Value::as_str)
            != payload.get("witness").and_then(Value::as_str)
        || begin
            .payload
            .get("args")
            .and_then(|args| args.get("key_id"))
            .and_then(Value::as_str)
            != payload.get("key_id").and_then(Value::as_str)
        || begin
            .payload
            .get("args")
            .and_then(|args| args.get("session"))
            .and_then(Value::as_str)
            != payload.get("session").and_then(Value::as_str)
    {
        bad(issues, event, "op_begin 参数与 sidecar 不一致");
        return;
    }
    let Some(result) = events.iter().skip(index + 1).find(|candidate| {
        candidate.kind == "op_result"
            && candidate.payload.get("begin_hash").and_then(Value::as_str)
                == Some(operation.to_hex().as_str())
    }) else {
        bad(issues, event, "attestation 操作没有收口");
        return;
    };
    if result.payload.get("op").and_then(Value::as_str) != Some("attest")
        || result.payload.get("status").and_then(Value::as_str) != Some("ok")
    {
        bad(issues, event, "attestation 操作未成功收口");
        return;
    }
    let bytes = match repo.store().get_chunk(&digest) {
        Ok(bytes) => bytes,
        Err(err) => {
            bad(issues, event, &format!("attestation 对象读不出来：{err}"));
            return;
        }
    };
    if Hash::of(&bytes) != digest {
        bad(issues, event, "attestation 对象摘要与事件不一致");
        return;
    }
    let parsed: Attestation = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(err) => {
            bad(issues, event, &format!("attestation 解不开：{err}"));
            return;
        }
    };
    if parsed.commit != id
        || parse_hash(payload.get("witness")) != Some(parsed.witness)
        || parse_hash(payload.get("tree")) != Some(parsed.tree)
        || parse_hash(payload.get("base")) != parsed.base
        || payload.get("key_id").and_then(Value::as_str) != Some(parsed.key_id.as_str())
        || payload.get("signature").and_then(Value::as_str) != Some(parsed.signature.as_str())
        || payload.get("signed_at_ms").and_then(Value::as_u64) != Some(parsed.signed_at_ms)
        || payload.get("session").and_then(Value::as_str) != Some(parsed.session.as_str())
    {
        bad(issues, event, "attestation 事件与 sidecar 对象不一致");
        return;
    }
    let commit = match repo.commit_at(&id) {
        Ok(commit) => commit,
        Err(err) => {
            bad(
                issues,
                event,
                &format!("attestation 指向的提交读不出来：{err}"),
            );
            return;
        }
    };
    let base = match commit.parents.first() {
        Some(parent) => match repo.commit_at(parent) {
            Ok(parent) => Some(parent.tree),
            Err(err) => {
                bad(
                    issues,
                    event,
                    &format!("attestation 的父提交读不出来：{err}"),
                );
                return;
            }
        },
        None => None,
    };
    let witness_bytes = match repo.store().get_chunk(&parsed.witness) {
        Ok(bytes) => bytes,
        Err(err) => {
            bad(
                issues,
                event,
                &format!("attestation 的 witness 对象读不出来：{err}"),
            );
            return;
        }
    };
    let keys = match repo.keys() {
        Ok(keys) => keys,
        Err(err) => {
            bad(issues, event, &format!("读不到信任表：{err}"));
            return;
        }
    };
    let Some(entry) = keys.keys.get(&parsed.key_id) else {
        bad(issues, event, "attestation 签者不在信任表");
        return;
    };
    let Some(public) = entry.public_key.as_deref() else {
        bad(issues, event, "attestation 签者没有公钥");
        return;
    };
    let public_bytes = match signing::public_key_bytes(public) {
        Ok(bytes) => bytes,
        Err(_) => {
            bad(issues, event, "attestation 公钥不合法");
            return;
        }
    };
    if public_key_id(&public_bytes) != parsed.key_id {
        bad(issues, event, "attestation key_id 与公钥指纹不一致");
        return;
    }
    if parsed.signed_at_ms < entry.added_at_ms {
        bad(issues, event, "attestation 签名早于签者加入信任表");
        return;
    }
    if !matches!(entry.role.as_str(), "author" | "auditor" | "release") {
        bad(issues, event, "attestation 签者角色不受支持");
        return;
    }
    if entry
        .revoked_at_ms
        .is_some_and(|at| parsed.signed_at_ms > at)
    {
        issues.push(AuditIssue::new(
            "attestation_revoked",
            format!("第 {} 条 attestation 的签者签名时已吊销", event.seq),
        ));
    }
    if let Err(err) = parsed.verify(public, &id, &commit, base, &witness_bytes) {
        issues.push(AuditIssue::new(
            "attestation_invalid",
            format!("第 {} 条 attestation 验签或绑定失败：{err}", event.seq),
        ));
    }
    if let Err(detail) = operation_states_match(event, begin, result) {
        issues.push(AuditIssue::new(
            "attestation_state_mismatch",
            format!("第 {} 条 {detail}", event.seq),
        ));
    }
}

fn bad(issues: &mut Vec<AuditIssue>, event: &Event, detail: &str) {
    issues.push(AuditIssue::new(
        "attestation_bad",
        format!("第 {} 条 attestation {detail}", event.seq),
    ));
}
