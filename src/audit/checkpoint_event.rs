//! `checkpoint` 事件的语义检查：高度、前缀 Merkle 根、前一条检查点、签名与信任表。
//!
//! 检查点不改变仓库状态，所以合法事件要求 `state_before == state_after`；它签的是
//! “检查点事件之前的事件前缀”，检查点事件本身不在根里。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::checkpoint::{checkpoint_statement, key_matches_public, merkle_root};
use crate::journal::Event;
use crate::repo::Repo;
use crate::signing::verify_signature;

pub(super) fn check_checkpoint(
    repo: &Repo,
    events: &[Event],
    index: usize,
    event: &Event,
    issues: &mut Vec<AuditIssue>,
    warnings: &mut Vec<AuditIssue>,
) {
    let payload = &event.payload;
    let Some(height) = payload.get("height").and_then(Value::as_u64) else {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!("第 {} 条 checkpoint 缺 height", event.seq),
        ));
        return;
    };
    let height_usize = match usize::try_from(height) {
        Ok(value) => value,
        Err(_) => {
            issues.push(AuditIssue::new(
                "checkpoint_bad",
                format!("第 {} 条 checkpoint 的 height 太大", event.seq),
            ));
            return;
        }
    };
    if height_usize > events.len() {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!(
                "第 {} 条 checkpoint 的 height={} 超过日志条数 {}",
                event.seq,
                height,
                events.len()
            ),
        ));
        return;
    }
    if index != height_usize || event.seq as usize != height_usize {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!(
                "第 {} 条 checkpoint 的 seq 是 {}，height 是 {}；检查点必须紧贴自己的前缀",
                event.seq, event.seq, height
            ),
        ));
    }

    let expected_head = events[..height_usize].last().map(|event| event.hash);
    let head = parse_hash(payload.get("head"));
    if head != expected_head {
        issues.push(AuditIssue::new(
            "checkpoint_head_mismatch",
            format!(
                "第 {} 条 checkpoint 的 head 是 {:?}，前缀最后一条是 {:?}",
                event.seq,
                head.map(|hash| hash.to_hex()),
                expected_head.map(|hash| hash.to_hex())
            ),
        ));
    }

    let Some(root) = parse_hash(payload.get("merkle_root")) else {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!("第 {} 条 checkpoint 缺可解析的 merkle_root", event.seq),
        ));
        return;
    };
    let expected_root = merkle_root(
        &events[..height_usize]
            .iter()
            .map(|event| event.hash)
            .collect::<Vec<_>>(),
    );
    if root != expected_root {
        issues.push(AuditIssue::new(
            "checkpoint_merkle_mismatch",
            format!(
                "第 {} 条 checkpoint 的 merkle_root 是 {}，重算得到 {}",
                event.seq,
                root.to_hex(),
                expected_root.to_hex()
            ),
        ));
    }

    let previous = parse_hash(payload.get("previous"));
    let expected_previous = events[..height_usize]
        .iter()
        .rev()
        .find(|event| event.kind == "checkpoint")
        .map(|event| event.hash);
    if previous != expected_previous {
        issues.push(AuditIssue::new(
            "checkpoint_chain_mismatch",
            format!(
                "第 {} 条 checkpoint 的 previous 是 {:?}，前缀里最后一条检查点是 {:?}",
                event.seq,
                previous.map(|hash| hash.to_hex()),
                expected_previous.map(|hash| hash.to_hex())
            ),
        ));
    }

    let Some(key_id) = payload.get("key_id").and_then(Value::as_str) else {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!("第 {} 条 checkpoint 缺 key_id", event.seq),
        ));
        return;
    };
    // 即使链路不对，也继续做根/签名检查，让同一条假事件一次报全。
    let _ = check_operation_link(events, height_usize, event, key_id, issues);
    if payload.get("algorithm").and_then(Value::as_str) != Some("ed25519") {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!("第 {} 条 checkpoint 的 algorithm 不是 ed25519", event.seq),
        ));
        return;
    }
    let Some(signature) = payload.get("signature").and_then(Value::as_str) else {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!("第 {} 条 checkpoint 缺 signature", event.seq),
        ));
        return;
    };
    let Some(signed_at) = payload.get("signed_at_ms").and_then(Value::as_u64) else {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!("第 {} 条 checkpoint 缺 signed_at_ms", event.seq),
        ));
        return;
    };
    let statement = checkpoint_statement(
        height_usize,
        expected_head,
        expected_root,
        expected_previous,
        signed_at,
        key_id,
    );

    let store = match repo.keys() {
        Ok(store) => store,
        Err(err) => {
            issues.push(AuditIssue::new(
                "checkpoint_untrusted",
                format!("第 {} 条 checkpoint 读不到信任表：{err}", event.seq),
            ));
            return;
        }
    };
    let Some(entry) = store.keys.get(key_id) else {
        issues.push(AuditIssue::new(
            "checkpoint_untrusted",
            format!("第 {} 条 checkpoint 签者 {key_id} 不在信任表", event.seq),
        ));
        return;
    };
    let Some(public) = entry.public_key.as_deref() else {
        issues.push(AuditIssue::new(
            "checkpoint_untrusted",
            format!("第 {} 条 checkpoint 签者 {key_id} 没有公钥", event.seq),
        ));
        return;
    };
    if key_matches_public(key_id, public).is_err() {
        issues.push(AuditIssue::new(
            "checkpoint_untrusted",
            format!("第 {} 条 checkpoint 的 key_id 与公钥指纹不一致", event.seq),
        ));
        return;
    }
    if !matches!(entry.role.as_str(), "auditor" | "release") {
        issues.push(AuditIssue::new(
            "checkpoint_untrusted",
            format!(
                "第 {} 条 checkpoint 签者角色是 {}，不是 auditor/release",
                event.seq, entry.role
            ),
        ));
    }
    if entry
        .revoked_at_ms
        .is_some_and(|revoked_at| signed_at > revoked_at)
    {
        issues.push(AuditIssue::new(
            "checkpoint_revoked",
            format!("第 {} 条 checkpoint 签名时 key {key_id} 已吊销", event.seq),
        ));
    }
    if verify_signature(public, signature, &statement).is_err() {
        issues.push(AuditIssue::new(
            "checkpoint_signature_invalid",
            format!("第 {} 条 checkpoint 的签名验不过前缀声明", event.seq),
        ));
    }

    let before = parse_hash(payload.get("state_before"));
    let after = parse_hash(payload.get("state_after"));
    match (before, after) {
        (Some(before), Some(after)) if before != after => issues.push(AuditIssue::new(
            "checkpoint_state_change",
            format!(
                "第 {} 条 checkpoint 标记不改状态，但 state_before={}、state_after={}",
                event.seq,
                before.to_hex(),
                after.to_hex()
            ),
        )),
        (Some(_), Some(_)) => {}
        _ => warnings.push(AuditIssue::new(
            "checkpoint_no_state",
            format!("第 {} 条 checkpoint 缺 state_before/state_after", event.seq),
        )),
    }
}

fn check_operation_link(
    events: &[Event],
    height: usize,
    event: &Event,
    key_id: &str,
    issues: &mut Vec<AuditIssue>,
) -> bool {
    let Some(begin) = height.checked_sub(1).and_then(|index| events.get(index)) else {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!("第 {} 条 checkpoint 的前缀里没有 op_begin", event.seq),
        ));
        return false;
    };
    let mut ok = true;
    if begin.kind != "op_begin"
        || begin.payload.get("op").and_then(Value::as_str) != Some("checkpoint")
    {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!(
                "第 {} 条 checkpoint 前一条不是 checkpoint op_begin，而是 {}",
                event.seq, begin.kind
            ),
        ));
        ok = false;
    }
    let args_key = begin
        .payload
        .get("args")
        .and_then(|args| args.get("key_id"))
        .and_then(Value::as_str);
    let args_session = begin
        .payload
        .get("args")
        .and_then(|args| args.get("session"))
        .and_then(Value::as_str);
    let event_session = event.payload.get("session").and_then(Value::as_str);
    if args_key != Some(key_id) || args_session != event_session {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!(
                "第 {} 条 checkpoint 的 op_begin key/session 与事件不一致",
                event.seq
            ),
        ));
        ok = false;
    }

    let Some(result) = events.get(height + 1) else {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!("第 {} 条 checkpoint 后没有 op_result 收口", event.seq),
        ));
        return false;
    };
    let begin_hash = begin.hash.to_hex();
    let result_ok = result.kind == "op_result"
        && result.payload.get("op").and_then(Value::as_str) == Some("checkpoint")
        && result.payload.get("begin").and_then(Value::as_u64) == Some(begin.seq)
        && result.payload.get("begin_hash").and_then(Value::as_str)
            == Some(begin_hash.as_str())
        && result.payload.get("status").and_then(Value::as_str) == Some("ok")
        && parse_hash(result.payload.get("state_after"))
            == parse_hash(event.payload.get("state_after"));
    if !result_ok {
        issues.push(AuditIssue::new(
            "checkpoint_bad",
            format!("第 {} 条 checkpoint 的 op_result 收口不匹配", event.seq),
        ));
        ok = false;
    }
    ok
}
