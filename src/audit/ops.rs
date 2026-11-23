//! 审计里的操作对检查：`op_begin`/`op_result` 的配对与状态连续性。

use std::collections::BTreeMap;

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::hash::Hash;
use crate::journal::Event;

/// 检查写前/写后操作对：每个 `op_begin` 必须有且只有一个 `op_result`，
/// 结果必须指回真实的 begin 且 op 一致；`op_begin.state_before` 还要接得上
/// 上一条已知的 `state_after`。这样即使中间某次状态变更后来被合法事件覆盖，
/// 下一个操作动手前的摘要也会把它对出来。
pub(super) fn check_operations(
    events: &[Event],
    issues: &mut Vec<AuditIssue>,
    warnings: &mut Vec<AuditIssue>,
) -> usize {
    let mut open: BTreeMap<u64, (String, Hash, String)> = BTreeMap::new();
    let mut last_state: Option<String> = None;

    for event in events {
        match event.kind.as_str() {
            "op_begin" => {
                let op = event.payload.get("op").and_then(Value::as_str);
                let before = parse_hash(event.payload.get("state_before"));
                match (op, before) {
                    (Some(op), Some(before)) => {
                        if let Some(last) = &last_state
                            && last != &before.to_hex()
                        {
                            issues.push(AuditIssue::new(
                                "op_state_gap",
                                format!(
                                    "第 {} 条 op_begin（{op}）动手前状态是 {}，上一条已知状态是 {last}",
                                    event.seq,
                                    before.to_hex()
                                ),
                            ));
                        }
                        open.insert(event.seq, (op.to_string(), event.hash, before.to_hex()));
                    }
                    _ => issues.push(AuditIssue::new(
                        "op_begin_bad",
                        format!("第 {} 条 op_begin 缺 op/state_before", event.seq),
                    )),
                }
            }
            "op_result" => {
                let begin_seq = event.payload.get("begin").and_then(Value::as_u64);
                let Some(begin_seq) = begin_seq else {
                    issues.push(AuditIssue::new(
                        "op_result_bad",
                        format!("第 {} 条 op_result 缺 begin 序号", event.seq),
                    ));
                    continue;
                };
                let Some((begin_op, begin_hash, begin_state)) = open.remove(&begin_seq) else {
                    issues.push(AuditIssue::new(
                        "op_result_unknown",
                        format!(
                            "第 {} 条 op_result 指回的 op_begin #{begin_seq} 不存在或已收口",
                            event.seq
                        ),
                    ));
                    continue;
                };
                let op = event.payload.get("op").and_then(Value::as_str);
                if op != Some(begin_op.as_str()) {
                    issues.push(AuditIssue::new(
                        "op_result_mismatch",
                        format!(
                            "第 {} 条 op_result 的 op 是 {:?}，op_begin #{begin_seq} 的 op 是 {begin_op}",
                            event.seq, op
                        ),
                    ));
                }
                let recorded_begin = parse_hash(event.payload.get("begin_hash"));
                if recorded_begin != Some(begin_hash) {
                    issues.push(AuditIssue::new(
                        "op_result_mismatch",
                        format!(
                            "第 {} 条 op_result 的 begin_hash 与 op_begin #{begin_seq} 的 hash 对不上",
                            event.seq
                        ),
                    ));
                }
                let status = event.payload.get("status").and_then(Value::as_str);
                match status {
                    Some("ok" | "failed") => {}
                    other => issues.push(AuditIssue::new(
                        "op_result_bad",
                        format!("第 {} 条 op_result 的 status 非法：{other:?}", event.seq),
                    )),
                }
                match parse_hash(event.payload.get("state_after")) {
                    Some(after) => {
                        if status == Some("failed") && after.to_hex() != begin_state {
                            issues.push(AuditIssue::new(
                                "op_failed_state_change",
                                format!(
                                    "第 {} 条 {} 标记 failed，但状态从 {} 变成了 {}",
                                    event.seq,
                                    begin_op,
                                    begin_state,
                                    after.to_hex()
                                ),
                            ));
                        }
                        last_state = Some(after.to_hex());
                    }
                    None => issues.push(AuditIssue::new(
                        "op_result_bad",
                        format!("第 {} 条 op_result 缺 state_after", event.seq),
                    )),
                }
            }
            _ => {
                if let Some(before) = parse_hash(event.payload.get("state_before"))
                    && let Some(last) = &last_state
                    && last != &before.to_hex()
                {
                    issues.push(AuditIssue::new(
                        "event_state_gap",
                        format!(
                            "第 {} 条 {} 动手前状态是 {}，上一条已知状态是 {last}",
                            event.seq,
                            event.kind,
                            before.to_hex()
                        ),
                    ));
                }
                if let Some(after) = parse_hash(event.payload.get("state_after")) {
                    last_state = Some(after.to_hex());
                }
            }
        }
    }

    for (seq, (op, _, _)) in &open {
        warnings.push(AuditIssue::new(
            "op_open",
            format!("op_begin #{seq}（{op}）没有对应的 op_result；进程可能死在操作中间"),
        ));
    }
    open.len()
}
