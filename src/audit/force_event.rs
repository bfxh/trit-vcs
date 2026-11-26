//! `trit-force-v1`：显式 `--force` 改写 ref/HEAD 的独立事件。
//!
//! 该事件只说明“这次成功应用带了强制开关”，必须能和同 op_id 的成功 `trit-sync-v1`
//! 事件对上；否则一条孤立的 `force` 事件既证明不了改写，也证明不了是谁触发的。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::hash::Hash;
use crate::journal::Event;
use crate::sync::{FORCE_SCHEMA, SCHEMA, valid_op_id};

pub(super) fn check_force(events: &[Event], event: &Event, issues: &mut Vec<AuditIssue>) {
    let payload = &event.payload;
    if payload.get("schema").and_then(Value::as_str) != Some(FORCE_SCHEMA) {
        bad(issues, event, "schema 不受支持");
        return;
    }
    let action = payload.get("action").and_then(Value::as_str);
    let transport = payload.get("transport").and_then(Value::as_str);
    let side = payload.get("side").and_then(Value::as_str);
    let combo_ok = matches!(
        (action, transport, side),
        (Some("publish"), Some("local"), Some("central"))
            | (Some("pull"), Some("local"), Some("client"))
            | (Some("pull"), Some("http"), Some("client"))
    );
    if !combo_ok {
        bad(issues, event, "action/transport/side 组合不受支持");
    }
    let Some(name) = payload.get("name").and_then(Value::as_str) else {
        bad(issues, event, "缺 name");
        return;
    };
    if crate::repo::Repo::validate_ref(name).is_err() {
        bad(issues, event, "name 不是合法 ref");
    }
    let Some(op_id) = payload.get("op_id").and_then(Value::as_str) else {
        bad(issues, event, "缺 op_id");
        return;
    };
    if !valid_op_id(op_id) {
        bad(issues, event, "op_id 不是合法哈希");
    }
    let Some(commit) = parse_hash(payload.get("commit")) else {
        bad(issues, event, "缺 commit");
        return;
    };
    let previous = match payload.get("previous") {
        Some(Value::Null) | None => None,
        Some(value) => match parse_hash(Some(value)) {
            Some(id) => Some(id),
            None => {
                bad(issues, event, "previous 既不是空也不是合法哈希");
                return;
            }
        },
    };
    if action == Some("publish") && previous.is_none() {
        bad(issues, event, "publish 的强制改写必须记录被替换的 previous");
    }
    let reason = payload.get("reason").and_then(Value::as_str);
    if !matches!(
        reason,
        Some("non_fast_forward" | "dirty_worktree" | "requested")
    ) {
        bad(issues, event, "reason 不合法");
    }
    if parse_hash(payload.get("state_before")).is_none()
        || parse_hash(payload.get("state_after")).is_none()
    {
        bad(issues, event, "缺 state_before/state_after");
    }

    let op_hash = Hash::from_hex(op_id);
    let linked = events.iter().any(|other| {
        if other.kind.as_str() != action.unwrap_or_default()
            || other.payload.get("schema").and_then(Value::as_str) != Some(SCHEMA)
            || other.payload.get("side").and_then(Value::as_str) != side
            || other.payload.get("name").and_then(Value::as_str) != Some(name)
            || parse_hash(other.payload.get("commit")) != Some(commit)
            || other.payload.get("forced") != Some(&Value::Bool(true))
        {
            return false;
        }
        match (&op_hash, other.payload.get("op_id").and_then(Value::as_str)) {
            (Some(op), Some(raw)) => Hash::from_hex(raw) == Some(*op),
            _ => false,
        }
    });
    if !linked {
        issues.push(AuditIssue::new(
            "force_link_missing",
            format!(
                "第 {} 条 force 事件找不到同 op_id/side 的成功 sync 事件（action={}）",
                event.seq,
                action.unwrap_or("?")
            ),
        ));
    }

    if action == Some("publish")
        && events.iter().any(|other| {
            other.kind == "publish"
                && other.payload.get("schema").and_then(Value::as_str) == Some(SCHEMA)
                && other.payload.get("side").and_then(Value::as_str) == Some("central")
                && other.payload.get("op_id").and_then(Value::as_str) == Some(op_id)
                && other
                    .payload
                    .get("previous")
                    .and_then(Value::as_str)
                    .and_then(Hash::from_hex)
                    != previous
        })
    {
        bad(issues, event, "previous 与同 op_id 的 publish 事件不一致");
    }
}

fn bad(issues: &mut Vec<AuditIssue>, event: &Event, detail: &str) {
    issues.push(AuditIssue::new(
        "force_bad",
        format!("第 {} 条 force {detail}", event.seq),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(seq: u64, kind: &str, payload: Value) -> Event {
        Event {
            seq,
            at_ms: seq,
            kind: kind.to_string(),
            hash: Hash::of(format!("{seq}:{kind}").as_bytes()),
            payload,
            prev: None,
        }
    }

    fn evidence(seq: u64, action: &str, transport: &str, side: &str) -> (Event, Event) {
        let op_id = Hash::of(format!("op-{seq}").as_bytes()).to_hex();
        let previous = Hash::of(b"previous").to_hex();
        let commit = Hash::of(b"commit").to_hex();
        let sync = event(
            seq + 1,
            action,
            json!({
                "schema": SCHEMA,
                "action": action,
                "op_id": op_id,
                "transport": transport,
                "side": side,
                "request_id": null,
                "actor": null,
                "name": "main",
                "commit": commit,
                "stage": "applied",
                "forced": true,
                "previous": previous,
                "state_before": Hash::of(b"before").to_hex(),
                "state_after": Hash::of(b"after").to_hex(),
            }),
        );
        let force = event(
            seq,
            "force",
            json!({
                "schema": FORCE_SCHEMA,
                "action": action,
                "transport": transport,
                "side": side,
                "name": "main",
                "op_id": op_id,
                "commit": commit,
                "previous": previous,
                "reason": "non_fast_forward",
                "state_before": Hash::of(b"before").to_hex(),
                "state_after": Hash::of(b"after").to_hex(),
            }),
        );
        (force, sync)
    }

    #[test]
    fn linked_force_event_passes() {
        let (force, sync) = evidence(1, "publish", "local", "central");
        let mut issues = Vec::new();
        check_force(&[force.clone(), sync], &force, &mut issues);
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn missing_sync_link_is_red() {
        let (force, _) = evidence(1, "pull", "http", "client");
        let mut issues = Vec::new();
        check_force(std::slice::from_ref(&force), &force, &mut issues);
        assert!(
            issues
                .iter()
                .any(|issue| issue.kind == "force_link_missing")
        );
    }

    #[test]
    fn forged_previous_or_switch_is_red() {
        let (force, sync) = evidence(1, "publish", "local", "central");
        let mut forged = force.clone();
        forged.payload["previous"] = json!(Hash::of(b"other").to_hex());
        let mut issues = Vec::new();
        check_force(&[forged.clone(), sync.clone()], &forged, &mut issues);
        assert!(issues.iter().any(|issue| issue.kind == "force_bad"));

        let mut unforced = sync;
        unforced.payload["forced"] = json!(false);
        let mut issues = Vec::new();
        check_force(&[force.clone(), unforced], &force, &mut issues);
        assert!(
            issues
                .iter()
                .any(|issue| issue.kind == "force_link_missing")
        );
    }

    #[test]
    fn publish_force_requires_a_previous_tip() {
        let (mut force, _) = evidence(1, "publish", "local", "central");
        force.payload["previous"] = Value::Null;
        let mut issues = Vec::new();
        check_force(std::slice::from_ref(&force), &force, &mut issues);
        assert!(issues.iter().any(|issue| issue.kind == "force_bad"));
    }
}
