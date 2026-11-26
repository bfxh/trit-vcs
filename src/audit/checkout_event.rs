//! `trit-checkout-v1`：`checkout --force` 放行未提交改动时留下的独立事件。
//!
//! `checkout` 只改工作树、不改 HEAD/refs/index，所以 `state_before` 与 `state_after`
//! 必须相等；事件本身证明的是“哪次强制检出、放行了哪些未提交改动”。完整脏集合由
//! `dirty_digest` 承诺，`dirty_sample` 只是给人看的前几条路径。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::journal::Event;
use crate::repo::Repo;
use crate::sparse::normalize_prefix;
use crate::worktree::{CHECKOUT_DIRTY_SAMPLE_MAX, CHECKOUT_SCHEMA};

pub(super) fn check_checkout(repo: &Repo, event: &Event, issues: &mut Vec<AuditIssue>) {
    let payload = &event.payload;
    if payload.get("schema").and_then(Value::as_str) != Some(CHECKOUT_SCHEMA) {
        bad(issues, event, "schema 不受支持");
        return;
    }
    if payload.get("force").and_then(Value::as_bool) != Some(true) {
        bad(issues, event, "只接受 force=true 的检出事件");
    }
    if payload.get("reason").and_then(Value::as_str) != Some("dirty_worktree") {
        bad(issues, event, "reason 必须是 dirty_worktree");
    }
    let Some(commit) = parse_hash(payload.get("commit")) else {
        bad(issues, event, "缺 commit");
        return;
    };
    if repo.commit_at(&commit).is_err() {
        bad(issues, event, "commit 在对象库里不存在");
    }
    match payload.get("prefix") {
        Some(Value::Null) => {}
        Some(Value::String(prefix))
            if normalize_prefix(prefix).is_ok_and(|normalized| normalized == *prefix) => {}
        _ => bad(issues, event, "prefix 既不是空也不是规范前缀"),
    }
    let Some(dirty) = payload.get("dirty").and_then(Value::as_u64) else {
        bad(issues, event, "缺 dirty");
        return;
    };
    if dirty == 0 {
        bad(issues, event, "dirty 必须大于 0");
    }
    let Some(sample) = payload.get("dirty_sample").and_then(Value::as_array) else {
        bad(issues, event, "缺 dirty_sample");
        return;
    };
    if sample.len() > CHECKOUT_DIRTY_SAMPLE_MAX || sample.len() as u64 > dirty {
        bad(issues, event, "dirty_sample 超过条数或采样上限");
    }
    if sample.iter().any(|path| {
        path.as_str()
            .is_none_or(|raw| raw.is_empty() || normalize_prefix(raw).is_err())
    }) {
        bad(issues, event, "dirty_sample 含空路径或非法路径");
    }
    if parse_hash(payload.get("dirty_digest")).is_none() {
        bad(issues, event, "缺 dirty_digest");
    }
    if payload.get("written").and_then(Value::as_u64).is_none()
        || payload.get("skipped").and_then(Value::as_u64).is_none()
    {
        bad(issues, event, "缺 written/skipped");
    }
    let before = parse_hash(payload.get("state_before"));
    let after = parse_hash(payload.get("state_after"));
    match (before, after) {
        (Some(before), Some(after)) if before == after => {}
        (Some(_), Some(_)) => bad(
            issues,
            event,
            "state_before/state_after 必须相等（检出只改工作树）",
        ),
        _ => bad(issues, event, "缺 state_before/state_after"),
    }
}

fn bad(issues: &mut Vec<AuditIssue>, event: &Event, detail: &str) {
    issues.push(AuditIssue::new(
        "checkout_bad",
        format!("第 {} 条 checkout {detail}", event.seq),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Hash;
    use crate::model::{Commit, Hlc};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trit-vcs-checkout-event-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn seed() -> (PathBuf, Repo, Hash) {
        let root = temp("seed");
        std::fs::create_dir_all(&root).unwrap();
        let repo = Repo::init(&root).unwrap();
        let commit = Commit::new(Hash::of(b"tree"), "audit:test", "seed", Hlc::zero());
        let encoded = commit.encode().unwrap();
        let (id, _) = repo.store().put_chunk(&encoded).unwrap();
        (root, repo, id)
    }

    fn event(seq: u64, payload: Value) -> Event {
        Event {
            seq,
            at_ms: seq,
            kind: "checkout".to_string(),
            hash: Hash::of(format!("{seq}:checkout").as_bytes()),
            payload,
            prev: None,
        }
    }

    fn valid_event(seq: u64, commit: &Hash, state: &Hash) -> Event {
        event(
            seq,
            serde_json::json!({
                "schema": CHECKOUT_SCHEMA,
                "commit": commit.to_hex(),
                "prefix": "a",
                "force": true,
                "reason": "dirty_worktree",
                "dirty": 1,
                "dirty_sample": ["a.txt"],
                "dirty_digest": Hash::of(b"dirty").to_hex(),
                "written": 1,
                "skipped": 0,
                "state_before": state.to_hex(),
                "state_after": state.to_hex(),
            }),
        )
    }

    #[test]
    fn force_checkout_event_passes() {
        let (root, repo, commit) = seed();
        let state = repo.state_digest().unwrap();
        let mut issues = Vec::new();
        check_checkout(&repo, &valid_event(1, &commit, &state), &mut issues);
        assert!(issues.is_empty(), "{issues:?}");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn missing_force_zero_dirty_or_bad_sample_is_red() {
        let (root, repo, commit) = seed();
        let state = repo.state_digest().unwrap();
        let mut event = valid_event(1, &commit, &state);
        event.payload["force"] = Value::Bool(false);
        let mut issues = Vec::new();
        check_checkout(&repo, &event, &mut issues);
        assert!(issues.iter().any(|issue| issue.kind == "checkout_bad"));

        let mut event = valid_event(2, &commit, &state);
        event.payload["dirty"] = Value::from(0);
        let mut issues = Vec::new();
        check_checkout(&repo, &event, &mut issues);
        assert!(issues.iter().any(|issue| issue.kind == "checkout_bad"));

        let mut event = valid_event(3, &commit, &state);
        event.payload["dirty_sample"] = serde_json::json!([""]);
        let mut issues = Vec::new();
        check_checkout(&repo, &event, &mut issues);
        assert!(issues.iter().any(|issue| issue.kind == "checkout_bad"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn state_change_or_missing_commit_is_red() {
        let (root, repo, commit) = seed();
        let state = repo.state_digest().unwrap();
        let mut event = valid_event(1, &commit, &state);
        event.payload["state_after"] = Value::from(Hash::of(b"other").to_hex());
        let mut issues = Vec::new();
        check_checkout(&repo, &event, &mut issues);
        assert!(issues.iter().any(|issue| issue.kind == "checkout_bad"));

        let mut event = valid_event(2, &commit, &state);
        event.payload["commit"] = Value::from(Hash::of(b"missing").to_hex());
        let mut issues = Vec::new();
        check_checkout(&repo, &event, &mut issues);
        assert!(issues.iter().any(|issue| issue.kind == "checkout_bad"));
        let _ = std::fs::remove_dir_all(&root);
    }
}
