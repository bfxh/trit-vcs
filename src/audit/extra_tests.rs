//! 审计的补充测试：失败操作如果已经把状态改掉，不能只凭 `status=failed` 放过。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use super::status;
use crate::hash::Hash;
use crate::repo::{DIR, Repo};

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "trit-vcs-audit-extra-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn failed_operation_that_changed_state_is_red() {
    let root = temp("op-failed");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let before = repo.state_digest().unwrap().to_hex();
    let begin = repo
        .journal_mut()
        .append(
            "op_begin",
            json!({"op": "manual", "state_before": before, "args": {}}),
            2_000,
        )
        .unwrap();
    let refs = root.join(DIR).join("refs");
    std::fs::create_dir_all(&refs).unwrap();
    std::fs::write(
        refs.join("hotfix"),
        format!("{}\n", Hash::of(b"not-a-commit")),
    )
    .unwrap();
    let after = repo.state_digest().unwrap().to_hex();
    repo.journal_mut()
        .append(
            "op_result",
            json!({
                "op": "manual",
                "begin": begin.seq,
                "begin_hash": begin.hash.to_hex(),
                "status": "failed",
                "state_after": after,
                "result": {},
            }),
            2_001,
        )
        .unwrap();
    let report = status(&repo).unwrap();
    assert!(!report.ok);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.kind == "op_failed_state_change"),
        "失败操作改了状态必须判红：{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn auth_event_with_request_shape_is_audited_green() {
    let root = temp("auth-ok");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.journal_mut()
        .append(
            "auth",
            json!({
                "action": "auth",
                "decision": "denied",
                "reason": "bad_token",
                "method": "POST",
                "path": "/v1/publish",
                "status": 401,
                "state_before": digest,
                "state_after": digest,
            }),
            2_000,
        )
        .unwrap();
    let report = status(&repo).unwrap();
    assert!(report.ok, "{:?}", report.issues);
    assert_eq!(report.open_ops, 0);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn auth_event_without_401_is_red() {
    let root = temp("auth-bad");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.journal_mut()
        .append(
            "auth",
            json!({
                "action": "auth",
                "decision": "denied",
                "reason": "bad_token",
                "method": "GET",
                "path": "/v1/pull",
                "status": 200,
                "state_after": digest,
            }),
            2_000,
        )
        .unwrap();
    let report = status(&repo).unwrap();
    assert!(!report.ok);
    assert!(
        report.issues.iter().any(|issue| issue.kind == "auth_bad"),
        "{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}
