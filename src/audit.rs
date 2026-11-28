//! 审计对账：把哈希链事件日志和仓库当前状态放在一起比。
//!
//! 这个模块回答的是审计员的第一个问题：**日志有没有解释当前状态？**
//! 它不替代 `Repo::verify`（对象库体检），而是在它之上补三件现在缺的事：
//! - 日志文件是否还在、有没有被截断/改坏；
//! - HEAD、refs、对象是否和日志里记的最后状态对得上；
//! - 最新事件里如果带 `state_after`，它是否等于当前状态摘要。
//!   提交签名、密钥轮换、检查点/锚、认领签名与 witness attestation 已接入。

use std::{collections::BTreeMap, path::PathBuf};

use crate::claims::ClaimSet;
use crate::hash::Hash;
use crate::journal::{Event, Journal, JournalError};
use crate::repo::{Repo, RepoError};
use serde::Serialize;
use serde_json::Value;
pub(crate) mod attestation_event;
mod auth_event;
mod checkout_event;
mod checkpoint_event;
mod claim_signature_event;
mod deny_event;
mod force_event;
mod key_event;
mod ops;
mod policy_event;
mod signature_event;
mod sync_event;
#[derive(Clone, Debug, Serialize)]
pub struct AuditIssue {
    pub kind: String,
    pub detail: String,
}

impl AuditIssue {
    fn new(kind: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            detail: detail.into(),
        }
    }
}

/// `audit status` / `audit verify` 的读数。
#[derive(Clone, Debug, Serialize)]
pub struct AuditReport {
    pub ok: bool,
    pub level: String,
    pub next_level: String,
    pub events: usize,
    pub open_ops: usize,
    pub chain_ok: bool,
    pub head: Option<String>,
    pub refs: BTreeMap<String, String>,
    pub state_digest: String,
    pub issues: Vec<AuditIssue>,
    pub warnings: Vec<AuditIssue>,
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("仓库: {0}")]
    Repo(#[from] RepoError),
    #[error("事件日志: {0}")]
    Journal(#[from] JournalError),
}

pub fn journal_path(repo: &Repo) -> PathBuf {
    repo.root().join(crate::repo::DIR).join("journal.jsonl")
}

fn parse_hash(value: Option<&Value>) -> Option<Hash> {
    value.and_then(Value::as_str).and_then(Hash::from_hex)
}

fn push_issue(issues: &mut Vec<AuditIssue>, kind: &str, detail: impl Into<String>) {
    issues.push(AuditIssue::new(kind, detail));
}
fn state_present(repo: &Repo) -> Result<bool, AuditError> {
    Ok(repo.head()?.is_some() || !repo.list_refs()?.is_empty())
}

/// 对账一次：链、HEAD、refs、对象、claim_set、状态摘要。
pub fn status(repo: &Repo) -> Result<AuditReport, AuditError> {
    let path = journal_path(repo);
    let exists = path.is_file();
    let memory_events = repo.journal().events();
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    let mut chain_ok = true;

    let mut disk_count = None;
    if exists {
        match Journal::verify(&path) {
            Ok(count) => disk_count = Some(count),
            Err(err) => {
                chain_ok = false;
                push_issue(&mut issues, "journal_broken", err.to_string());
            }
        }
    } else if state_present(repo)? || !memory_events.is_empty() {
        chain_ok = false;
        push_issue(
            &mut issues,
            "journal_missing",
            format!("{} 不存在，但仓库已有状态", path.display()),
        );
    }

    let disk = if exists {
        Journal::open(&path).ok()
    } else {
        None
    };
    let events: &[Event] = disk.as_ref().map(Journal::events).unwrap_or(memory_events);
    if let Some(count) = disk_count {
        if count < memory_events.len() {
            chain_ok = false;
            push_issue(
                &mut issues,
                "journal_truncated",
                format!("盘上 {count} 条，内存里已加载 {} 条", memory_events.len()),
            );
        } else if count > memory_events.len() {
            warnings.push(AuditIssue::new(
                "journal_ahead",
                format!(
                    "盘上 {count} 条，比本次打开时多 {} 条",
                    count - memory_events.len()
                ),
            ));
        }
    }

    let open_ops = ops::check_operations(events, &mut issues, &mut warnings);
    if let Some(pending) = repo.pending_txn() {
        let msg = format!("发现未完成事务 {pending}；下一次持锁写操作会先回滚快照再继续");
        push_issue(&mut issues, "txn_pending", msg);
    }

    let actual_head = repo.head()?;
    let mut expected_head = None;
    let mut expected_refs: BTreeMap<String, String> = BTreeMap::new();
    for event in events {
        match event.kind.as_str() {
            "commit" => {
                if let Some(id) = parse_hash(event.payload.get("id")) {
                    expected_head = Some(id);
                } else {
                    push_issue(
                        &mut issues,
                        "bad_event_payload",
                        format!("第 {} 条 commit 事件缺 id", event.seq),
                    );
                }
            }
            "adopt" => {
                if let Some(id) = parse_hash(event.payload.get("commit")) {
                    expected_head = Some(id);
                } else {
                    push_issue(
                        &mut issues,
                        "bad_event_payload",
                        format!("第 {} 条 adopt 事件缺 commit", event.seq),
                    );
                }
            }
            "ref" => match (
                event.payload.get("name").and_then(Value::as_str),
                parse_hash(event.payload.get("commit")),
            ) {
                (Some(name), Some(id)) => {
                    expected_refs.insert(name.to_string(), id.to_hex());
                }
                _ => push_issue(
                    &mut issues,
                    "bad_event_payload",
                    format!("第 {} 条 ref 事件缺 name/commit", event.seq),
                ),
            },
            _ => {}
        }
    }

    match (actual_head, expected_head) {
        (Some(actual), Some(expected)) if actual != expected => push_issue(
            &mut issues,
            "head_mismatch",
            format!(
                "HEAD 是 {}，日志最后记的是 {}",
                actual.short(),
                expected.short()
            ),
        ),
        (Some(actual), None) => push_issue(
            &mut issues,
            "head_unlogged",
            format!(
                "HEAD 是 {}，日志里没有任何 commit/adopt 事件",
                actual.short()
            ),
        ),
        (None, Some(expected)) => push_issue(
            &mut issues,
            "head_missing",
            format!("日志最后记的提交 {} 没有落到 HEAD", expected.short()),
        ),
        _ => {}
    }

    let actual_refs: BTreeMap<String, String> = repo
        .list_refs()?
        .into_iter()
        .map(|(name, id)| (name, id.to_hex()))
        .collect();
    for (name, actual) in &actual_refs {
        match expected_refs.get(name) {
            Some(expected) if expected == actual => {}
            Some(expected) => push_issue(
                &mut issues,
                "ref_mismatch",
                format!("ref {name} 现在是 {actual}，日志最后记的是 {expected}"),
            ),
            None => push_issue(
                &mut issues,
                "ref_unlogged",
                format!("ref {name} 指向 {actual}，日志里没有它的设置事件"),
            ),
        }
    }
    for (name, expected) in &expected_refs {
        if !actual_refs.contains_key(name) {
            push_issue(
                &mut issues,
                "ref_missing",
                format!("日志记了 ref {name} → {expected}，但工作树里没有这个 ref"),
            );
        }
    }
    let (mut require_signed_witness, mut require_signed_claims) = (false, false);
    let mut policy_replay = policy_event::PolicyReplay::default();
    let mut signed_witness_commits = BTreeMap::new();
    for (index, event) in events.iter().enumerate() {
        match event.kind.as_str() {
            "claim_add" | "claim_release" => {
                claim_signature_event::check_claim_event(
                    events,
                    index,
                    event,
                    require_signed_claims,
                    &mut issues,
                );
            }
            "stage" => {
                if let Some(tree) = parse_hash(event.payload.get("tree"))
                    && let Err(err) = repo.store().tree_entries(&tree)
                {
                    push_issue(
                        &mut issues,
                        "object_missing",
                        format!(
                            "第 {} 条 stage 的树 {} 读不出来：{err}",
                            event.seq,
                            tree.short()
                        ),
                    );
                }
            }
            "commit" => {
                if let Some(id) = parse_hash(event.payload.get("id")) {
                    match repo.commit_at(&id) {
                        Ok(commit) => {
                            attestation_event::track_commit(
                                id,
                                index,
                                &commit,
                                require_signed_witness,
                                &mut signed_witness_commits,
                                &mut issues,
                            );
                            if let Some(claim_set) = commit.claim_set {
                                match repo.store().get_chunk(&claim_set) {
                                    Ok(bytes) => match ClaimSet::decode(&bytes) {
                                        Ok(set) => match set.id() {
                                            Ok(actual) if actual == claim_set => {}
                                            Ok(actual) => push_issue(
                                                &mut issues,
                                                "claim_set_mismatch",
                                                format!(
                                                    "提交 {} 的 claim_set 摘要记录 {claim_set}，实际 {actual}",
                                                    id.short()
                                                ),
                                            ),
                                            Err(err) => push_issue(
                                                &mut issues,
                                                "claim_set_bad",
                                                format!(
                                                    "提交 {} 的 claim_set 编码失败：{err}",
                                                    id.short()
                                                ),
                                            ),
                                        },
                                        Err(err) => push_issue(
                                            &mut issues,
                                            "claim_set_bad",
                                            format!(
                                                "提交 {} 的 claim_set 解不开：{err}",
                                                id.short()
                                            ),
                                        ),
                                    },
                                    Err(err) => push_issue(
                                        &mut issues,
                                        "claim_set_missing",
                                        format!("提交 {} 的 claim_set 对象缺失：{err}", id.short()),
                                    ),
                                }
                            }
                        }
                        Err(err) => push_issue(
                            &mut issues,
                            "object_missing",
                            format!(
                                "第 {} 条 commit 的 {} 读不出来：{err}",
                                event.seq,
                                id.short()
                            ),
                        ),
                    }
                }
            }
            "ref" | "adopt" => {
                if let Some(id) = parse_hash(event.payload.get("commit"))
                    && let Err(err) = repo.commit_at(&id)
                {
                    push_issue(
                        &mut issues,
                        "object_missing",
                        format!(
                            "第 {} 条 {} 的提交 {} 读不出来：{err}",
                            event.seq,
                            event.kind,
                            id.short()
                        ),
                    );
                }
            }
            "pull" | "publish" => {
                if let Some(id) = parse_hash(event.payload.get("commit"))
                    && let Err(err) = repo.commit_at(&id)
                {
                    push_issue(
                        &mut issues,
                        "object_missing",
                        format!(
                            "第 {} 条 {} 的提交 {} 读不出来：{err}",
                            event.seq,
                            event.kind,
                            id.short()
                        ),
                    );
                }
                sync_event::check_sync(events, index, event, &mut issues);
            }
            "gate" => {
                if event.payload.get("decision").and_then(Value::as_str) != Some("denied") {
                    push_issue(
                        &mut issues,
                        "gate_bad",
                        format!("第 {} 条 gate 事件的 decision 不是 denied", event.seq),
                    );
                }
                if event
                    .payload
                    .get("reason")
                    .and_then(Value::as_str)
                    .is_none()
                {
                    push_issue(
                        &mut issues,
                        "gate_bad",
                        format!("第 {} 条 gate 事件缺 reason", event.seq),
                    );
                }
                if parse_hash(event.payload.get("state_after")).is_none() {
                    warnings.push(AuditIssue::new(
                        "gate_no_state",
                        format!("第 {} 条 gate 事件没有可解析的 state_after", event.seq),
                    ));
                }
            }
            "policy" => {
                require_signed_claims = policy_event::require_signed_claims(event);
                require_signed_witness = policy_event::require_signed_witness(event);
                policy_replay.observe(repo, event, &mut issues, &mut warnings);
            }
            "key" => key_event::check_key(repo, event, &mut issues, &mut warnings),
            "signature" => {
                signature_event::check_signature(repo, event, &mut issues, &mut warnings)
            }
            "claim_signature" => claim_signature_event::check_claim_signature(
                repo,
                events,
                index,
                event,
                &mut issues,
            ),
            "checkpoint" => checkpoint_event::check_checkpoint(
                repo,
                events,
                event.seq as usize,
                event,
                &mut issues,
                &mut warnings,
            ),
            "attestation" => {
                attestation_event::check_attestation(repo, events, index, event, &mut issues)
            }
            "auth" => auth_event::check_auth(event, &mut issues, &mut warnings),
            "deny" => deny_event::check_deny(events, index, event, &mut issues, &mut warnings),
            "force" => force_event::check_force(events, event, &mut issues),
            "checkout" => checkout_event::check_checkout(repo, event, &mut issues),
            "accept" => {
                let Some(receipt) = parse_hash(event.payload.get("receipt")) else {
                    push_issue(
                        &mut issues,
                        "bad_event_payload",
                        format!("第 {} 条 accept 事件缺 receipt", event.seq),
                    );
                    continue;
                };
                match repo.store().get_chunk(&receipt) {
                    Ok(bytes) => match crate::accept::AcceptReceipt::decode(&bytes) {
                        Ok(parsed) => match parsed.id() {
                            Ok(actual) if actual == receipt => {}
                            Ok(actual) => push_issue(
                                &mut issues,
                                "receipt_mismatch",
                                format!(
                                    "第 {} 条 accept 回执记录 {receipt}，实际 {actual}",
                                    event.seq
                                ),
                            ),
                            Err(err) => push_issue(
                                &mut issues,
                                "receipt_bad",
                                format!("第 {} 条 accept 回执编码失败：{err}", event.seq),
                            ),
                        },
                        Err(err) => push_issue(
                            &mut issues,
                            "receipt_bad",
                            format!("第 {} 条 accept 回执解不开：{err}", event.seq),
                        ),
                    },
                    Err(err) => push_issue(
                        &mut issues,
                        "receipt_missing",
                        format!("第 {} 条 accept 回执对象缺失：{err}", event.seq),
                    ),
                }
            }
            _ => {}
        }
    }
    attestation_event::check_required(events, &signed_witness_commits, &mut issues);
    let digest = repo.state_digest()?;
    let latest_state = events
        .iter()
        .rev()
        .find_map(|event| event.payload.get("state_after").and_then(Value::as_str));
    if let Some(expected) = latest_state {
        if expected != digest.to_hex() {
            push_issue(
                &mut issues,
                "state_drift",
                format!("最新事件记的状态 {expected}，当前状态 {}", digest.to_hex()),
            );
        }
    } else if !events.is_empty() {
        warnings.push(AuditIssue::new(
            "no_state_digest",
            "历史事件里没有 state_after；只能做语义对账，不能做状态摘要比对",
        ));
    }

    // `Repo::verify` 还负责全对象 fsck、witness 解码、claim_set/receipt 摘要；
    // audit 不复制这些规则，只把它的失败作为一个 issue 带出来。
    if let Err(err) = repo.verify() {
        push_issue(&mut issues, "verify_failed", err.to_string());
    }

    let level = if !chain_ok {
        "L0"
    } else if issues.is_empty() && latest_state.is_some() {
        "L2"
    } else {
        "L1"
    };
    let next_level = if level == "L2" { "L3" } else { "L2" };
    Ok(AuditReport {
        ok: issues.is_empty(),
        level: level.to_string(),
        next_level: next_level.to_string(),
        events: events.len(),
        open_ops,
        chain_ok,
        head: actual_head.map(|id| id.to_hex()),
        refs: actual_refs,
        state_digest: digest.to_hex(),
        issues,
        warnings,
    })
}

pub fn log(
    repo: &Repo,
    kind: Option<&str>,
    from: Option<u64>,
    to: Option<u64>,
) -> Result<Vec<Value>, AuditError> {
    let journal = Journal::open(journal_path(repo))?;
    Ok(journal
        .events()
        .iter()
        .filter(|event| kind.is_none_or(|want| event.kind == want))
        .filter(|event| from.is_none_or(|start| event.seq >= start))
        .filter(|event| to.is_none_or(|end| event.seq <= end))
        .filter_map(|event| serde_json::to_value(event).ok())
        .collect())
}

pub fn show(repo: &Repo, seq: u64) -> Result<Option<Value>, AuditError> {
    let journal = Journal::open(journal_path(repo))?;
    Ok(journal
        .events()
        .iter()
        .find(|event| event.seq == seq)
        .and_then(|event| serde_json::to_value(event).ok()))
}

pub fn json(report: &AuditReport) -> Value {
    serde_json::to_value(report).unwrap_or(Value::Null)
}

/// 只给测试/诊断用：确认状态摘要不是由 journal 自己算出来的。
pub fn state_digest(repo: &Repo) -> Result<Hash, AuditError> {
    repo.state_digest().map_err(AuditError::Repo)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::ClaimSpec;
    use crate::repo::CommitRequest;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn temp(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "trit-vcs-audit-{tag}-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn seed(tag: &str) -> (PathBuf, Repo) {
        let root = temp(tag);
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let mut repo = Repo::init(&root).unwrap();
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_string(), b"audit\n".to_vec());
        repo.stage(&files, 1_000).unwrap();
        repo.commit(CommitRequest {
            message: "seed".to_string(),
            session: "audit:test".to_string(),
            claims: vec![ClaimSpec {
                id: "c1".to_string(),
                owner: "audit:test".to_string(),
                paths: vec!["a.txt".to_string()],
                acquired_at: 1,
                expires_at: u64::MAX / 2,
            }],
            now_secs: 1_000,
            ..Default::default()
        })
        .unwrap();
        (root, repo)
    }

    #[test]
    fn empty_repo_has_no_journal_issue() {
        let dir = temp("empty");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let repo = Repo::init(&dir).unwrap();
        let report = status(&repo).unwrap();
        assert!(report.ok, "空仓不应报漏账");
        assert_eq!(report.events, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clean_commit_reaches_l2_and_verify_sees_claim_set() {
        let (root, repo) = seed("clean");
        let report = status(&repo).unwrap();
        assert!(report.ok, "干净提交不应有问题：{:?}", report.issues);
        assert_eq!(report.level, "L2");
        assert_eq!(report.next_level, "L3");
        let head = repo.head().unwrap().unwrap();
        let commit = repo.commit_at(&head).unwrap();
        assert!(commit.claim_set.is_some(), "提交必须带认领快照");
        assert_eq!(repo.verify().unwrap().claim_sets, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn deleted_journal_is_l0() {
        let (root, _) = seed("missing");
        let journal = journal_path(&Repo::open(&root).unwrap());
        std::fs::remove_file(&journal).unwrap();
        let repo = Repo::open(&root).unwrap();
        let report = status(&repo).unwrap();
        assert!(!report.ok);
        assert_eq!(report.level, "L0");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "journal_missing")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn manual_ref_write_without_event_is_caught() {
        let (root, repo) = seed("ref");
        let head = repo.head().unwrap().unwrap();
        let refs = root.join(crate::repo::DIR).join("refs");
        std::fs::create_dir_all(&refs).unwrap();
        std::fs::write(refs.join("hotfix"), format!("{head}\n")).unwrap();
        let report = status(&Repo::open(&root).unwrap()).unwrap();
        assert!(!report.ok);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "ref_unlogged")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn manual_head_write_without_event_is_caught() {
        let (root, _) = seed("head");
        let fake = Hash::of(b"not-a-commit");
        std::fs::write(
            root.join(crate::repo::DIR).join("HEAD"),
            format!("{fake}\n"),
        )
        .unwrap();
        let report = status(&Repo::open(&root).unwrap()).unwrap();
        assert!(!report.ok);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "head_mismatch")
        );
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "state_drift")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tampered_journal_fails_the_chain() {
        let (root, repo) = seed("broken");
        let journal = journal_path(&repo);
        std::fs::write(&journal, "not-json\n").unwrap();
        let report = status(&repo).unwrap();
        assert!(!report.ok);
        assert!(!report.chain_ok);
        assert_eq!(report.level, "L0");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "journal_broken")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn open_operation_is_visible_but_not_red() {
        let (root, mut repo) = seed("open-op");
        let before = repo.state_digest().unwrap().to_hex();
        repo.journal_mut()
            .append(
                "op_begin",
                json!({"op": "manual", "state_before": before, "args": {}}),
                2_000,
            )
            .unwrap();
        let report = status(&repo).unwrap();
        assert_eq!(report.open_ops, 1);
        assert!(report.ok, "没改状态的中断操作只应提示，不应判红");
        assert_eq!(report.level, "L2");
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.kind == "op_open")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn op_result_hash_mismatch_is_red() {
        let (root, mut repo) = seed("op-result");
        let before = repo.state_digest().unwrap().to_hex();
        let begin = repo
            .journal_mut()
            .append(
                "op_begin",
                json!({"op": "manual", "state_before": before, "args": {}}),
                2_000,
            )
            .unwrap();
        let after = repo.state_digest().unwrap().to_hex();
        repo.journal_mut()
            .append(
                "op_result",
                json!({
                    "op": "manual",
                    "begin": begin.seq,
                    "begin_hash": Hash::of(b"wrong-begin").to_hex(),
                    "status": "ok",
                    "state_after": after,
                    "result": {},
                }),
                2_001,
            )
            .unwrap();
        let report = status(&repo).unwrap();
        assert!(!report.ok);
        assert_eq!(report.open_ops, 0);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "op_result_mismatch")
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unlogged_state_between_ops_is_caught_by_next_begin() {
        let (root, mut repo) = seed("op-gap");
        let head = repo.head().unwrap().unwrap();
        let refs = root.join(crate::repo::DIR).join("refs");
        std::fs::create_dir_all(&refs).unwrap();
        std::fs::write(refs.join("hotfix"), format!("{head}\n")).unwrap();
        let before = repo.state_digest().unwrap().to_hex();
        repo.journal_mut()
            .append(
                "op_begin",
                json!({"op": "manual", "state_before": before, "args": {}}),
                2_000,
            )
            .unwrap();
        let report = status(&repo).unwrap();
        assert!(!report.ok);
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "op_state_gap"),
            "下一个 op_begin 的 state_before 必须接得上上一条 state_after：{:?}",
            report.issues
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}

#[cfg(test)]
mod extra_tests;
