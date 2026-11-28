//! `verify` 必须同时跑审计对账：对象库绿、日志缺页不是绿。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_trit-vcs")
}

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(bin())
        .args(args)
        .current_dir(root)
        .output()
        .expect("启动 trit-vcs 失败")
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trit-vcs-verify-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn seed(root: &Path, file: &str, text: &str) {
    let init = run(root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    fs::write(root.join(file), text).unwrap();
    let add = run(root, &["add", file]);
    assert!(add.status.success(), "{}", stderr(&add));
    let commit = run(
        root,
        &[
            "commit",
            "-m",
            "seed",
            "--owner",
            "qoder:test",
            "--allow-unclaimed",
        ],
    );
    assert!(commit.status.success(), "{}", stderr(&commit));
}

fn head(root: &Path) -> String {
    fs::read_to_string(root.join(".tritvcs/HEAD"))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn clean_repo_verify_reports_audit_reconcile() {
    let root = temp("clean");
    seed(&root, "a.txt", "a\n");
    let verify = run(&root, &["verify"]);
    assert!(verify.status.success(), "{}", stderr(&verify));
    assert!(
        stdout(&verify).contains("审计对账通过"),
        "{}",
        stdout(&verify)
    );
    let json = run(&root, &["verify", "--json"]);
    assert!(json.status.success(), "{}", stderr(&json));
    let value: serde_json::Value = serde_json::from_str(&stdout(&json)).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["audit"]["ok"], true);
}

#[test]
fn verify_fails_when_journal_is_deleted() {
    let root = temp("missing-journal");
    seed(&root, "a.txt", "a\n");
    fs::remove_file(root.join(".tritvcs/journal.jsonl")).unwrap();
    let verify = run(&root, &["verify"]);
    assert!(!verify.status.success(), "{}", stdout(&verify));
    let err = stderr(&verify);
    assert!(err.contains("verify_audit"), "{err}");
    assert!(err.contains("journal_missing"), "{err}");
}

#[test]
fn verify_fails_when_head_is_rolled_back() {
    let root = temp("head-rollback");
    seed(&root, "a.txt", "a\n");
    let first = head(&root);
    fs::write(root.join("a.txt"), "b\n").unwrap();
    let add = run(&root, &["add", "a.txt"]);
    assert!(add.status.success(), "{}", stderr(&add));
    let commit = run(
        &root,
        &[
            "commit",
            "-m",
            "second",
            "--owner",
            "qoder:test",
            "--allow-unclaimed",
        ],
    );
    assert!(commit.status.success(), "{}", stderr(&commit));
    fs::write(root.join(".tritvcs/HEAD"), format!("{first}\n")).unwrap();
    let verify = run(&root, &["verify"]);
    assert!(!verify.status.success(), "{}", stdout(&verify));
    let err = stderr(&verify);
    assert!(err.contains("verify_audit"), "{err}");
    assert!(err.contains("head_mismatch"), "{err}");
}

#[test]
fn verify_fails_when_an_operation_is_unclosed() {
    let root = temp("open-op");
    seed(&root, "a.txt", "a\n");
    let journal = root.join(".tritvcs/journal.jsonl");
    let text = fs::read_to_string(&journal).unwrap();
    let kept = text
        .lines()
        .rev()
        .skip(1)
        .collect::<Vec<_>>()
        .into_iter()
        .rev();
    fs::write(
        &journal,
        kept.map(|line| format!("{line}\n")).collect::<String>(),
    )
    .unwrap();
    let verify = run(&root, &["verify"]);
    assert!(!verify.status.success(), "{}", stdout(&verify));
    assert!(stderr(&verify).contains("open_ops"));
}

#[test]
fn verify_fails_when_journal_loses_a_commit_event() {
    let root = temp("missing-commit-event");
    seed(&root, "a.txt", "a\n");
    let journal = root.join(".tritvcs/journal.jsonl");
    let text = fs::read_to_string(&journal).unwrap();
    let mut dropped = false;
    let kept = text
        .lines()
        .filter(|line| {
            if dropped {
                return true;
            }
            let event: serde_json::Value = serde_json::from_str(line).unwrap();
            if event["kind"] == "commit" {
                dropped = true;
                return false;
            }
            true
        })
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    assert!(dropped, "夹具里没有 commit 事件");
    fs::write(&journal, kept).unwrap();
    let verify = run(&root, &["verify"]);
    assert!(!verify.status.success(), "{}", stdout(&verify));
    assert!(stderr(&verify).contains("verify_audit"));
}
