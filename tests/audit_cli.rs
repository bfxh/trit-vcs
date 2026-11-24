//! `trit-vcs audit` 的端到端读数：状态对账、日志查看、故障必须非零。

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
    let dir = std::env::temp_dir().join(format!("trit-vcs-auditcli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn init(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    let out = run(dir, &["init"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

fn seed_commit(root: &Path) {
    init(root);
    fs::write(root.join("a.txt"), "audit\n").unwrap();
    let added = run(root, &["add", "a.txt"]);
    assert!(added.status.success(), "{}", stderr(&added));
    let owner = "audit:cli";
    let claim = run(
        root,
        &[
            "claims",
            "add",
            "--central",
            ".",
            "--id",
            "c1",
            "--owner",
            owner,
            "--path",
            "a.txt",
        ],
    );
    assert!(claim.status.success(), "{}", stderr(&claim));
    let claims = root.join("claims.json");
    let claims_text = claims.to_string_lossy().to_string();
    let exported = run(
        root,
        &["claims", "export", "--central", ".", "--out", &claims_text],
    );
    assert!(exported.status.success(), "{}", stderr(&exported));
    let committed = run(
        root,
        &[
            "commit",
            "-m",
            "seed",
            "--owner",
            owner,
            "--claims",
            &claims_text,
        ],
    );
    assert!(committed.status.success(), "{}", stderr(&committed));
}

#[test]
fn clean_repo_is_l2_and_log_is_readable() {
    let root = temp("clean");
    seed_commit(&root);
    let status = run(&root, &["audit", "status", "--json"]);
    assert!(status.status.success(), "{}", stderr(&status));
    let value: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["level"], "L2");
    assert_eq!(value["chain_ok"], true);
    let event_count = value["events"].as_u64().unwrap();
    assert!(
        event_count >= 6,
        "stage/commit 都应成对留下 op_begin/op_result"
    );
    assert_eq!(value["open_ops"], 0);

    let default = run(&root, &["audit", "--json"]);
    assert!(default.status.success(), "{}", stderr(&default));
    let default_value: serde_json::Value = serde_json::from_str(&stdout(&default)).unwrap();
    assert_eq!(default_value["level"], "L2");

    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let rows: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    assert_eq!(rows.as_array().unwrap().len() as u64, event_count);
    assert_eq!(rows[0]["kind"], "op_begin");
    assert!(
        rows.as_array()
            .unwrap()
            .iter()
            .any(|row| row["kind"] == "stage")
    );

    let show = run(&root, &["audit", "show", "0", "--json"]);
    assert!(show.status.success(), "{}", stderr(&show));
    let event: serde_json::Value = serde_json::from_str(&stdout(&show)).unwrap();
    assert_eq!(event["seq"], 0);
    assert_eq!(event["kind"], "op_begin");
}

#[test]
fn deleted_journal_is_red_and_nonzero() {
    let root = temp("missing");
    seed_commit(&root);
    fs::remove_file(root.join(".tritvcs").join("journal.jsonl")).unwrap();
    let status = run(&root, &["audit", "status", "--json"]);
    assert!(!status.status.success(), "漏账必须非零");
    let value: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["level"], "L0");
    assert_eq!(value["issues"][0]["kind"], "journal_missing");
}

#[test]
fn broken_journal_is_still_auditable() {
    let root = temp("broken");
    seed_commit(&root);
    fs::write(root.join(".tritvcs").join("journal.jsonl"), "not-json\n").unwrap();
    let status = run(&root, &["audit", "status", "--json"]);
    assert!(!status.status.success(), "坏链必须非零");
    let value: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(value["ok"], false);
    assert_eq!(value["chain_ok"], false);
    assert!(
        value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["kind"] == "journal_broken")
    );
}

#[test]
fn manual_ref_write_is_red() {
    let root = temp("ref");
    seed_commit(&root);
    let head = run(&root, &["log", "--json"]);
    assert!(head.status.success());
    let rows: serde_json::Value = serde_json::from_str(&stdout(&head)).unwrap();
    let id = rows[0]["id"].as_str().unwrap().to_string();
    let refs = root.join(".tritvcs").join("refs");
    fs::create_dir_all(&refs).unwrap();
    fs::write(refs.join("hotfix"), format!("{id}\n")).unwrap();
    let status = run(&root, &["audit", "status", "--json"]);
    assert!(!status.status.success());
    let value: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(value["ok"], false);
    assert!(
        value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["kind"] == "ref_unlogged")
    );
}

#[test]
fn accept_receipt_is_hashed_and_audited() {
    let root = temp("accept");
    init(&root);
    fs::write(root.join("a.txt"), "audit\n").unwrap();
    assert!(run(&root, &["add", "a.txt"]).status.success());
    let owner = "audit:accept";
    assert!(
        run(
            &root,
            &[
                "claims",
                "add",
                "--central",
                ".",
                "--id",
                "c1",
                "--owner",
                owner,
                "--path",
                "a.txt",
            ],
        )
        .status
        .success()
    );
    let claims = root.join("claims.json").to_string_lossy().to_string();
    assert!(
        run(
            &root,
            &["claims", "export", "--central", ".", "--out", &claims],
        )
        .status
        .success()
    );
    let preflight = run(
        &root,
        &[
            "preflight",
            "-m",
            "accept",
            "--owner",
            owner,
            "--claims",
            &claims,
            "--goal",
            "check accept receipt",
            "--accept",
            "cargo --version",
            "--verify-accept",
        ],
    );
    assert!(preflight.status.success(), "{}", stderr(&preflight));
    assert!(
        String::from_utf8_lossy(&preflight.stderr).contains("判据回执"),
        "{}",
        stderr(&preflight)
    );
    let status = run(&root, &["audit", "status", "--json"]);
    assert!(status.status.success(), "{}", stderr(&status));
    let value: serde_json::Value = serde_json::from_str(&stdout(&status)).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["level"], "L2");
    let log = run(&root, &["audit", "log", "accept", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let rows: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["payload"]["passed"], true);
    let verify = run(&root, &["verify"]);
    assert!(verify.status.success(), "{}", stderr(&verify));
    assert!(
        stdout(&verify).contains("判据回执 1 条"),
        "{}",
        stdout(&verify)
    );
}
