//! `audit checkpoint` 的端到端账：前缀高度、Merkle 根、双检查点链和审计复验。

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
    let dir = std::env::temp_dir().join(format!(
        "trit-vcs-checkpointcli-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn checkpoint_cli_signs_prefix_and_chains_two_checkpoints() {
    let root = temp("chain");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    fs::write(root.join("a.txt"), "alpha").unwrap();
    let add = run(&root, &["add", "a.txt"]);
    assert!(add.status.success(), "{}", stderr(&add));

    let key_init = run(&root, &["key", "init", "--out", "auditor.key", "--json"]);
    assert!(key_init.status.success(), "{}", stderr(&key_init));
    let key: serde_json::Value = serde_json::from_str(&stdout(&key_init)).unwrap();
    let key_id = key["key_id"].as_str().unwrap().to_string();
    let trust = run(
        &root,
        &[
            "key",
            "add",
            "--key-file",
            "auditor.key",
            "--principal",
            "qoder:auditor",
            "--role",
            "auditor",
            "--owner",
            "qoder:auditor",
        ],
    );
    assert!(trust.status.success(), "{}", stderr(&trust));

    let first = run(
        &root,
        &[
            "audit",
            "checkpoint",
            "--key-file",
            "auditor.key",
            "--owner",
            "qoder:auditor",
            "--json",
        ],
    );
    assert!(first.status.success(), "{}", stderr(&first));
    let first_value: serde_json::Value = serde_json::from_str(&stdout(&first)).unwrap();
    assert!(first_value["height"].as_u64().unwrap() > 0);
    assert_eq!(first_value["key_id"], key_id);
    assert_eq!(first_value["signature"].as_str().unwrap().len(), 128);
    assert_eq!(first_value["merkle_root"].as_str().unwrap().len(), 64);
    assert!(first_value["previous"].is_null());

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true, "{}", stdout(&audit));

    let checkpoint_seq = first_value["height"].as_u64().unwrap().to_string();
    let proof = run(
        &root,
        &[
            "audit",
            "proof",
            "--checkpoint",
            &checkpoint_seq,
            "--event",
            "0",
            "--json",
        ],
    );
    assert!(proof.status.success(), "{}", stderr(&proof));
    let proof_value: serde_json::Value = serde_json::from_str(&stdout(&proof)).unwrap();
    assert_eq!(proof_value["checkpoint_event"], first_value["event"]);
    assert_eq!(proof_value["merkle_root"], first_value["merkle_root"]);
    assert!(!proof_value["proof"].as_array().unwrap().is_empty());

    // 再写一条事件，第二个检查点必须指回第一个事件哈希。
    fs::write(root.join("b.txt"), "beta").unwrap();
    let add = run(&root, &["add", "b.txt"]);
    assert!(add.status.success(), "{}", stderr(&add));
    let second = run(
        &root,
        &[
            "audit",
            "checkpoint",
            "--key-file",
            "auditor.key",
            "--owner",
            "qoder:auditor",
            "--json",
        ],
    );
    assert!(second.status.success(), "{}", stderr(&second));
    let second_value: serde_json::Value = serde_json::from_str(&stdout(&second)).unwrap();
    assert_eq!(second_value["previous"], first_value["event"]);
    assert!(second_value["height"].as_u64().unwrap() > first_value["height"].as_u64().unwrap());

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true, "{}", stdout(&audit));

    let log = run(&root, &["audit", "log", "checkpoint", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let rows: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 2);
    assert_eq!(rows[0]["payload"]["previous"], serde_json::Value::Null);
    assert_eq!(rows[1]["payload"]["previous"], first_value["event"]);
}

#[test]
fn checkpoint_requires_auditor_or_release_role() {
    let root = temp("role");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let key_init = run(&root, &["key", "init", "--out", "author.key", "--json"]);
    assert!(key_init.status.success(), "{}", stderr(&key_init));
    let trust = run(
        &root,
        &[
            "key",
            "add",
            "--key-file",
            "author.key",
            "--principal",
            "qoder:author",
            "--role",
            "author",
            "--owner",
            "qoder:author",
        ],
    );
    assert!(trust.status.success(), "{}", stderr(&trust));
    let checkpoint = run(
        &root,
        &[
            "audit",
            "checkpoint",
            "--key-file",
            "author.key",
            "--owner",
            "qoder:author",
        ],
    );
    assert!(!checkpoint.status.success(), "author 不能签检查点");
    assert!(
        stderr(&checkpoint).contains("auditor/release"),
        "{}",
        stderr(&checkpoint)
    );
    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true);
}
