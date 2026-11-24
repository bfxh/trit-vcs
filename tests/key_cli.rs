//! `key` 的端到端账：add/revoke 进链，keyset 原始字节进状态摘要。

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
    let dir =
        std::env::temp_dir().join(format!("trit-vcs-keycli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

const KEY: &str = "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn key_add_and_revoke_are_audited_and_keyset_drift_is_red() {
    let root = temp("flow");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));

    let add = run(
        &root,
        &[
            "key",
            "add",
            "--key-id",
            KEY,
            "--principal",
            "qoder:key",
            "--role",
            "author",
            "--owner",
            "qoder:keycli",
            "--json",
        ],
    );
    assert!(add.status.success(), "{}", stderr(&add));
    let add_value: serde_json::Value = serde_json::from_str(&stdout(&add)).unwrap();
    assert_eq!(add_value["action"], "add");
    assert_eq!(add_value["key_id"], KEY);

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true);
    assert_eq!(audit_value["open_ops"], 0);

    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let key_event = events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["kind"] == "key")
        .expect("key add 必须留下 key 事件");
    assert_eq!(key_event["payload"]["action"], "add");
    assert_eq!(key_event["payload"]["session"], "qoder:keycli");

    let list = run(&root, &["key", "list", "--json"]);
    assert!(list.status.success(), "{}", stderr(&list));
    let list_value: serde_json::Value = serde_json::from_str(&stdout(&list)).unwrap();
    assert_eq!(list_value["keys"][0]["principal"], "qoder:key");

    let revoke = run(
        &root,
        &[
            "key",
            "revoke",
            "--key-id",
            KEY,
            "--reason",
            "测试吊销",
            "--owner",
            "qoder:keycli",
            "--json",
        ],
    );
    assert!(revoke.status.success(), "{}", stderr(&revoke));
    let audit_after = run(&root, &["audit", "status", "--json"]);
    assert!(audit_after.status.success(), "{}", stderr(&audit_after));
    let revoked = run(&root, &["key", "list", "--json"]);
    assert!(revoked.status.success(), "{}", stderr(&revoked));
    let revoked_value: serde_json::Value = serde_json::from_str(&stdout(&revoked)).unwrap();
    assert!(revoked_value["keys"][0]["revoked_at_ms"].as_u64().is_some());

    // raw 字节变化也必须被状态摘要抓到；append 一个换行不会破坏 JSON。
    let path = root.join(".tritvcs").join("keys.json");
    let text = fs::read_to_string(&path).unwrap();
    fs::write(&path, format!("{text}\n")).unwrap();
    let bad = run(&root, &["audit", "status", "--json"]);
    assert!(!bad.status.success(), "手改 keyset 必须非零");
    let bad_value: serde_json::Value = serde_json::from_str(&stdout(&bad)).unwrap();
    assert!(
        bad_value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["kind"] == "state_drift"),
        "手改 keyset 应报 state_drift：{}",
        stdout(&bad)
    );
}

#[test]
fn generated_key_signs_commit_and_audit_verifies() {
    let root = temp("sign");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    fs::write(root.join("a.txt"), "alpha").unwrap();
    let add = run(&root, &["add", "a.txt"]);
    assert!(add.status.success(), "{}", stderr(&add));

    let key_init = run(&root, &["key", "init", "--out", "key.json", "--json"]);
    assert!(key_init.status.success(), "{}", stderr(&key_init));
    let key: serde_json::Value = serde_json::from_str(&stdout(&key_init)).unwrap();
    let key_id = key["key_id"].as_str().unwrap().to_string();
    assert!(key["public"].as_str().unwrap().len() == 64);

    let trust = run(
        &root,
        &[
            "key",
            "add",
            "--key-file",
            "key.json",
            "--principal",
            "qoder:sign",
            "--owner",
            "qoder:sign",
        ],
    );
    assert!(trust.status.success(), "{}", stderr(&trust));

    let commit = run(
        &root,
        &[
            "commit",
            "-m",
            "签名提交",
            "--owner",
            "qoder:sign",
            "--allow-unclaimed",
            "--sign-key",
            "key.json",
        ],
    );
    assert!(commit.status.success(), "{}", stderr(&commit));

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true);

    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let signature = events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["kind"] == "signature")
        .expect("签名提交必须留下 signature 事件");
    assert_eq!(signature["payload"]["key_id"], key_id);
    assert_eq!(signature["payload"]["algorithm"], "ed25519");
}

#[test]
fn generated_key_rotation_is_audited_and_old_key_is_revoked() {
    let root = temp("rotate");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    fs::write(root.join("a.txt"), "alpha").unwrap();
    let add = run(&root, &["add", "a.txt"]);
    assert!(add.status.success(), "{}", stderr(&add));

    let old_init = run(&root, &["key", "init", "--out", "old.json", "--json"]);
    assert!(old_init.status.success(), "{}", stderr(&old_init));
    let old_key: serde_json::Value = serde_json::from_str(&stdout(&old_init)).unwrap();
    let old_id = old_key["key_id"].as_str().unwrap().to_string();
    let new_init = run(&root, &["key", "init", "--out", "new.json", "--json"]);
    assert!(new_init.status.success(), "{}", stderr(&new_init));
    let new_key: serde_json::Value = serde_json::from_str(&stdout(&new_init)).unwrap();
    let new_id = new_key["key_id"].as_str().unwrap().to_string();

    let trust = run(
        &root,
        &[
            "key",
            "add",
            "--key-file",
            "old.json",
            "--principal",
            "qoder:rotate",
            "--owner",
            "qoder:rotate",
        ],
    );
    assert!(trust.status.success(), "{}", stderr(&trust));
    let commit = run(
        &root,
        &[
            "commit",
            "-m",
            "轮换前签名",
            "--owner",
            "qoder:rotate",
            "--allow-unclaimed",
            "--sign-key",
            "old.json",
        ],
    );
    assert!(commit.status.success(), "{}", stderr(&commit));

    let rotate = run(
        &root,
        &[
            "key",
            "rotate",
            "--old-key-file",
            "old.json",
            "--new-key-file",
            "new.json",
            "--reason",
            "年度轮换",
            "--owner",
            "qoder:rotate",
            "--json",
        ],
    );
    assert!(rotate.status.success(), "{}", stderr(&rotate));
    let rotate_value: serde_json::Value = serde_json::from_str(&stdout(&rotate)).unwrap();
    assert_eq!(rotate_value["action"], "rotate");
    assert_eq!(rotate_value["old_key_id"], old_id);
    assert_eq!(rotate_value["key_id"], new_id);

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true, "轮换后审计必须绿：{}", stdout(&audit));

    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let rotate_event = events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["kind"] == "key" && event["payload"]["action"] == "rotate")
        .expect("rotate 必须留下 key 事件");
    assert_eq!(rotate_event["payload"]["old_key_id"], old_id);
    assert_eq!(rotate_event["payload"]["key_id"], new_id);
    assert_eq!(rotate_event["payload"]["reason"], "年度轮换");

    let list = run(&root, &["key", "list", "--json"]);
    assert!(list.status.success(), "{}", stderr(&list));
    let list_value: serde_json::Value = serde_json::from_str(&stdout(&list)).unwrap();
    let old_entry = list_value["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key_id"] == old_id)
        .unwrap();
    assert!(old_entry["revoked_at_ms"].is_number());
    let new_entry = list_value["keys"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["key_id"] == new_id)
        .unwrap();
    assert_eq!(new_entry["rotated_from"], old_id);
}

#[test]
fn duplicate_and_unknown_key_are_rejected_without_new_event() {
    let root = temp("reject");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let args = [
        "key",
        "add",
        "--key-id",
        KEY,
        "--principal",
        "qoder:key",
        "--owner",
        "qoder:keycli",
    ];
    let first = run(&root, &args);
    assert!(first.status.success(), "{}", stderr(&first));
    let duplicate = run(&root, &args);
    assert!(!duplicate.status.success(), "重复 key 必须失败");
    assert!(
        stderr(&duplicate).contains("已存在"),
        "{}",
        stderr(&duplicate)
    );
    let unknown = run(
        &root,
        &[
            "key",
            "revoke",
            "--key-id",
            "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            "--reason",
            "不存在",
            "--owner",
            "qoder:keycli",
        ],
    );
    assert!(!unknown.status.success(), "未知 key 必须失败");
    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let key_events = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|event| event["kind"] == "key")
        .count();
    assert_eq!(key_events, 1, "失败命令只能留 op_result，不能伪造 key 事件");
}
