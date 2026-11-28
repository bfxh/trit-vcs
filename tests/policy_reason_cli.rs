//! `policy set` 的变更原因/工单端到端读数：v6 事件、签名与关闭门槛。

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
        "trit-vcs-policy-reason-{name}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn policy_change_reason_is_required_and_recorded_in_v6_event() {
    let root = temp("reason");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let key = run(&root, &["key", "init", "--out", "policy.key", "--json"]);
    assert!(key.status.success(), "{}", stderr(&key));
    let add = run(
        &root,
        &[
            "key",
            "add",
            "--key-file",
            "policy.key",
            "--principal",
            "qoder:policy",
            "--role",
            "auditor",
            "--owner",
            "qoder:policy",
        ],
    );
    assert!(add.status.success(), "{}", stderr(&add));

    let missing = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--require-policy-reason",
            "--sign-key",
            "policy.key",
        ],
    );
    assert!(
        !missing.status.success(),
        "require_policy_reason 下缺原因必须失败"
    );
    assert!(
        stderr(&missing).contains("--policy-reason"),
        "{}",
        stderr(&missing)
    );

    let strict = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--require-policy-reason",
            "--policy-reason",
            "启用变更原因门槛",
            "--policy-ticket",
            "OPS-9",
            "--sign-key",
            "policy.key",
            "--json",
        ],
    );
    assert!(strict.status.success(), "{}", stderr(&strict));
    let strict_value: serde_json::Value = serde_json::from_str(&stdout(&strict)).unwrap();
    assert_eq!(strict_value["require_policy_reason"], true);
    assert_eq!(strict_value["policy_reason"], "启用变更原因门槛");
    assert_eq!(strict_value["policy_ticket"], "OPS-9");

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true);
    let log = run(&root, &["audit", "log", "--json"]);
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let policy = events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["kind"] == "policy")
        .expect("策略变更必须留下 policy 事件");
    assert_eq!(policy["payload"]["schema"], "trit-policy-v6");
    assert_eq!(policy["payload"]["require_policy_reason"], true);
    assert_eq!(policy["payload"]["policy_reason"], "启用变更原因门槛");
    assert_eq!(policy["payload"]["policy_ticket"], "OPS-9");

    let show = run(&root, &["policy", "--json"]);
    assert!(show.status.success(), "{}", stderr(&show));
    let show_value: serde_json::Value = serde_json::from_str(&stdout(&show)).unwrap();
    assert_eq!(show_value["require_policy_reason"], true);

    let closed_without_reason = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--sign-key",
            "policy.key",
        ],
    );
    assert!(
        !closed_without_reason.status.success(),
        "关闭原因门槛也必须说明原因"
    );
    let closed = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--policy-reason",
            "关闭原因门槛",
            "--sign-key",
            "policy.key",
        ],
    );
    assert!(closed.status.success(), "{}", stderr(&closed));
    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true);
    let log = run(&root, &["audit", "log", "--json"]);
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let last = events
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event["kind"] == "policy")
        .expect("关闭也必须留下 policy 事件");
    assert_eq!(last["payload"]["schema"], "trit-policy-v6");
    assert_eq!(last["payload"]["require_policy_reason"], false);
    assert_eq!(last["payload"]["policy_reason"], "关闭原因门槛");
    assert!(last["payload"]["policy_ticket"].is_null());
}
