//! `policy` 的端到端读数：策略变更进链，手工改文件会被审计抓出来。

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
        std::env::temp_dir().join(format!("trit-vcs-policycli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn policy_set_is_audited_and_manual_edit_is_red() {
    let root = temp("flow");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));

    let defaults = run(&root, &["policy", "--json"]);
    assert!(defaults.status.success(), "{}", stderr(&defaults));
    let value: serde_json::Value = serde_json::from_str(&stdout(&defaults)).unwrap();
    assert_eq!(value["require_witness"], false);
    assert_eq!(value["require_intent"], false);

    let set = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-witness",
            "--require-intent",
            "--json",
        ],
    );
    assert!(set.status.success(), "{}", stderr(&set));
    let set_value: serde_json::Value = serde_json::from_str(&stdout(&set)).unwrap();
    assert_eq!(set_value["require_witness"], true);
    assert_eq!(set_value["require_intent"], true);

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true);
    assert_eq!(audit_value["open_ops"], 0);
    let rows = audit_value["events"].as_u64().unwrap();
    assert!(rows >= 3, "policy/op_begin/op_result 都要进链");
    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let policy_event = events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["kind"] == "policy")
        .expect("策略变更必须留下 policy 事件");
    assert_eq!(policy_event["payload"]["session"], "qoder:policy");
    assert_eq!(policy_event["payload"]["require_witness"], true);

    fs::write(
        root.join(".tritvcs").join("policy.json"),
        "{\"require_witness\":false,\"require_intent\":false}\n",
    )
    .unwrap();
    let bad = run(&root, &["audit", "status", "--json"]);
    assert!(!bad.status.success(), "手改策略必须非零");
    let bad_value: serde_json::Value = serde_json::from_str(&stdout(&bad)).unwrap();
    assert!(
        bad_value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["kind"] == "state_drift"),
        "手改策略应报 state_drift：{}",
        stdout(&bad)
    );

    let repaired = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-intent",
            "--json",
        ],
    );
    assert!(repaired.status.success(), "{}", stderr(&repaired));
    let still_red = run(&root, &["audit", "status", "--json"]);
    assert!(
        !still_red.status.success(),
        "手工改动留下的状态缺口不会因为下一次合法写而被抹掉"
    );
    let still_value: serde_json::Value = serde_json::from_str(&stdout(&still_red)).unwrap();
    assert!(
        still_value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["kind"] == "op_state_gap"),
        "后续 op_begin 必须把未记账的手工改动对出来：{}",
        stdout(&still_red)
    );
}
