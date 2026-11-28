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
fn signed_policy_change_is_attributed_and_strict_mode_requires_it() {
    let root = temp("signed");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let key = run(&root, &["key", "init", "--out", "policy.key", "--json"]);
    assert!(key.status.success(), "{}", stderr(&key));
    let key_value: serde_json::Value = serde_json::from_str(&stdout(&key)).unwrap();
    let key_id = key_value["key_id"].as_str().unwrap().to_string();
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

    let author_key = run(
        &root,
        &["key", "init", "--out", "policy-author.key", "--json"],
    );
    assert!(author_key.status.success(), "{}", stderr(&author_key));
    let author_add = run(
        &root,
        &[
            "key",
            "add",
            "--key-file",
            "policy-author.key",
            "--principal",
            "qoder:author",
            "--role",
            "author",
            "--owner",
            "qoder:author",
        ],
    );
    assert!(author_add.status.success(), "{}", stderr(&author_add));

    let signed = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--sign-key",
            "policy.key",
            "--json",
        ],
    );
    assert!(signed.status.success(), "{}", stderr(&signed));
    let signed_value: serde_json::Value = serde_json::from_str(&stdout(&signed)).unwrap();
    assert_eq!(signed_value["require_signed_policy"], true);
    assert_eq!(signed_value["signed"], true);

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let audit_value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true);
    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let policy = events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["kind"] == "policy")
        .expect("策略变更必须留下 policy 事件");
    assert_eq!(policy["payload"]["algorithm"], "ed25519");
    assert_eq!(policy["payload"]["require_signed_policy"], true);
    assert!(policy["payload"]["previous_policy_hash"].is_null());
    assert_eq!(policy["payload"]["policy_threshold"], 1);
    assert_eq!(policy["payload"]["signatures"][0]["key_id"], key_id);
    assert!(
        policy["payload"]["signatures"][0]["signature"]
            .as_str()
            .is_some()
    );

    let non_auditor = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--sign-key",
            "policy-author.key",
            "--json",
        ],
    );
    assert!(
        !non_auditor.status.success(),
        "非 auditor 签严格策略必须失败"
    );
    assert!(
        stderr(&non_auditor).contains("auditor"),
        "{}",
        stderr(&non_auditor)
    );
    assert!(
        stderr(&non_auditor).contains("角色是 author"),
        "必须报签名 key 的角色不匹配，而不是只报缺少角色：{}",
        stderr(&non_auditor)
    );

    let unsigned = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-witness",
            "--json",
        ],
    );
    assert!(!unsigned.status.success(), "严格策略下无签名变更必须失败");
    assert!(
        stderr(&unsigned).contains("--sign-key"),
        "{}",
        stderr(&unsigned)
    );

    let re_signed = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-witness",
            "--require-signed-policy",
            "--sign-key",
            "policy.key",
            "--json",
        ],
    );
    assert!(re_signed.status.success(), "{}", stderr(&re_signed));
    let re_audit = run(&root, &["audit", "status", "--json"]);
    assert!(re_audit.status.success(), "{}", stderr(&re_audit));
}

#[test]
fn policy_quorum_cli_requires_multiple_auditor_keys() {
    let root = temp("quorum");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    for (key_file, principal) in [("policy-a.key", "qoder:a"), ("policy-b.key", "qoder:b")] {
        let key = run(&root, &["key", "init", "--out", key_file, "--json"]);
        assert!(key.status.success(), "{}", stderr(&key));
        let add = run(
            &root,
            &[
                "key",
                "add",
                "--key-file",
                key_file,
                "--principal",
                principal,
                "--role",
                "auditor",
                "--owner",
                "qoder:policy",
            ],
        );
        assert!(add.status.success(), "{}", stderr(&add));
    }

    let one = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--policy-threshold",
            "2",
            "--sign-key",
            "policy-a.key",
            "--json",
        ],
    );
    assert!(!one.status.success(), "2-of-2 策略不能被单钥开启");
    assert!(stderr(&one).contains("至少 2"), "{}", stderr(&one));

    let two = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--policy-threshold",
            "2",
            "--sign-key",
            "policy-a.key",
            "--sign-key",
            "policy-b.key",
            "--json",
        ],
    );
    assert!(two.status.success(), "{}", stderr(&two));
    let two_value: serde_json::Value = serde_json::from_str(&stdout(&two)).unwrap();
    assert_eq!(two_value["policy_threshold"], 2);
    assert_eq!(two_value["signer_count"], 2);

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let policy = events
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event["kind"] == "policy")
        .unwrap();
    assert_eq!(policy["payload"]["policy_threshold"], 2);
    assert_eq!(policy["payload"]["signatures"].as_array().unwrap().len(), 2);

    let lower = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--policy-threshold",
            "1",
            "--sign-key",
            "policy-a.key",
            "--json",
        ],
    );
    assert!(!lower.status.success(), "调低阈值也必须满足旧阈值");
    assert!(stderr(&lower).contains("至少 2"), "{}", stderr(&lower));
}

#[test]
fn mixed_role_policy_cli_requires_auditor_and_release() {
    let root = temp("mixed-role");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    for (key_file, principal, role) in [
        ("policy-auditor.key", "qoder:auditor", "auditor"),
        ("policy-release.key", "qoder:release", "release"),
    ] {
        let key = run(&root, &["key", "init", "--out", key_file, "--json"]);
        assert!(key.status.success(), "{}", stderr(&key));
        let add = run(
            &root,
            &[
                "key",
                "add",
                "--key-file",
                key_file,
                "--principal",
                principal,
                "--role",
                role,
                "--owner",
                "qoder:policy",
            ],
        );
        assert!(add.status.success(), "{}", stderr(&add));
    }

    let invalid_role = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--policy-role",
            "owner",
            "--json",
        ],
    );
    assert!(!invalid_role.status.success(), "未知策略角色必须拒绝");
    assert!(
        stderr(&invalid_role).contains("只支持 auditor/release"),
        "{}",
        stderr(&invalid_role)
    );

    let one = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--policy-threshold",
            "2",
            "--policy-role",
            "release",
            "--policy-role",
            "auditor",
            "--sign-key",
            "policy-auditor.key",
            "--json",
        ],
    );
    assert!(!one.status.success(), "混合角色策略不能被单个角色开启");
    assert!(stderr(&one).contains("至少 2"), "{}", stderr(&one));

    let both = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--policy-threshold",
            "2",
            "--policy-role",
            "release",
            "--policy-role",
            "auditor",
            "--sign-key",
            "policy-auditor.key",
            "--sign-key",
            "policy-release.key",
            "--json",
        ],
    );
    assert!(both.status.success(), "{}", stderr(&both));
    let value: serde_json::Value = serde_json::from_str(&stdout(&both)).unwrap();
    assert_eq!(
        value["policy_roles"],
        serde_json::json!(["auditor", "release"])
    );
    assert_eq!(value["signer_count"], 2);

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let policy = events
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event["kind"] == "policy")
        .unwrap();
    assert_eq!(policy["payload"]["schema"], "trit-policy-v3");
    assert_eq!(
        policy["payload"]["policy_roles"],
        serde_json::json!(["auditor", "release"])
    );
    assert_eq!(policy["payload"]["signatures"].as_array().unwrap().len(), 2);
}

#[test]
fn principal_quorum_cli_requires_distinct_principals() {
    let root = temp("principal-quorum");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    for (key_file, principal, role) in [
        ("policy-first.key", "qoder:shared", "auditor"),
        ("policy-second.key", "qoder:shared", "auditor"),
        ("policy-third.key", "qoder:other", "auditor"),
    ] {
        let key = run(&root, &["key", "init", "--out", key_file, "--json"]);
        assert!(key.status.success(), "{}", stderr(&key));
        let add = run(
            &root,
            &[
                "key",
                "add",
                "--key-file",
                key_file,
                "--principal",
                principal,
                "--role",
                role,
                "--owner",
                "qoder:policy",
            ],
        );
        assert!(add.status.success(), "{}", stderr(&add));
    }

    let key_quorum = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--policy-threshold",
            "2",
            "--sign-key",
            "policy-first.key",
            "--sign-key",
            "policy-second.key",
            "--json",
        ],
    );
    assert!(
        key_quorum.status.success(),
        "旧 key 计票模式应允许同一主体的两把 key：{}",
        stderr(&key_quorum)
    );

    let same_principal = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--policy-threshold",
            "2",
            "--policy-principal-quorum",
            "--sign-key",
            "policy-first.key",
            "--sign-key",
            "policy-second.key",
            "--json",
        ],
    );
    assert!(
        !same_principal.status.success(),
        "主体计票不能被同一主体的两把 key 满足"
    );
    assert!(
        stderr(&same_principal).contains("不同主体"),
        "{}",
        stderr(&same_principal)
    );

    let distinct = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-policy",
            "--policy-threshold",
            "2",
            "--policy-principal-quorum",
            "--sign-key",
            "policy-first.key",
            "--sign-key",
            "policy-third.key",
            "--json",
        ],
    );
    assert!(distinct.status.success(), "{}", stderr(&distinct));
    let value: serde_json::Value = serde_json::from_str(&stdout(&distinct)).unwrap();
    assert_eq!(value["policy_principal_quorum"], true);
    assert_eq!(value["signer_count"], 2);

    let audit = run(&root, &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let log = run(&root, &["audit", "log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let events: serde_json::Value = serde_json::from_str(&stdout(&log)).unwrap();
    let policy = events
        .as_array()
        .unwrap()
        .iter()
        .rev()
        .find(|event| event["kind"] == "policy")
        .unwrap();
    assert_eq!(policy["payload"]["schema"], "trit-policy-v4");
    assert_eq!(policy["payload"]["policy_principal_quorum"], true);
    assert_eq!(policy["payload"]["signatures"].as_array().unwrap().len(), 2);
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
    assert_eq!(policy_event["payload"]["schema"], "trit-policy-v2");
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
