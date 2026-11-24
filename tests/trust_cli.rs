//! 签名见证的端到端账：严格策略、延迟 attest、CLI/MCP 准入与审计。

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use serde_json::{Value, json};
use trit_vcs::Hash;
use trit_vcs::journal::Event;

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
    let dir = std::env::temp_dir().join(format!("trit-vcs-trustcli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn witness_file(root: &Path) -> PathBuf {
    let dir = root.join(".tritvcs").join("witness");
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(entries.len(), 1, "应该只有一份见证：{entries:?}");
    entries.pop().unwrap()
}

fn mcp_call(root: &Path, arguments: Value) -> Value {
    let mut child = Command::new(bin())
        .arg("mcp")
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("启动 mcp 失败");
    {
        let stdin = child.stdin.as_mut().unwrap();
        for line in [
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            &json!({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": "admit", "arguments": arguments},
            })
            .to_string(),
        ] {
            writeln!(stdin, "{line}").unwrap();
        }
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(lines.len(), 2);
    lines[1]["result"].clone()
}

fn tamper_attestation_state(root: &Path) {
    let path = root.join(".tritvcs").join("journal.jsonl");
    let mut events: Vec<Event> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    for event in &mut events {
        if event.kind == "attestation" {
            event.payload["state_after"] = json!(Hash::of(b"tampered").to_hex());
        }
    }
    let mut previous = None;
    let mut remapped = std::collections::HashMap::new();
    let mut lines = Vec::new();
    for event in &mut events {
        let old_hash = event.hash.to_hex();
        if event.kind == "op_result"
            && let Some(begin_hash) = event
                .payload
                .get("begin_hash")
                .and_then(Value::as_str)
                .map(str::to_string)
            && let Some(new_begin) = remapped.get(&begin_hash)
        {
            event.payload["begin_hash"] = json!(new_begin);
        }
        event.prev = previous;
        let prev = event
            .prev
            .map(|hash| hash.to_hex())
            .unwrap_or_else(|| "-".to_string());
        let body = format!(
            "{}\n{}\n{}\n{}\n{prev}",
            event.seq,
            event.at_ms,
            event.kind,
            serde_json::to_string(&event.payload).unwrap()
        );
        event.hash = Hash::of(body.as_bytes());
        remapped.insert(old_hash, event.hash.to_hex());
        previous = Some(event.hash);
        lines.push(serde_json::to_string(event).unwrap());
    }
    fs::write(path, format!("{}\n", lines.join("\n"))).unwrap();
}

fn witness_commit(root: &Path, strict: bool) -> (String, PathBuf) {
    let init = run(root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let key = run(root, &["key", "init", "--out", "witness.key", "--json"]);
    assert!(key.status.success(), "{}", stderr(&key));
    let trust = run(
        root,
        &[
            "key",
            "add",
            "--key-file",
            "witness.key",
            "--principal",
            "qoder:auditor",
            "--role",
            "auditor",
            "--owner",
            "qoder:auditor",
        ],
    );
    assert!(trust.status.success(), "{}", stderr(&trust));
    fs::write(root.join("a.txt"), "trusted\n").unwrap();
    let add = run(root, &["add", "a.txt"]);
    assert!(add.status.success(), "{}", stderr(&add));
    if strict {
        let policy = run(
            root,
            &[
                "policy",
                "set",
                "--owner",
                "qoder:auditor",
                "--require-signed-witness",
                "--json",
            ],
        );
        assert!(policy.status.success(), "{}", stderr(&policy));
    }
    let witnessed = run(root, &["witness", "--", "cargo", "--version"]);
    assert!(witnessed.status.success(), "{}", stderr(&witnessed));
    let witness = witness_file(root);
    let witness_text = witness.to_string_lossy().to_string();
    let commit = run(
        root,
        &[
            "commit",
            "-m",
            "strict witness",
            "--owner",
            "qoder:auditor",
            "--allow-unclaimed",
            "--witness",
            &witness_text,
        ],
    );
    assert!(commit.status.success(), "{}", stderr(&commit));
    let log = run(root, &["log", "--json"]);
    assert!(log.status.success(), "{}", stderr(&log));
    let rows: Value = serde_json::from_str(&stdout(&log)).unwrap();
    (rows[0]["id"].as_str().unwrap().to_string(), witness)
}

#[test]
fn strict_policy_defers_attestation_and_cli_mcp_enforce_it() {
    let root = temp("flow");
    let (id, witness) = witness_commit(root.as_path(), true);
    let witness_text = witness.to_string_lossy().to_string();

    let missing = run(
        root.as_path(),
        &["admit", &id, "--witness", &witness_text, "--signed"],
    );
    assert!(!missing.status.success(), "未签署必须拒绝严格准入");
    let audit = run(root.as_path(), &["audit", "status", "--json"]);
    assert!(!audit.status.success(), "缺 attestation 必须判红");
    let audit_value: Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert!(
        audit_value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["kind"] == "attestation_missing"),
        "{}",
        stdout(&audit)
    );
    let mcp_missing = mcp_call(
        root.as_path(),
        json!({"commit": id, "witness_path": witness_text, "signed": true}),
    );
    assert_eq!(mcp_missing["isError"], true, "{mcp_missing}");

    let attest = run(
        root.as_path(),
        &[
            "attest",
            &id,
            "--witness",
            &witness_text,
            "--key-file",
            "witness.key",
            "--owner",
            "qoder:auditor",
            "--json",
        ],
    );
    assert!(attest.status.success(), "{}", stderr(&attest));
    let attest_value: Value = serde_json::from_str(&stdout(&attest)).unwrap();
    assert_eq!(attest_value["ok"], true);
    assert_eq!(attest_value["commit"], id);

    let log = run(root.as_path(), &["log", "--json"]);
    let rows: Value = serde_json::from_str(&stdout(&log)).unwrap();
    assert_eq!(rows[0]["id"], id, "sidecar 不得改变提交 id");
    let admitted = run(
        root.as_path(),
        &["admit", &id, "--witness", &witness_text, "--signed"],
    );
    assert!(admitted.status.success(), "{}", stderr(&admitted));

    let mcp_ok = mcp_call(
        root.as_path(),
        json!({"commit": id, "witness_path": witness_text, "signed": true}),
    );
    assert_eq!(mcp_ok["isError"], false, "{mcp_ok}");
    let admitted: Value =
        serde_json::from_str(mcp_ok["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(admitted["admitted"], true);
    assert_eq!(admitted["signed"], true);
    assert_eq!(admitted["attestation"], attest_value["attestation"]);

    for arguments in [
        json!({"commit": id.clone(), "witness_path": witness_text.clone()}),
        json!({"commit": id.clone(), "witness_path": witness_text.clone(), "signed": false}),
    ] {
        let strict_default = mcp_call(root.as_path(), arguments);
        assert_eq!(strict_default["isError"], false, "{strict_default}");
        let value: Value =
            serde_json::from_str(strict_default["content"][0]["text"].as_str().unwrap()).unwrap();
        assert_eq!(value["signed"], true);
        assert_eq!(value["attestation"], attest_value["attestation"]);
    }

    let audit = run(root.as_path(), &["audit", "status", "--json"]);
    assert!(audit.status.success(), "{}", stdout(&audit));
    let audit_value: Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert_eq!(audit_value["ok"], true);
    let policy = run(root.as_path(), &["policy", "--json"]);
    let policy_value: Value = serde_json::from_str(&stdout(&policy)).unwrap();
    assert_eq!(policy_value["require_signed_witness"], true);

    let duplicate = run(
        root.as_path(),
        &[
            "attest",
            &id,
            "--witness",
            &witness_text,
            "--key-file",
            "witness.key",
            "--owner",
            "qoder:auditor",
        ],
    );
    assert!(!duplicate.status.success(), "同一提交不得重复签署");

    tamper_attestation_state(root.as_path());
    let state_tamper = run(
        root.as_path(),
        &["admit", &id, "--witness", &witness_text, "--signed"],
    );
    assert!(
        !state_tamper.status.success(),
        "操作状态被改必须拒绝签名准入"
    );
    let audit = run(root.as_path(), &["audit", "status", "--json"]);
    assert!(!audit.status.success(), "操作状态被改必须判红");
    let audit_value: Value = serde_json::from_str(&stdout(&audit)).unwrap();
    assert!(
        audit_value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["kind"] == "attestation_state_mismatch"),
        "{}",
        stdout(&audit)
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn signed_flag_is_opt_in_without_strict_policy() {
    let root = temp("opt-in");
    let (id, witness) = witness_commit(root.as_path(), false);
    let witness_text = witness.to_string_lossy().to_string();

    let unsigned = run(root.as_path(), &["admit", &id, "--witness", &witness_text]);
    assert!(unsigned.status.success(), "{}", stderr(&unsigned));
    let signed = run(
        root.as_path(),
        &["admit", &id, "--witness", &witness_text, "--signed"],
    );
    assert!(!signed.status.success(), "--signed 必须显式要求 sidecar");

    let mcp_unsigned = mcp_call(
        root.as_path(),
        json!({"commit": id, "witness_path": witness_text}),
    );
    assert_eq!(mcp_unsigned["isError"], false, "{mcp_unsigned}");
    let value: Value =
        serde_json::from_str(mcp_unsigned["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(value["signed"], false);
    assert!(value["attestation"].is_null());

    let mcp_signed = mcp_call(
        root.as_path(),
        json!({"commit": id, "witness_path": witness_text, "signed": true}),
    );
    assert_eq!(mcp_signed["isError"], true, "{mcp_signed}");

    let malformed = mcp_call(
        root.as_path(),
        json!({"commit": id, "witness_path": witness_text, "signed": "true"}),
    );
    assert_eq!(malformed["isError"], true, "{malformed}");
    assert_eq!(malformed["_meta"]["kind"], "mcp_bad_args", "{malformed}");

    let malformed_path = mcp_call(
        root.as_path(),
        json!({"commit": id, "witness_path": "missing-witness.json", "signed": "true"}),
    );
    assert_eq!(
        malformed_path["_meta"]["kind"], "mcp_bad_args",
        "{malformed_path}"
    );

    let keys_path = root.join(".tritvcs").join("keys.json");
    let mut keys: Value = serde_json::from_str(&fs::read_to_string(&keys_path).unwrap()).unwrap();
    let entry = keys["keys"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    entry["added_at_ms"] = json!(1);
    entry["revoked_at_ms"] = json!(1);
    fs::write(keys_path, serde_json::to_vec_pretty(&keys).unwrap()).unwrap();
    let revoked = run(
        root.as_path(),
        &[
            "attest",
            &id,
            "--witness",
            &witness_text,
            "--key-file",
            "witness.key",
            "--owner",
            "qoder:auditor",
        ],
    );
    assert!(!revoked.status.success(), "吊销后不得签署");
    assert!(stderr(&revoked).contains("吊销"), "{}", stderr(&revoked));
    let _ = fs::remove_dir_all(&root);
}
