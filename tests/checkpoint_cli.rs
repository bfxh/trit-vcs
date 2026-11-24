//! `audit checkpoint` 的端到端账：前缀高度、Merkle 根、双检查点链和审计复验。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::json;
use trit_vcs::checkpoint::checkpoint_statement;
use trit_vcs::hash::Hash;
use trit_vcs::repo::Repo;
use trit_vcs::signing::KeyFile;

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

fn trust_auditor(root: &Path) -> String {
    let key_init = run(root, &["key", "init", "--out", "auditor.key", "--json"]);
    assert!(key_init.status.success(), "{}", stderr(&key_init));
    let key: serde_json::Value = serde_json::from_str(&stdout(&key_init)).unwrap();
    let key_id = key["key_id"].as_str().unwrap().to_string();
    let trust = run(
        root,
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
    key_id
}

fn checkpoint(root: &Path) -> serde_json::Value {
    let output = run(
        root,
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
    assert!(output.status.success(), "{}", stderr(&output));
    serde_json::from_str(&stdout(&output)).unwrap()
}

fn add_file(root: &Path, name: &str, body: &str) {
    fs::write(root.join(name), body).unwrap();
    let add = run(root, &["add", name]);
    assert!(add.status.success(), "{}", stderr(&add));
}

#[test]
fn consistency_cli_generates_verifies_and_rejects_tampering() {
    let root = temp("consistency");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    trust_auditor(&root);
    add_file(&root, "a.txt", "alpha");
    let first = checkpoint(&root);
    add_file(&root, "b.txt", "beta");
    let second = checkpoint(&root);
    let from = first["height"].as_u64().unwrap().to_string();
    let to = second["height"].as_u64().unwrap().to_string();

    let generated = run(
        &root,
        &[
            "audit",
            "consistency",
            "--from",
            &from,
            "--to",
            &to,
            "--out",
            "consistency.json",
            "--json",
        ],
    );
    assert!(generated.status.success(), "{}", stderr(&generated));
    let value: serde_json::Value = serde_json::from_str(&stdout(&generated)).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["old_root"], first["merkle_root"]);
    assert_eq!(value["new_root"], second["merkle_root"]);

    let verified = run(
        &root,
        &[
            "audit",
            "verify-consistency",
            "--from",
            &from,
            "--to",
            &to,
            "--proof",
            "consistency.json",
            "--json",
        ],
    );
    assert!(verified.status.success(), "{}", stderr(&verified));

    let mut proof: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join("consistency.json")).unwrap()).unwrap();
    proof["siblings"][0]["hash"] = serde_json::json!("00".repeat(32));
    fs::write(
        root.join("tampered.json"),
        serde_json::to_vec(&proof).unwrap(),
    )
    .unwrap();
    let rejected = run(
        &root,
        &[
            "audit",
            "verify-consistency",
            "--from",
            &from,
            "--to",
            &to,
            "--proof",
            "tampered.json",
            "--json",
        ],
    );
    assert!(!rejected.status.success());
    let failure: serde_json::Value = serde_json::from_str(&stdout(&rejected)).unwrap();
    assert_eq!(failure["error"]["kind"], "audit_consistency_failed");
}

#[test]
fn file_anchor_checks_extension_and_detects_deleted_anchored_tail() {
    let root = temp("anchor");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    trust_auditor(&root);
    add_file(&root, "a.txt", "alpha");
    let first = checkpoint(&root);
    add_file(&root, "b.txt", "beta");
    let second = checkpoint(&root);
    let third = checkpoint(&root);

    for (name, value) in [
        ("anchor-second.json", &second),
        ("anchor-third.json", &third),
    ] {
        let seq = value["height"].as_u64().unwrap().to_string();
        let exported = run(
            &root,
            &[
                "audit",
                "anchor",
                "--checkpoint",
                &seq,
                "--out",
                name,
                "--json",
            ],
        );
        assert!(exported.status.success(), "{}", stderr(&exported));
    }

    for name in ["anchor-second.json", "anchor-third.json"] {
        let verified = run(
            &root,
            &["audit", "verify-anchor", "--anchor", name, "--json"],
        );
        assert!(verified.status.success(), "{}", stderr(&verified));
        let audit = run(&root, &["audit", "verify", "--anchor", name, "--json"]);
        assert!(audit.status.success(), "{}", stderr(&audit));
        let value: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
        assert_eq!(value["ok"], true);
        assert_eq!(value["anchor"]["ok"], true);
    }

    let journal = root.join(".tritvcs/journal.jsonl");
    let full = fs::read_to_string(&journal).unwrap();
    let keep_second = second["height"].as_u64().unwrap() as usize + 2;
    let truncated = full
        .lines()
        .take(keep_second)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&journal, truncated).unwrap();

    let old_anchor = run(
        &root,
        &[
            "audit",
            "verify",
            "--anchor",
            "anchor-second.json",
            "--json",
        ],
    );
    assert!(old_anchor.status.success(), "{}", stderr(&old_anchor));
    let new_anchor = run(
        &root,
        &["audit", "verify", "--anchor", "anchor-third.json", "--json"],
    );
    assert!(!new_anchor.status.success());
    let failure: serde_json::Value = serde_json::from_str(&stdout(&new_anchor)).unwrap();
    assert_eq!(failure["issues"][0]["kind"], "anchor_ahead");

    let keep_before_third = third["height"].as_u64().unwrap() as usize;
    let truncated = full
        .lines()
        .take(keep_before_third)
        .collect::<Vec<_>>()
        .join("\n")
        + "\n";
    fs::write(&journal, truncated).unwrap();
    let missing_checkpoint = run(
        &root,
        &[
            "audit",
            "verify-anchor",
            "--anchor",
            "anchor-third.json",
            "--json",
        ],
    );
    assert!(!missing_checkpoint.status.success());
    let failure: serde_json::Value = serde_json::from_str(&stdout(&missing_checkpoint)).unwrap();
    assert_eq!(failure["error"]["kind"], "anchor_ahead");
    assert!(first["height"].as_u64().unwrap() < second["height"].as_u64().unwrap());
}

#[test]
fn file_anchor_rejects_envelope_tampering_and_refuses_overwrite() {
    let root = temp("anchor-tamper");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    trust_auditor(&root);
    add_file(&root, "a.txt", "alpha");
    let value = checkpoint(&root);
    let seq = value["height"].as_u64().unwrap().to_string();
    let exported = run(
        &root,
        &[
            "audit",
            "anchor",
            "--checkpoint",
            &seq,
            "--out",
            "anchor.json",
            "--json",
        ],
    );
    assert!(exported.status.success(), "{}", stderr(&exported));
    let original_anchor = fs::read(root.join("anchor.json")).unwrap();
    fs::write(root.join("anchor.json"), b"do-not-clobber\n").unwrap();

    let overwrite = run(
        &root,
        &[
            "audit",
            "anchor",
            "--checkpoint",
            &seq,
            "--out",
            "anchor.json",
            "--json",
        ],
    );
    assert!(!overwrite.status.success());
    assert_eq!(
        fs::read(root.join("anchor.json")).unwrap(),
        b"do-not-clobber\n"
    );
    let failure: serde_json::Value = serde_json::from_str(&stdout(&overwrite)).unwrap();
    assert_eq!(failure["error"]["kind"], "cli_local_io");

    let mut anchor: serde_json::Value = serde_json::from_slice(&original_anchor).unwrap();
    anchor["event"]["payload"]["merkle_root"] = serde_json::json!("00".repeat(32));
    fs::write(
        root.join("tampered.json"),
        serde_json::to_vec(&anchor).unwrap(),
    )
    .unwrap();
    let rejected = run(
        &root,
        &[
            "audit",
            "verify-anchor",
            "--anchor",
            "tampered.json",
            "--json",
        ],
    );
    assert!(!rejected.status.success());
    let failure: serde_json::Value = serde_json::from_str(&stdout(&rejected)).unwrap();
    assert_eq!(failure["error"]["kind"], "anchor_bad");
}

#[test]
fn anchor_export_rejects_validly_signed_wrong_prefix() {
    let root = temp("anchor-wrong-prefix");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    trust_auditor(&root);
    add_file(&root, "a.txt", "alpha");

    let mut repo = Repo::open(&root).unwrap();
    let key = KeyFile::load(&root.join("auditor.key")).unwrap();
    let events = repo.journal().events();
    let height = events.len();
    let head = events.last().map(|event| event.hash);
    let previous = events
        .iter()
        .rev()
        .find(|event| event.kind == "checkpoint")
        .map(|event| event.hash);
    let at_ms = events.last().map_or(1, |event| event.at_ms + 1);
    let wrong_root = Hash::of(b"wrong-prefix-root");
    let statement = checkpoint_statement(height, head, wrong_root, previous, at_ms, &key.key_id);
    let signature = key.sign_hex(&statement).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.append_audit(
        "checkpoint",
        json!({
            "height": height,
            "head": head.map(|hash| hash.to_hex()),
            "merkle_root": wrong_root.to_hex(),
            "previous": previous.map(|hash| hash.to_hex()),
            "key_id": key.key_id,
            "algorithm": "ed25519",
            "signature": signature,
            "signed_at_ms": at_ms,
            "session": "qoder:auditor",
            "state_before": digest,
            "state_after": digest,
        }),
        at_ms,
    )
    .unwrap();
    drop(repo);

    let seq = height.to_string();
    let exported = run(
        &root,
        &[
            "audit",
            "anchor",
            "--checkpoint",
            &seq,
            "--out",
            "invalid-anchor.json",
            "--json",
        ],
    );
    assert!(!exported.status.success());
    let failure: serde_json::Value = serde_json::from_str(&stdout(&exported)).unwrap();
    assert_eq!(failure["error"]["kind"], "anchor_mismatch");
    assert!(!root.join("invalid-anchor.json").exists());
}

#[test]
fn proof_and_anchor_cli_reject_malformed_json() {
    let root = temp("malformed-json");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    trust_auditor(&root);
    let first = checkpoint(&root);
    let second = checkpoint(&root);
    let from = first["height"].as_u64().unwrap().to_string();
    let to = second["height"].as_u64().unwrap().to_string();
    fs::write(root.join("bad-proof.json"), b"{not-json").unwrap();
    fs::write(root.join("bad-anchor.json"), b"{not-json").unwrap();

    let proof = run(
        &root,
        &[
            "audit",
            "verify-consistency",
            "--from",
            &from,
            "--to",
            &to,
            "--proof",
            "bad-proof.json",
            "--json",
        ],
    );
    assert!(!proof.status.success());
    let failure: serde_json::Value = serde_json::from_str(&stdout(&proof)).unwrap();
    assert_eq!(failure["error"]["kind"], "audit_proof_bad");

    let anchor = run(
        &root,
        &[
            "audit",
            "verify-anchor",
            "--anchor",
            "bad-anchor.json",
            "--json",
        ],
    );
    assert!(!anchor.status.success());
    let failure: serde_json::Value = serde_json::from_str(&stdout(&anchor)).unwrap();
    assert_eq!(failure["error"]["kind"], "anchor_bad");
}
