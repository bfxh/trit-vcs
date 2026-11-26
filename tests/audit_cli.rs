//! `trit-vcs audit` 的端到端读数：状态对账、日志查看、故障必须非零。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use trit_vcs::journal::Event;
use trit_vcs::{Commit, Hash, Hlc, Repo};

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

fn rewrite_policy_event(root: &Path, mutate: impl FnOnce(&mut serde_json::Value)) {
    let path = root.join(".tritvcs").join("journal.jsonl");
    let mut events: Vec<Event> = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let policy = events
        .iter_mut()
        .find(|event| event.kind == "policy")
        .expect("测试应先写入 policy 事件");
    mutate(&mut policy.payload);
    let mut previous = None;
    let mut remapped = std::collections::HashMap::new();
    let mut lines = Vec::new();
    for event in &mut events {
        let old_hash = event.hash.to_hex();
        if event.kind == "op_result"
            && let Some(begin_hash) = event
                .payload
                .get("begin_hash")
                .and_then(serde_json::Value::as_str)
                .map(str::to_string)
            && let Some(new_begin) = remapped.get(&begin_hash)
        {
            event.payload["begin_hash"] = serde_json::json!(new_begin);
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

#[test]
fn policy_event_accepts_legacy_shape_but_rejects_non_boolean_signed_witness() {
    let root = temp("policy-compat");
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    let set = run(
        &root,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:policy",
            "--require-signed-witness",
            "--json",
        ],
    );
    assert!(set.status.success(), "{}", stderr(&set));

    fs::write(root.join("a.txt"), b"policy\n").unwrap();
    assert!(run(&root, &["add", "a.txt"]).status.success());
    assert!(
        run(&root, &["witness", "--", "cargo", "--version"])
            .status
            .success()
    );
    let witness = fs::read_dir(root.join(".tritvcs/witness"))
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let witness_text = witness.to_string_lossy().to_string();
    let commit = run(
        &root,
        &[
            "commit",
            "-m",
            "policy replay",
            "--owner",
            "qoder:policy",
            "--allow-unclaimed",
            "--witness",
            &witness_text,
        ],
    );
    assert!(commit.status.success(), "{}", stderr(&commit));

    rewrite_policy_event(&root, |payload| {
        let payload = payload.as_object_mut().unwrap();
        payload.remove("require_signed_witness");
        payload.remove("schema");
    });
    let legacy = run(&root, &["audit", "status", "--json"]);
    assert!(legacy.status.success(), "{}", stdout(&legacy));
    let legacy_value: serde_json::Value = serde_json::from_str(&stdout(&legacy)).unwrap();
    assert_eq!(legacy_value["ok"], true);

    rewrite_policy_event(&root, |payload| {
        payload.as_object_mut().unwrap().insert(
            "require_signed_witness".to_string(),
            serde_json::json!("yes"),
        );
    });
    let malformed = run(&root, &["audit", "status", "--json"]);
    assert!(!malformed.status.success(), "非布尔策略值必须判红");
    let value: serde_json::Value = serde_json::from_str(&stdout(&malformed)).unwrap();
    let kinds: Vec<_> = value["issues"]
        .as_array()
        .unwrap()
        .iter()
        .map(|issue| issue["kind"].as_str().unwrap())
        .collect();
    assert!(kinds.contains(&"policy_bad"), "{}", stdout(&malformed));
    assert!(
        kinds.contains(&"attestation_missing"),
        "{}",
        stdout(&malformed)
    );

    rewrite_policy_event(&root, |payload| {
        let payload = payload.as_object_mut().unwrap();
        payload.remove("require_signed_witness");
        payload.insert("schema".to_string(), serde_json::json!("trit-policy-v1"));
    });
    let missing = run(&root, &["audit", "status", "--json"]);
    assert!(!missing.status.success(), "新版策略缺字段必须 fail-closed");
    let value: serde_json::Value = serde_json::from_str(&stdout(&missing)).unwrap();
    assert!(
        value["issues"].as_array().unwrap().iter().any(|issue| {
            issue["kind"] == "policy_bad"
                && issue["detail"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("require_signed_witness")
        }),
        "{}",
        stdout(&missing)
    );
    assert!(
        value["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|issue| issue["kind"] == "attestation_missing"),
        "{}",
        stdout(&missing)
    );

    let mut repo = Repo::open(&root).unwrap();
    let commit = Commit::new(
        Hash::of(b"unwitnessed-tree"),
        "qoder:policy",
        "policy replay",
        Hlc::zero(),
    );
    let (unwitnessed_id, _) = repo.store().put_chunk(&commit.encode().unwrap()).unwrap();
    repo.append_audit(
        "commit",
        serde_json::json!({"id": unwitnessed_id.to_hex()}),
        2_000,
    )
    .unwrap();
    drop(repo);
    let unwitnessed = run(&root, &["audit", "status", "--json"]);
    assert!(
        !unwitnessed.status.success(),
        "严格策略下的无 witness 提交必须判红"
    );
    let value: serde_json::Value = serde_json::from_str(&stdout(&unwitnessed)).unwrap();
    assert!(
        value["issues"].as_array().unwrap().iter().any(|issue| {
            issue["kind"] == "attestation_missing"
                && issue["detail"]
                    .as_str()
                    .unwrap_or_default()
                    .contains("缺 witness")
        }),
        "{}",
        stdout(&unwitnessed)
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn force_checkout_records_bypassed_dirty_state() {
    let root = temp("checkout-force");
    seed_commit(&root);
    let rows: serde_json::Value =
        serde_json::from_str(&stdout(&run(&root, &["log", "--json"]))).unwrap();
    let id = rows[0]["id"].as_str().unwrap().to_string();

    // seed_commit 为导出认领快照留下的 claims.json 是未跟踪文件；先清掉，只留一个脏文件。
    let _ = fs::remove_file(root.join("claims.json"));
    fs::write(root.join("a.txt"), "dirty\n").unwrap();
    let checkout = run(&root, &["checkout", &id, "--force"]);
    assert!(checkout.status.success(), "{}", stderr(&checkout));
    assert!(
        stdout(&checkout).contains("放行 1 个未提交改动"),
        "强制检出要在读数里点名：{}",
        stdout(&checkout)
    );

    let events: serde_json::Value = serde_json::from_str(&stdout(&run(
        &root,
        &["audit", "log", "checkout", "--json"],
    )))
    .unwrap();
    let events = events.as_array().unwrap();
    assert_eq!(events.len(), 1, "{events:?}");
    let event = &events[0];
    assert_eq!(event["payload"]["schema"], "trit-checkout-v1");
    assert_eq!(event["payload"]["force"], true);
    assert_eq!(event["payload"]["reason"], "dirty_worktree");
    assert_eq!(event["payload"]["commit"], id);
    assert_eq!(event["payload"]["dirty"], 1);
    assert_eq!(
        event["payload"]["dirty_sample"],
        serde_json::json!(["a.txt"])
    );
    assert_eq!(
        event["payload"]["state_before"], event["payload"]["state_after"],
        "检出不改 HEAD/refs/index，前后状态必须相同"
    );

    let status: serde_json::Value =
        serde_json::from_str(&stdout(&run(&root, &["audit", "status", "--json"]))).unwrap();
    assert_eq!(status["ok"], true, "{status}");
    assert_eq!(status["level"], "L2");
    assert_eq!(status["open_ops"], 0);

    fs::write(root.join("a.txt"), "dirty again\n").unwrap();
    let refused = run(&root, &["checkout", &id]);
    assert!(!refused.status.success(), "不带 --force 必须拒绝覆盖");
    assert!(
        stderr(&refused).contains("worktree_dirty"),
        "{}",
        stderr(&refused)
    );
    let after: serde_json::Value = serde_json::from_str(&stdout(&run(
        &root,
        &["audit", "log", "checkout", "--json"],
    )))
    .unwrap();
    assert_eq!(
        after.as_array().unwrap().len(),
        1,
        "被拒的检出不能伪造成功事件"
    );
    let _ = fs::remove_dir_all(&root);
}
