//! 命令行端到端：中央仓里的认领账本（跨仓共享、冲突拒绝、导出后可直接用于 --claims）。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{Value, json};
use trit_vcs::hash::Hash;
use trit_vcs::repo::Repo;

#[path = "claims_cli/flow.rs"]
mod flow;
#[path = "claims_cli/tamper.rs"]
mod tamper;

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
        std::env::temp_dir().join(format!("trit-vcs-claimscli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn init(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    let out = run(dir, &["init"]);
    assert!(out.status.success(), "{}", stderr(&out));
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn trust_key(root: &Path, central: &Path, name: &str, principal: &str, role: &str) -> String {
    let key_path = root.join(name);
    let key_text = path_text(&key_path);
    let generated = run(root, &["key", "init", "--out", &key_text, "--json"]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    let value: Value = serde_json::from_str(&stdout(&generated)).unwrap();
    let key_id = value["key_id"].as_str().unwrap().to_string();
    let central_text = path_text(central);
    let added = run(
        root,
        &[
            "key",
            "add",
            "--key-file",
            &key_text,
            "--principal",
            principal,
            "--role",
            role,
            "--owner",
            "qoder:key-admin",
            "--repo",
            &central_text,
            "--json",
        ],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    key_id
}

fn audit_report(central: &Path) -> Value {
    let output = run(central, &["audit", "--json"]);
    serde_json::from_str(&stdout(&output)).unwrap()
}

fn audit(central: &Path) -> Value {
    let report = audit_report(central);
    assert!(report["ok"].as_bool().unwrap(), "{report}");
    report
}

fn has_issue(report: &Value, kind: &str) -> bool {
    report["issues"]
        .as_array()
        .is_some_and(|issues| issues.iter().any(|issue| issue["kind"] == kind))
}

fn journal_events(central: &Path) -> Vec<Value> {
    let text = fs::read_to_string(central.join(".tritvcs").join("journal.jsonl")).unwrap();
    text.lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn event_index(events: &[Value], kind: &str) -> usize {
    events
        .iter()
        .position(|event| event["kind"] == kind)
        .unwrap_or_else(|| panic!("缺 {kind} 事件"))
}

fn value_hash(value: &Value) -> Hash {
    let bytes: [u8; 32] = value
        .as_array()
        .unwrap()
        .iter()
        .map(|byte| byte.as_u64().unwrap() as u8)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    Hash::from_bytes(bytes)
}

fn event_hash(event: &Value, index: usize, previous: Option<Hash>) -> Hash {
    let previous_hex = previous
        .map(|hash| hash.to_hex())
        .unwrap_or_else(|| "-".to_string());
    let body = format!(
        "{index}\n{}\n{}\n{}\n{previous_hex}",
        event["at_ms"].as_u64().unwrap(),
        event["kind"].as_str().unwrap(),
        serde_json::to_string(&event["payload"]).unwrap(),
    );
    Hash::of(body.as_bytes())
}

fn rechain(events: &mut [Value]) {
    let mut previous: Option<Hash> = None;
    for (index, event) in events.iter_mut().enumerate() {
        event["seq"] = json!(index);
        let hash = event_hash(event, index, previous);
        event["prev"] = previous
            .map(|previous| json!(previous.as_bytes().to_vec()))
            .unwrap_or(Value::Null);
        event["hash"] = json!(hash.as_bytes().to_vec());
        if let Some(object) = event.as_object_mut() {
            object.remove("previous");
        }
        previous = Some(hash);
    }
}

fn rewrite_journal(central: &Path, baseline: &Path, mutate: impl FnOnce(&mut Vec<Value>)) {
    let text = fs::read_to_string(baseline).unwrap();
    let mut events: Vec<Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    mutate(&mut events);
    rechain(&mut events);
    let mut output = String::new();
    for event in &events {
        output.push_str(&serde_json::to_string(event).unwrap());
        output.push('\n');
    }
    fs::write(central.join(".tritvcs").join("journal.jsonl"), output).unwrap();
}

fn sync_latest_state(central: &Path, events: &mut [Value]) {
    let digest = Repo::open(central)
        .unwrap()
        .state_digest()
        .unwrap()
        .to_hex();
    let last = events.last_mut().unwrap();
    last["payload"]["state_after"] = json!(digest);
}

#[test]
fn shared_claim_ledger_gates_two_worktrees() {
    let root = temp("flow");
    let central = root.join("central");
    let central_text = central.to_string_lossy().to_string();
    let ledger = central
        .join(".tritvcs")
        .join("claims.json")
        .to_string_lossy()
        .to_string();

    // 1) 第一个工作树在中央仓认领，账本文件自己建起来。
    let added = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "c1",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
            "--ttl",
            "900",
            "--json",
        ],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    let value: serde_json::Value = serde_json::from_str(&stdout(&added)).unwrap();
    assert_eq!(value["claim"]["owner"], "qoder:a");
    assert_eq!(value["claim"]["paths"], serde_json::json!(["a.rs"]));
    assert!(Path::new(&ledger).is_file(), "账本要落在中央仓里");

    let listed = run(
        &root,
        &["claims", "list", "--central", &central_text, "--json"],
    );
    let listed_value: serde_json::Value = serde_json::from_str(&stdout(&listed)).unwrap();
    assert_eq!(listed_value["claims"].as_array().unwrap().len(), 1);
    assert_eq!(listed_value["claims"][0]["owner"], "qoder:a");

    // 2) 另一个 owner 碰同一路径：拒绝并点名（不是静默覆盖）。
    let blocked = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "c2",
            "--owner",
            "zcode:z",
            "--path",
            "a.rs",
        ],
    );
    assert!(!blocked.status.success(), "相交认领必须判失败");
    assert!(stderr(&blocked).contains("FAIL"), "{}", stderr(&blocked));
    assert!(
        stderr(&blocked).contains("claims_conflict"),
        "要带机器可读的 kind：{}",
        stderr(&blocked)
    );
    assert!(
        stderr(&blocked).contains("zcode:z") || stderr(&blocked).contains("qoder:a"),
        "要把挡着的人点名：{}",
        stderr(&blocked)
    );

    // 3) 同一个 id 换 owner：拒绝。
    let stolen = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "c1",
            "--owner",
            "zcode:z",
            "--path",
            "b.rs",
        ],
    );
    assert!(!stolen.status.success(), "同一 id 不能被别人接管");
    assert!(
        stderr(&stolen).contains("claims_id_taken"),
        "{}",
        stderr(&stolen)
    );

    // 4) 只有持有者能释放。
    let wrong_release = run(
        &root,
        &[
            "claims",
            "release",
            "--central",
            &central_text,
            "--id",
            "c1",
            "--owner",
            "zcode:z",
        ],
    );
    assert!(!wrong_release.status.success());
    assert!(
        stderr(&wrong_release).contains("claims_owner_mismatch"),
        "{}",
        stderr(&wrong_release)
    );

    // 5) 导出的快照与账本同格式：A 仓用它能过认领门，B 仓拿它提交别人的路径会被拒。
    let snapshot = root.join("claims-snapshot.json");
    let exported = run(
        &root,
        &[
            "claims",
            "export",
            "--central",
            &central_text,
            "--out",
            snapshot.to_str().unwrap(),
        ],
    );
    assert!(exported.status.success(), "{}", stderr(&exported));
    let parsed: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&snapshot).unwrap()).unwrap();
    assert_eq!(parsed.as_array().unwrap().len(), 1);

    let repo_a = root.join("repo-a");
    init(&repo_a);
    fs::write(repo_a.join("a.rs"), b"a\n").unwrap();
    assert!(run(&repo_a, &["add", "a.rs"]).status.success());
    let committed = run(
        &repo_a,
        &[
            "commit",
            "-m",
            "with shared claim",
            "--owner",
            "qoder:a",
            "--claims",
            ledger.as_str(),
        ],
    );
    assert!(
        committed.status.success(),
        "共享账本里的在效认领应当能过闸：{}",
        stderr(&committed)
    );

    let repo_b = root.join("repo-b");
    init(&repo_b);
    fs::write(repo_b.join("a.rs"), b"b\n").unwrap();
    assert!(run(&repo_b, &["add", "a.rs"]).status.success());
    let conflicting = run(
        &repo_b,
        &[
            "commit",
            "-m",
            "someone else",
            "--owner",
            "zcode:z",
            "--claims",
            ledger.as_str(),
        ],
    );
    assert!(!conflicting.status.success(), "别人的在效认领必须挡住提交");
    assert!(
        stderr(&conflicting).contains("claim_conflict"),
        "{}",
        stderr(&conflicting)
    );

    // 6) 持有者释放后，账本里就没有这条了。
    let released = run(
        &repo_a,
        &[
            "claims",
            "release",
            "--central",
            &central_text,
            "--id",
            "c1",
            "--owner",
            "qoder:a",
        ],
    );
    assert!(released.status.success(), "{}", stderr(&released));
    let empty = run(
        &root,
        &["claims", "list", "--central", &central_text, "--json"],
    );
    let empty_value: serde_json::Value = serde_json::from_str(&stdout(&empty)).unwrap();
    assert!(empty_value["claims"].as_array().unwrap().is_empty());

    // 7) 改动进中央仓哈希链（不是只改一个 JSON 文件）。
    let journal = fs::read_to_string(central.join(".tritvcs").join("journal.jsonl")).unwrap();
    assert!(journal.contains("claim_add"), "认领要进审计链");
    assert!(journal.contains("claim_release"), "释放也要进审计链");
    let _ = fs::remove_dir_all(&root);
}
