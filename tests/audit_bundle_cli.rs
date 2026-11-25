//! TVAB 端到端：无仓库离线验证，以及对象、日志、状态、外锚和容器边界篡改。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::Value;
use trit_vcs::audit_bundle::{Manifest, PieceRef, SCHEMA};
use trit_vcs::hash::Hash;
use trit_vcs::journal::Event;
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

fn json(output: &Output) -> Value {
    serde_json::from_str(&stdout(output))
        .unwrap_or_else(|_| panic!("不是 JSON：{}", stdout(output)))
}

fn failure_kind(output: &Output) -> String {
    assert!(!output.status.success(), "应失败：{}", stdout(output));
    let value = json(output);
    value["error"]["kind"]
        .as_str()
        .or_else(|| value["kind"].as_str())
        .unwrap_or_else(|| panic!("失败 JSON 没有 kind：{value}"))
        .to_string()
}

struct TestDir {
    path: PathBuf,
}

impl TestDir {
    fn new(name: &str) -> Self {
        for _ in 0..8 {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).unwrap();
            let path = std::env::temp_dir().join(format!(
                "trit-vcs-auditbundlecli-{name}-{}-{}",
                std::process::id(),
                Hash::of(&random).to_hex()
            ));
            match fs::create_dir(&path) {
                Ok(()) => return Self { path },
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("创建测试目录失败：{err}"),
            }
        }
        panic!("无法创建唯一测试目录");
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_dir_all(&self.path) {
            if std::thread::panicking() {
                eprintln!("清理测试目录 {} 失败：{err}", self.path.display());
            } else {
                panic!("清理测试目录 {} 失败：{err}", self.path.display());
            }
        }
    }
}

struct Fixture {
    root: PathBuf,
    public: String,
    anchor: PathBuf,
    bundle: PathBuf,
    _dir: TestDir,
}

fn fixture(name: &str) -> Fixture {
    let dir = TestDir::new(name);
    let root = dir.path.clone();
    let init = run(&root, &["init"]);
    assert!(init.status.success(), "{}", stderr(&init));
    fs::write(root.join("a.txt"), "audit bundle\n").unwrap();
    let add = run(&root, &["add", "a.txt"]);
    assert!(add.status.success(), "{}", stderr(&add));

    let auditor = run(&root, &["key", "init", "--out", "auditor.key", "--json"]);
    assert!(auditor.status.success(), "{}", stderr(&auditor));
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
    let commit = run(
        &root,
        &[
            "commit",
            "-m",
            "seed",
            "--owner",
            "audit:cli",
            "--allow-unclaimed",
        ],
    );
    assert!(commit.status.success(), "{}", stderr(&commit));
    let policy = run(
        &root,
        &["policy", "set", "--owner", "audit:cli", "--require-witness"],
    );
    assert!(policy.status.success(), "{}", stderr(&policy));
    let checkpoint = run(
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
    assert!(checkpoint.status.success(), "{}", stderr(&checkpoint));
    let checkpoint = json(&checkpoint);
    let seq = checkpoint["height"].as_u64().unwrap().to_string();

    let external = run(&root, &["key", "init", "--out", "external.key", "--json"]);
    assert!(external.status.success(), "{}", stderr(&external));
    let public = json(&external)["public"].as_str().unwrap().to_string();
    let anchor = root.join("external-anchor.json");
    let anchored = run(
        &root,
        &[
            "audit",
            "external-anchor",
            "--checkpoint",
            &seq,
            "--key-file",
            "external.key",
            "--anchor-public-key",
            &public,
            "--out",
            anchor.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(anchored.status.success(), "{}", stderr(&anchored));
    let bundle = root.join("repo.audit.tvab");
    Fixture {
        root,
        public,
        anchor,
        bundle,
        _dir: dir,
    }
}

fn export(fixture: &Fixture) -> Output {
    run(
        &fixture.root,
        &[
            "audit",
            "bundle",
            "--out",
            fixture.bundle.to_str().unwrap(),
            "--anchor",
            fixture.anchor.to_str().unwrap(),
            "--anchor-public-key",
            &fixture.public,
            "--json",
        ],
    )
}

fn verify(path: &Path, cwd: &Path, public: &str) -> Output {
    run(
        cwd,
        &[
            "audit",
            "verify-bundle",
            path.to_str().unwrap(),
            "--anchor-public-key",
            public,
            "--offline",
            "--json",
        ],
    )
}

#[test]
fn bundle_verifies_offline_without_opening_a_repository() {
    let fixture = fixture("happy");
    let exported = export(&fixture);
    assert!(exported.status.success(), "{}", stderr(&exported));
    let value = json(&exported);
    assert_eq!(value["ok"], true);
    assert!(value["objects"].as_u64().unwrap() > 0);
    assert_eq!(value["package_id"].as_str().unwrap().len(), 64);
    assert_eq!(
        value["events"],
        value["anchor"]["height"].as_u64().unwrap() + 2
    );

    let empty = TestDir::new("verify-empty");
    let verified = verify(&fixture.bundle, &empty.path, &fixture.public);
    assert!(verified.status.success(), "{}", stderr(&verified));
    let value = json(&verified);
    assert_eq!(value["ok"], true);
    assert_eq!(value["offline"], true);
    assert_eq!(value["audit"]["ok"], true);
    assert_eq!(value["audit"]["level"], "L2");
    assert!(!empty.path.join(".tritvcs").exists(), "验包不应初始化仓库");
    assert_eq!(
        value["bytes"].as_u64().unwrap(),
        fs::metadata(&fixture.bundle).unwrap().len()
    );
    assert!(fs::read_dir(&fixture.root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tvab-")
    }));
}

#[test]
fn wrong_external_public_key_is_rejected() {
    let fixture = fixture("wrong-key");
    assert!(export(&fixture).status.success());
    let wrong = KeyFile::generate().unwrap().public;
    let verified = verify(&fixture.bundle, &fixture.root, &wrong);
    assert_eq!(failure_kind(&verified), "anchor_untrusted");
}

#[test]
fn object_and_journal_tampering_are_rejected_by_container_hashes() {
    let fixture = fixture("hash-tamper");
    assert!(export(&fixture).status.success());

    let object = unpack(&fixture.bundle);
    let index = object
        .1
        .iter()
        .position(|(piece, _)| piece.name.starts_with("object:"))
        .unwrap();
    let mut corrupt_object = object.clone();
    corrupt_object.1[index].1[0] ^= 0xff;
    let object_path = fixture.root.join("bad-object.tvab");
    pack(&object_path, &corrupt_object);
    assert_eq!(
        failure_kind(&verify(&object_path, &fixture.root, &fixture.public)),
        "audit_bundle_hash_mismatch"
    );

    let mut corrupt_journal = object;
    let journal = corrupt_journal
        .1
        .iter_mut()
        .find(|(piece, _)| piece.name == "journal.jsonl")
        .unwrap();
    journal.1[0] ^= 0xff;
    let journal_path = fixture.root.join("bad-journal.tvab");
    pack(&journal_path, &corrupt_journal);
    assert_eq!(
        failure_kind(&verify(&journal_path, &fixture.root, &fixture.public)),
        "audit_bundle_hash_mismatch"
    );
}

#[test]
fn state_tampering_is_caught_even_when_piece_hash_is_recomputed() {
    let fixture = fixture("state-tamper");
    assert!(export(&fixture).status.success());
    let mut decoded = unpack(&fixture.bundle);
    let original = decoded.clone();
    let index = decoded
        .0
        .pieces
        .iter()
        .position(|piece| piece.name == "policy.json")
        .unwrap();
    decoded.1[index].1.push(b' ');
    decoded.1[index].0.hash = Hash::of(&decoded.1[index].1).to_hex();
    decoded.1[index].0.bytes = decoded.1[index].1.len() as u64;
    decoded.0.pieces[index] = decoded.1[index].0.clone();
    let path = fixture.root.join("bad-state.tvab");
    pack(&path, &decoded);
    let verified = verify(&path, &fixture.root, &fixture.public);
    assert_eq!(
        failure_kind(&verified),
        "audit_bundle_incomplete",
        "{}\n{}",
        stdout(&verified),
        stderr(&verified)
    );

    let mut wrong_digest = original;
    wrong_digest.0.state_digest = Hash::of(b"wrong-manifest-state").to_hex();
    let digest_path = fixture.root.join("bad-digest.tvab");
    pack(&digest_path, &wrong_digest);
    assert_eq!(
        failure_kind(&verify(&digest_path, &fixture.root, &fixture.public)),
        "audit_bundle_incomplete"
    );
}

#[test]
fn missing_object_and_bad_anchor_signature_are_rejected() {
    let fixture = fixture("semantic-tamper");
    assert!(export(&fixture).status.success());

    let decoded = unpack(&fixture.bundle);
    let mut missing = decoded.clone();
    let index = missing
        .0
        .pieces
        .iter()
        .position(|piece| piece.name.starts_with("object:"))
        .unwrap();
    missing.0.pieces.remove(index);
    missing.1.remove(index);
    let missing_path = fixture.root.join("missing-object.tvab");
    pack(&missing_path, &missing);
    let verified = verify(&missing_path, &fixture.root, &fixture.public);
    assert_eq!(
        failure_kind(&verified),
        "audit_bundle_incomplete",
        "{}\n{}",
        stdout(&verified),
        stderr(&verified)
    );

    let mut bad_anchor = decoded;
    bad_anchor.0.anchor.signature = "00".repeat(64);
    let anchor_path = fixture.root.join("bad-anchor.tvab");
    pack(&anchor_path, &bad_anchor);
    assert_eq!(
        failure_kind(&verify(&anchor_path, &fixture.root, &fixture.public)),
        "anchor_signature_invalid"
    );
}

#[test]
fn recomputed_checkpoint_completion_tail_is_still_checked() {
    let fixture = fixture("tail-tamper");
    assert!(export(&fixture).status.success());
    let mut decoded = unpack(&fixture.bundle);
    let index = decoded
        .0
        .pieces
        .iter()
        .position(|piece| piece.name == "journal.jsonl")
        .unwrap();
    let mut events: Vec<Event> = std::str::from_utf8(&decoded.1[index].1)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let tail = events.last_mut().unwrap();
    tail.at_ms += 1;
    let prev = tail
        .prev
        .map(|hash| hash.to_hex())
        .unwrap_or_else(|| "-".to_string());
    let body = format!(
        "{}\n{}\n{}\n{}\n{prev}",
        tail.seq,
        tail.at_ms,
        tail.kind,
        serde_json::to_string(&tail.payload).unwrap()
    );
    tail.hash = Hash::of(body.as_bytes());
    let rewritten = events
        .iter()
        .map(|event| serde_json::to_string(event).unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    decoded.1[index].1 = format!("{rewritten}\n").into_bytes();
    decoded.1[index].0.hash = Hash::of(&decoded.1[index].1).to_hex();
    decoded.1[index].0.bytes = decoded.1[index].1.len() as u64;
    decoded.0.pieces[index] = decoded.1[index].0.clone();
    let path = fixture.root.join("bad-tail.tvab");
    pack(&path, &decoded);
    let verified = verify(&path, &fixture.root, &fixture.public);
    assert_eq!(
        failure_kind(&verified),
        "audit_bundle_incomplete",
        "{}\n{}",
        stdout(&verified),
        stderr(&verified)
    );
}

#[test]
fn trailing_truncated_and_oversized_containers_are_rejected() {
    let fixture = fixture("container-edges");
    assert!(export(&fixture).status.success());
    let original = fs::read(&fixture.bundle).unwrap();

    let mut trailing = original.clone();
    trailing.push(0);
    let trailing_path = fixture.root.join("trailing.tvab");
    fs::write(&trailing_path, trailing).unwrap();
    assert_eq!(
        failure_kind(&verify(&trailing_path, &fixture.root, &fixture.public)),
        "audit_bundle_trailing"
    );

    let truncated_path = fixture.root.join("truncated.tvab");
    fs::write(&truncated_path, &original[..original.len() - 1]).unwrap();
    assert_eq!(
        failure_kind(&verify(&truncated_path, &fixture.root, &fixture.public)),
        "audit_bundle_truncated"
    );

    let mut oversized = original;
    oversized[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    let oversized_path = fixture.root.join("oversized.tvab");
    fs::write(&oversized_path, oversized).unwrap();
    assert_eq!(
        failure_kind(&verify(&oversized_path, &fixture.root, &fixture.public)),
        "audit_bundle_too_large"
    );
}

#[test]
fn stale_anchor_and_existing_output_are_refused() {
    let stale = fixture("refusals");
    fs::write(stale.root.join("later.txt"), "later").unwrap();
    let add = run(&stale.root, &["add", "later.txt"]);
    assert!(add.status.success(), "{}", stderr(&add));
    let exported = export(&stale);
    assert_eq!(failure_kind(&exported), "audit_bundle_incomplete");
    assert!(!stale.bundle.exists());

    let fresh = fixture("no-overwrite");
    fs::write(&fresh.bundle, b"keep-me").unwrap();
    let exported = export(&fresh);
    assert_eq!(failure_kind(&exported), "audit_bundle_exists");
    assert_eq!(fs::read(&fresh.bundle).unwrap(), b"keep-me");
}

#[test]
fn non_regular_inputs_are_rejected_before_reading() {
    let fixture = fixture("non-regular");
    assert!(export(&fixture).status.success());

    let directory_bundle = fixture.root.join("directory.tvab");
    fs::create_dir(&directory_bundle).unwrap();
    assert_eq!(
        failure_kind(&verify(&directory_bundle, &fixture.root, &fixture.public)),
        "audit_bundle_bad"
    );

    let out = fixture.root.join("directory-anchor.tvab");
    let exported = run(
        &fixture.root,
        &[
            "audit",
            "bundle",
            "--out",
            out.to_str().unwrap(),
            "--anchor",
            fixture.root.to_str().unwrap(),
            "--anchor-public-key",
            &fixture.public,
            "--json",
        ],
    );
    assert_eq!(failure_kind(&exported), "audit_bundle_bad");
    assert!(!out.exists());
}

#[test]
fn sparse_state_is_rejected_on_export_and_verification() {
    let fixture = fixture("sparse-rejected");
    assert!(export(&fixture).status.success());

    let mut decoded = unpack(&fixture.bundle);
    let sparse = b"{\"prefix\":\"a\",\"tree\":\"untrusted\"}";
    let reference = PieceRef {
        name: "sparse.json".to_string(),
        hash: Hash::of(sparse).to_hex(),
        bytes: sparse.len() as u64,
    };
    decoded.0.pieces.push(reference.clone());
    decoded.1.push((reference, sparse.to_vec()));
    let path = fixture.root.join("sparse-in-package.tvab");
    pack(&path, &decoded);
    assert_eq!(
        failure_kind(&verify(&path, &fixture.root, &fixture.public)),
        "audit_bundle_bad"
    );

    fs::write(fixture.root.join(".tritvcs/sparse.json"), sparse).unwrap();
    let out = fixture.root.join("sparse-source.tvab");
    let exported = run(
        &fixture.root,
        &[
            "audit",
            "bundle",
            "--out",
            out.to_str().unwrap(),
            "--anchor",
            fixture.anchor.to_str().unwrap(),
            "--anchor-public-key",
            &fixture.public,
            "--json",
        ],
    );
    assert_eq!(failure_kind(&exported), "audit_bundle_incomplete");
    assert!(!out.exists());
}

#[test]
fn inventory_is_the_independently_derived_evidence_closure() {
    let fixture = fixture("inventory-closure");
    let orphan = b"unreferenced object";
    let orphan_id = Hash::of(orphan);
    {
        let repo = trit_vcs::repo::Repo::open(&fixture.root).unwrap();
        let (actual, _) = repo.store().put_chunk(orphan).unwrap();
        assert_eq!(actual, orphan_id);
    }
    assert!(export(&fixture).status.success());
    let decoded = unpack(&fixture.bundle);
    assert!(
        decoded
            .0
            .pieces
            .iter()
            .all(|piece| piece.name != format!("object:{orphan_id}"))
    );

    let mut decoded = decoded;
    let reference = PieceRef {
        name: format!("object:{orphan_id}"),
        hash: orphan_id.to_hex(),
        bytes: orphan.len() as u64,
    };
    let index = decoded
        .0
        .pieces
        .iter()
        .position(|piece| piece.name > reference.name)
        .unwrap_or(decoded.0.pieces.len());
    decoded.0.pieces.insert(index, reference.clone());
    decoded.1.insert(index, (reference, orphan.to_vec()));
    let path = fixture.root.join("extra-object.tvab");
    pack(&path, &decoded);
    assert_eq!(
        failure_kind(&verify(&path, &fixture.root, &fixture.public)),
        "audit_bundle_incomplete"
    );
}

type Decoded = (Manifest, Vec<(PieceRef, Vec<u8>)>);

fn unpack(path: &Path) -> Decoded {
    let bytes = fs::read(path).unwrap();
    assert_eq!(&bytes[..4], b"TVAB");
    assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), SCHEMA);
    let manifest_len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    let manifest: Manifest = serde_json::from_slice(&bytes[12..12 + manifest_len]).unwrap();
    let mut offset = 12 + manifest_len;
    let count = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
    offset += 4;
    let mut pieces = Vec::with_capacity(count);
    for reference in &manifest.pieces {
        offset += 32;
        let len = u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap()) as usize;
        offset += 4;
        pieces.push((reference.clone(), bytes[offset..offset + len].to_vec()));
        offset += len;
    }
    assert_eq!(offset, bytes.len());
    (manifest, pieces)
}

fn pack(path: &Path, decoded: &Decoded) {
    let (manifest, pieces) = decoded;
    let manifest = serde_json::to_vec(manifest).unwrap();
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"TVAB");
    bytes.extend_from_slice(&SCHEMA.to_le_bytes());
    bytes.extend_from_slice(&(manifest.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&manifest);
    bytes.extend_from_slice(&(pieces.len() as u32).to_le_bytes());
    for (reference, payload) in pieces {
        let hash = Hash::from_hex(&reference.hash).unwrap();
        bytes.extend_from_slice(hash.as_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(payload);
    }
    fs::write(path, bytes).unwrap();
}
