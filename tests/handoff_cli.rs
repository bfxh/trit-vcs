//! 交接包：round-trip、删任一部件必红、篡改必红、语义篡改 diff 必红、悬空引用必红。

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use trit_vcs::Hash;
use trit_vcs::handoff::Manifest;
use trit_vcs::repo::Repo;

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

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trit-vcs-handoff-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn commit(root: &Path, message: &str) {
    let out = run(
        root,
        &[
            "commit",
            "-m",
            message,
            "--owner",
            "qoder:test",
            "--allow-unclaimed",
            "--goal",
            "验证交接包",
            "--accept",
            "handoff-verify 通过",
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
}

fn head(root: &Path) -> String {
    Repo::open(root)
        .unwrap()
        .head()
        .unwrap()
        .expect("HEAD 为空")
        .to_hex()
}

/// 两个提交：a 改、b 增、c 删 ⇒ diff 三种 kind 都有。
fn seed(root: &Path) -> String {
    assert!(run(root, &["init"]).status.success());
    fs::write(root.join("a.txt"), "first\n").unwrap();
    fs::write(root.join("c.txt"), "to-delete\n").unwrap();
    assert!(run(root, &["add", "a.txt", "c.txt"]).status.success());
    commit(root, "第一版");
    fs::write(root.join("a.txt"), "second\n").unwrap();
    fs::write(root.join("b.txt"), "new\n").unwrap();
    fs::remove_file(root.join("c.txt")).unwrap();
    // c 不在 targets 里 ⇒ 新树没有它，相对父提交就是删除。
    assert!(run(root, &["add", "a.txt", "b.txt"]).status.success());
    commit(root, "第二版");
    head(root)
}

fn handoff(root: &Path, commit: &str, name: &str) -> PathBuf {
    let package = temp(name);
    let out = run(
        root,
        &[
            "handoff",
            commit,
            "--out",
            package.to_str().unwrap(),
            "--repo",
            root.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    package
}

fn verify(root: &Path, package: &Path) -> Output {
    run(
        root,
        &[
            "handoff-verify",
            package.to_str().unwrap(),
            "--repo",
            root.to_str().unwrap(),
        ],
    )
}

fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            walk(&path, base, out);
        } else {
            out.push(
                path.strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn read_manifest(package: &Path) -> Manifest {
    serde_json::from_slice(&fs::read(package.join("manifest.json")).unwrap()).unwrap()
}

fn write_manifest(package: &Path, manifest: &Manifest) {
    fs::write(
        package.join("manifest.json"),
        serde_json::to_vec_pretty(manifest).unwrap(),
    )
    .unwrap();
}

#[test]
fn handoff_round_trip_and_delete_each_component_is_red() {
    let root = temp("roundtrip");
    let head = seed(&root);
    let package = handoff(&root, &head, "roundtrip-pkg");

    let ok = verify(&root, &package);
    assert!(ok.status.success(), "{}", stderr(&ok));

    let mut files = Vec::new();
    walk(&package, &package, &mut files);
    assert!(files.len() >= 8, "包太小，删件测试没覆盖：{files:?}");
    assert!(files.iter().any(|p| p == "manifest.json"));
    assert!(files.iter().any(|p| p.starts_with("objects/")));

    for rel in &files {
        let path = package.join(rel);
        let bytes = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let out = verify(&root, &package);
        let text = stderr(&out);
        assert!(!out.status.success(), "删掉 {rel} 后 verify 仍绿");
        assert!(
            text.contains("FAIL") && text.contains("（handoff_missing）"),
            "删掉 {rel} 后没有 handoff_missing FAIL 行：{text}"
        );
        fs::write(&path, bytes).unwrap();
    }
    let ok = verify(&root, &package);
    assert!(ok.status.success(), "{}", stderr(&ok));
}

#[test]
fn handoff_verify_rejects_tampered_component() {
    let root = temp("tamper");
    let head = seed(&root);
    let package = handoff(&root, &head, "tamper-pkg");

    // 改文件内容部件：长度不变、也没有语义复算能兜住它 ⇒ 只有 hash 这一道能抓。
    let manifest = read_manifest(&package);
    let component = manifest
        .components
        .iter()
        .find(|c| c.kind == "file")
        .expect("file 部件");
    let path = package.join(&component.path);
    let mut bytes = fs::read(&path).unwrap();
    assert!(!bytes.is_empty());
    bytes[0] = if bytes[0] == b'a' { b'b' } else { b'a' };
    fs::write(&path, bytes).unwrap();

    let out = verify(&root, &package);
    let text = stderr(&out);
    assert!(
        !out.status.success(),
        "篡改 file 部件后 verify 仍绿：{text}"
    );
    assert!(text.contains("（handoff_hash）"), "{text}");
}

#[test]
fn handoff_verify_rejects_tampered_package_id() {
    let root = temp("package-id");
    let head = seed(&root);
    let package = handoff(&root, &head, "package-id-pkg");

    let mut manifest = read_manifest(&package);
    manifest.package_id = "0".repeat(64);
    write_manifest(&package, &manifest);

    let out = verify(&root, &package);
    let text = stderr(&out);
    assert!(
        !out.status.success(),
        "改 package_id 后 verify 仍绿：{text}"
    );
    assert!(text.contains("（handoff_hash）"), "{text}");
    assert!(text.contains("package_id"), "{text}");
}

#[test]
fn handoff_verify_rejects_tampered_diff() {
    let root = temp("diff");
    let head = seed(&root);
    let package = handoff(&root, &head, "diff-pkg");

    let mut manifest = read_manifest(&package);
    let component = manifest
        .components
        .iter_mut()
        .find(|c| c.kind == "diff")
        .expect("diff 部件");
    let new_bytes = b"[]".to_vec();
    fs::write(package.join(&component.path), &new_bytes).unwrap();
    component.object = Hash::of(&new_bytes).to_hex();
    component.bytes = new_bytes.len() as u64;
    manifest.package_id = manifest.recompute_package_id().unwrap().to_hex();
    write_manifest(&package, &manifest);

    let out = verify(&root, &package);
    let text = stderr(&out);
    assert!(!out.status.success(), "改 diff 后 verify 仍绿：{text}");
    assert!(text.contains("diff 与 commit/parent 树不一致"), "{text}");
    assert!(text.contains("（handoff_manifest）"), "{text}");
}

#[test]
fn handoff_verify_rejects_dangling_reference() {
    let root = temp("dangling");
    let head = seed(&root);
    let package = handoff(&root, &head, "dangling-pkg");

    let mut manifest = read_manifest(&package);
    let index = manifest
        .components
        .iter()
        .position(|c| c.kind == "file-map")
        .expect("file-map 部件");
    manifest.components.remove(index);
    manifest.package_id = manifest.recompute_package_id().unwrap().to_hex();
    write_manifest(&package, &manifest);

    let out = verify(&root, &package);
    let text = stderr(&out);
    assert!(!out.status.success(), "删清单条目后 verify 仍绿：{text}");
    assert!(text.contains("（handoff_dangling）"), "{text}");
}

#[test]
fn handoff_root_commit_has_no_parents() {
    let root = temp("root");
    assert!(run(&root, &["init"]).status.success());
    fs::write(root.join("a.txt"), "one\n").unwrap();
    assert!(run(&root, &["add", "a.txt"]).status.success());
    commit(&root, "根提交");
    let package = handoff(&root, &head(&root), "root-pkg");

    let manifest = read_manifest(&package);
    assert!(manifest.parents.is_empty(), "{}", manifest.parents.len());
    let out = verify(&root, &package);
    assert!(out.status.success(), "{}", stderr(&out));
}

fn handoff_file(root: &Path, commit: &str, name: &str) -> PathBuf {
    let file = temp(name).join("package.tvhp");
    let out = run(
        root,
        &[
            "handoff",
            commit,
            "--out",
            file.to_str().unwrap(),
            "--bundle",
            "--repo",
            root.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(file.is_file(), "单文件包应当是一个文件，不是目录");
    file
}

#[test]
fn handoff_single_file_round_trip_and_same_package_id() {
    let root = temp("sf-roundtrip");
    let head = seed(&root);
    let dir = handoff(&root, &head, "sf-dir");
    let file = handoff_file(&root, &head, "sf-file");

    // 单文件头是 TVHP，与传输包 TVBD 区分。
    assert_eq!(&fs::read(&file).unwrap()[0..4], b"TVHP");

    let ok = verify(&root, &file);
    assert!(ok.status.success(), "{}", stderr(&ok));

    // 同一提交两种形态：包 id / commit / 部件数逐字相同。
    let dir_report = trit_vcs::handoff::verify(&dir, None).unwrap();
    let file_report = trit_vcs::handoff::verify(&file, None).unwrap();
    assert_eq!(dir_report.package_id, file_report.package_id);
    assert_eq!(dir_report.commit, file_report.commit);
    assert_eq!(dir_report.components, file_report.components);
}

#[test]
fn handoff_single_file_tampered_payload_is_red() {
    let root = temp("sf-tamper");
    let head = seed(&root);
    let file = handoff_file(&root, &head, "sf-tamper-f");
    let mut bytes = fs::read(&file).unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    fs::write(&file, bytes).unwrap();
    let out = verify(&root, &file);
    let text = stderr(&out);
    assert!(!out.status.success(), "篡改单文件后仍绿：{text}");
    assert!(text.contains("（handoff_hash）"), "{text}");
}

#[test]
fn handoff_single_file_truncated_is_red() {
    let root = temp("sf-trunc");
    let head = seed(&root);
    let file = handoff_file(&root, &head, "sf-trunc-f");
    let mut bytes = fs::read(&file).unwrap();
    bytes.truncate(bytes.len() / 2);
    fs::write(&file, bytes).unwrap();
    let out = verify(&root, &file);
    let text = stderr(&out);
    assert!(!out.status.success(), "截断单文件后仍绿：{text}");
    assert!(text.contains("（handoff_missing）"), "{text}");
}

#[test]
fn handoff_single_file_bad_magic_is_red() {
    let root = temp("sf-magic");
    let head = seed(&root);
    let file = handoff_file(&root, &head, "sf-magic-f");
    let mut bytes = fs::read(&file).unwrap();
    bytes[0] ^= 0xFF;
    fs::write(&file, bytes).unwrap();
    let out = verify(&root, &file);
    let text = stderr(&out);
    assert!(!out.status.success(), "坏 magic 后仍绿：{text}");
    assert!(text.contains("（handoff_manifest）"), "{text}");
}

#[test]
fn handoff_verify_rejects_transport_tvbd() {
    let root = temp("sf-cross-tvbd");
    seed(&root);
    let repo = Repo::open(&root).unwrap();
    let head_id = repo.head().unwrap().unwrap();
    let tree = repo.commit_at(&head_id).unwrap().tree;
    let tvbd = temp("sf-tvbd").join("transport.tvbd");
    let out = run(
        &root,
        &[
            "export",
            &tree.to_hex(),
            "--out",
            tvbd.to_str().unwrap(),
            "--repo",
            root.to_str().unwrap(),
        ],
    );
    assert!(out.status.success(), "{}", stderr(&out));
    let out = verify(&root, &tvbd);
    let text = stderr(&out);
    assert!(!out.status.success(), "传输包被当成交接包收：{text}");
    assert!(text.contains("（handoff_manifest）"), "{text}");
}

#[test]
fn import_rejects_handoff_tvhp() {
    let root = temp("sf-cross-tvhp");
    let head = seed(&root);
    let file = handoff_file(&root, &head, "sf-cross-f");
    let out = run(
        &root,
        &[
            "import",
            file.to_str().unwrap(),
            "--repo",
            root.to_str().unwrap(),
        ],
    );
    let text = stderr(&out);
    assert!(!out.status.success(), "交接包被传输 import 收：{text}");
    assert!(text.contains("magic"), "{text}");
}
