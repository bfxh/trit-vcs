use std::collections::BTreeMap;

use super::*;
use crate::gate::ClaimSpec;

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trit-vcs-git-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn commit_with(
    repo: &mut Repo,
    files: &[(&str, &str)],
    now: u64,
    parents: Option<Vec<Hash>>,
) -> Hash {
    let map: BTreeMap<String, Vec<u8>> = files
        .iter()
        .map(|(path, body)| (path.to_string(), body.as_bytes().to_vec()))
        .collect();
    repo.stage(&map, now).unwrap();
    repo.commit(CommitRequest {
        message: format!("trit c{now}"),
        session: "qoder:git".to_string(),
        claims: vec![ClaimSpec {
            id: format!("c{now}"),
            owner: "qoder:git".to_string(),
            paths: map.keys().cloned().collect(),
            acquired_at: 1,
            expires_at: u64::MAX / 2,
        }],
        tags: vec!["vcs".to_string()],
        parents_override: parents,
        now_secs: now,
        ..Default::default()
    })
    .unwrap()
    .id
}

fn commit(repo: &mut Repo, files: &[(&str, &str)], now: u64) -> Hash {
    commit_with(repo, files, now, None)
}

fn head_files(repo: &Repo) -> BTreeMap<String, Vec<u8>> {
    let head = repo.head().unwrap().unwrap();
    let tree = repo.commit_at(&head).unwrap().tree;
    let entries = repo.store().tree_entries(&tree).unwrap();
    entries
        .into_iter()
        .map(|(path, id)| (path, repo.store().get_file(&id).unwrap()))
        .collect()
}

fn git_ok(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn init_git(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    git_ok(dir, &["init", "-q", "-b", "main"]);
    git_ok(dir, &["config", "user.name", "Alice"]);
    git_ok(dir, &["config", "user.email", "alice@example.com"]);
}

#[test]
fn imported_git_metadata_is_audited_and_exported_back() {
    let root = temp("metadata");
    let git_dir = root.join("git");
    init_git(&git_dir);
    std::fs::write(git_dir.join("a.txt"), b"one").unwrap();
    git_ok(&git_dir, &["add", "a.txt"]);
    let mut commit_cmd = Command::new("git");
    commit_cmd
        .args(["commit", "-q", "-m", "from git"])
        .current_dir(&git_dir)
        .env("GIT_AUTHOR_DATE", "@1700000000 +0000")
        .env("GIT_COMMITTER_DATE", "@1700000001 +0000");
    assert!(commit_cmd.output().unwrap().status.success());

    let mut dst = Repo::init(root.join("dst")).unwrap();
    let imported = import(&mut dst, &git_dir).unwrap();
    assert_eq!(imported.commits, 1);
    assert_eq!(imported.metadata_commits, 1);
    let head = dst.head().unwrap().unwrap();
    let commit = dst.commit_at(&head).unwrap();
    assert!(
        commit
            .evidence
            .iter()
            .any(|line| line == "git-author:Alice <alice@example.com>"),
        "{:?}",
        commit.evidence
    );
    assert!(
        commit
            .evidence
            .iter()
            .any(|line| line == "git-author-at:1700000000"),
        "{:?}",
        commit.evidence
    );

    let events = dst.journal().events();
    let bridge = events
        .iter()
        .rev()
        .find(|event| event.kind == "git_bridge")
        .expect("导入应落 git_bridge 事件");
    assert_eq!(bridge.payload["action"], "import");
    assert_eq!(bridge.payload["status"], "ok");
    assert_eq!(bridge.payload["commits"], 1);
    assert_eq!(bridge.payload["metadata_commits"], 1);
    assert!(
        bridge.payload["map_digest"].as_str().unwrap().len() == 64,
        "{}",
        bridge.payload
    );

    let out = root.join("out");
    let exported = export(&mut dst, &out).unwrap();
    assert_eq!(exported.metadata_commits, 1);
    let author = git_text(&out, &["log", "-1", "--format=%an <%ae>|%at"]).unwrap();
    assert_eq!(author.trim(), "Alice <alice@example.com>|1700000000");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn git_tags_are_imported_exported_and_annotations_are_marked_lossy() {
    let root = temp("tags");
    let git_dir = root.join("git");
    init_git(&git_dir);
    std::fs::write(git_dir.join("a.txt"), b"one").unwrap();
    git_ok(&git_dir, &["add", "a.txt"]);
    git_ok(&git_dir, &["commit", "-q", "-m", "base"]);
    git_ok(&git_dir, &["tag", "v1"]);
    std::fs::write(git_dir.join("b.txt"), b"two").unwrap();
    git_ok(&git_dir, &["add", "b.txt"]);
    git_ok(&git_dir, &["commit", "-q", "-m", "second"]);
    git_ok(&git_dir, &["tag", "-a", "release", "-m", "release notes"]);
    // 不在 HEAD 历史上的标签不能被假装搬进来。
    git_ok(&git_dir, &["switch", "-q", "-c", "side"]);
    std::fs::write(git_dir.join("side.txt"), b"side").unwrap();
    git_ok(&git_dir, &["add", "side.txt"]);
    git_ok(&git_dir, &["commit", "-q", "-m", "side"]);
    git_ok(&git_dir, &["tag", "side-only"]);
    git_ok(&git_dir, &["switch", "-q", "main"]);

    let mut dst = Repo::init(root.join("dst")).unwrap();
    let imported = import(&mut dst, &git_dir).unwrap();
    assert_eq!(imported.tags, 2);
    assert_eq!(imported.annotated_tags, 1);
    assert_eq!(imported.tags_skipped, 1, "侧分支标签不在 HEAD 图里");
    let log = dst.log().unwrap();
    let base = log
        .iter()
        .find(|(_, commit)| commit.message == "base")
        .unwrap();
    let second = log
        .iter()
        .find(|(_, commit)| commit.message == "second")
        .unwrap();
    assert!(
        base.1.evidence.iter().any(|line| line == "git-tag:v1"),
        "{:?}",
        base.1.evidence
    );
    assert!(
        second
            .1
            .evidence
            .iter()
            .any(|line| line == "git-tag-annotated:release"),
        "{:?}",
        second.1.evidence
    );
    let event = dst
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "git_bridge")
        .unwrap();
    assert_eq!(event.payload["tags"], 2);
    assert_eq!(event.payload["annotated_tags"], 1);
    assert_eq!(event.payload["tags_skipped"], 1);

    let out = root.join("out");
    let exported = export(&mut dst, &out).unwrap();
    assert_eq!(exported.tags, 2);
    assert_eq!(
        exported.annotated_tags_degraded, 1,
        "附注标签导出为轻量标签"
    );
    let tags = git_text(&out, &["tag", "--list"]).unwrap();
    assert!(tags.lines().any(|name| name == "v1"), "{tags}");
    assert!(tags.lines().any(|name| name == "release"), "{tags}");
    assert!(
        !tags.lines().any(|name| name == "side-only"),
        "未导入的侧分支标签不该凭空出现：{tags}"
    );

    let mut roundtrip = Repo::init(root.join("roundtrip")).unwrap();
    let reimported = import(&mut roundtrip, &out).unwrap();
    assert_eq!(reimported.tags, 2);
    assert_eq!(reimported.annotated_tags, 0, "导出后只剩轻量标签");
    let log = roundtrip.log().unwrap();
    let second = log
        .iter()
        .find(|(_, commit)| commit.message == "second")
        .unwrap();
    assert!(
        second
            .1
            .evidence
            .iter()
            .any(|line| line == "git-tag:release"),
        "附注标签应降级为轻量标签名：{:?}",
        second.1.evidence
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn export_preserves_trit_merge_graph() {
    let root = temp("export-merge");
    let mut repo = Repo::init(root.join("src")).unwrap();
    let base = commit(&mut repo, &[("base.txt", "base")], 1_000);
    let left = commit_with(&mut repo, &[("base.txt", "left")], 1_001, Some(vec![base]));
    let right = commit_with(&mut repo, &[("base.txt", "right")], 1_002, Some(vec![base]));
    let merge = commit_with(
        &mut repo,
        &[("base.txt", "merged")],
        1_003,
        Some(vec![left, right]),
    );
    assert_eq!(repo.head().unwrap().unwrap(), merge);
    assert_eq!(repo.commit_at(&merge).unwrap().parents, vec![left, right]);

    let out = root.join("git");
    let exported = export(&mut repo, &out).unwrap();
    assert_eq!(exported.commits, 4);
    assert_eq!(exported.merge_commits, 1, "多父图不能只导出第一父链");
    let count = git_text(&out, &["rev-list", "--count", "HEAD"]).unwrap();
    assert_eq!(count.trim(), "4");
    let parents = git_text(&out, &["log", "-1", "--format=%P", "HEAD"]).unwrap();
    assert_eq!(
        parents.split_whitespace().count(),
        2,
        "Git HEAD 应该是 merge：{parents}"
    );

    let mut dst = Repo::init(root.join("dst")).unwrap();
    let imported = import(&mut dst, &out).unwrap();
    assert_eq!(imported.commits, 4);
    assert_eq!(imported.merge_commits, 1);
    let imported_merge = dst.head().unwrap().unwrap();
    let commit = dst.commit_at(&imported_merge).unwrap();
    assert_eq!(commit.parents.len(), 2, "导入后仍应有两个父");
    assert!(commit.tags.contains(&"git-merge".to_string()));

    let flat = root.join("git-flat");
    let degraded =
        export_with_options(&mut repo, &flat, &BridgeOptions { first_parent: true }).unwrap();
    assert_eq!(degraded.commits, 3, "第一父链：base、left、merge");
    assert_eq!(degraded.merge_commits, 1);
    let count = git_text(&flat, &["rev-list", "--count", "HEAD"]).unwrap();
    assert_eq!(count.trim(), "3");
    let parents = git_text(&flat, &["log", "-1", "--format=%P", "HEAD"]).unwrap();
    assert_eq!(parents.split_whitespace().count(), 1, "{parents}");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn git_merge_graph_imports_by_default_and_first_parent_can_degrade() {
    let root = temp("merge");
    let git_dir = root.join("git");
    init_git(&git_dir);
    std::fs::write(git_dir.join("base.txt"), b"base").unwrap();
    git_ok(&git_dir, &["add", "base.txt"]);
    git_ok(&git_dir, &["commit", "-q", "-m", "base"]);
    git_ok(&git_dir, &["branch", "feature"]);
    git_ok(&git_dir, &["switch", "-q", "feature"]);
    std::fs::write(git_dir.join("feature.txt"), b"feature").unwrap();
    git_ok(&git_dir, &["add", "feature.txt"]);
    git_ok(&git_dir, &["commit", "-q", "-m", "feature"]);
    git_ok(&git_dir, &["switch", "-q", "main"]);
    git_ok(
        &git_dir,
        &["merge", "--no-ff", "-q", "-m", "merge", "feature"],
    );

    let mut dst = Repo::init(root.join("dst")).unwrap();
    let imported = import(&mut dst, &git_dir).unwrap();
    assert_eq!(imported.commits, 3, "base、feature、merge 都在图里");
    assert_eq!(imported.merge_commits, 1);
    let head = dst.head().unwrap().unwrap();
    let commit = dst.commit_at(&head).unwrap();
    assert_eq!(commit.parents.len(), 2, "默认导入必须保留两个父");
    assert_eq!(commit.message, "merge");
    assert!(commit.tags.contains(&"git-merge".to_string()));
    let event = dst
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "git_bridge")
        .expect("导入应落事件");
    assert_eq!(event.payload["status"], "ok");
    assert_eq!(event.payload["merge_commits"], 1);
    assert_eq!(event.payload["first_parent"], false);

    let mut flat = Repo::init(root.join("flat")).unwrap();
    let degraded =
        import_with_options(&mut flat, &git_dir, &BridgeOptions { first_parent: true }).unwrap();
    assert_eq!(degraded.commits, 2, "第一父链：base、merge");
    assert_eq!(degraded.merge_commits, 1);
    let flat_head = flat.head().unwrap().unwrap();
    let flat_merge = flat.commit_at(&flat_head).unwrap();
    assert_eq!(flat_merge.parents.len(), 1, "显式降级只保留第一父");
    assert!(
        flat_merge.tags.contains(&"git-merge".to_string()),
        "证据仍应记下它原本是 merge"
    );
    let flat_event = flat
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "git_bridge")
        .expect("降级导入也应落事件");
    assert_eq!(flat_event.payload["first_parent"], true);
    assert_eq!(flat_event.payload["merge_commits"], 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn trailers_are_stripped_from_imported_messages() {
    assert_eq!(
        strip_trailers("msg\n\nTrit-Id: abc\nTrit-Session: s\nTrit-Tags: vcs\n"),
        "msg"
    );
    assert_eq!(strip_trailers("plain"), "plain");
}

#[test]
fn export_then_import_roundtrip_keeps_content_and_order() {
    let root = temp("roundtrip");
    let mut src = Repo::init(root.join("src")).unwrap();
    commit(&mut src, &[("a.txt", "one"), ("dir/b.txt", "two")], 1_000);
    commit(
        &mut src,
        &[("a.txt", "one changed"), ("c.txt", "three")],
        2_000,
    );
    let before = head_files(&src);

    let git_dir = root.join("git");
    let exported = export(&mut src, &git_dir).unwrap();
    assert_eq!(exported.commits, 2);
    assert_eq!(exported.files_written, 4);

    let log = git_text(&git_dir, &["log", "--format=%s%n%b"]).unwrap();
    assert!(
        log.contains("Trit-Tags: vcs"),
        "提交里应带 trit 尾注：{log}"
    );
    assert!(
        !git_dir.join("dir/b.txt").exists(),
        "删除必须同步到 Git 工作树"
    );

    let mut dst = Repo::init(root.join("dst")).unwrap();
    let imported = import(&mut dst, &git_dir).unwrap();
    assert_eq!(imported.commits, 2);
    assert_eq!(head_files(&dst), before, "往返后内容逐字节一致");
    let head = dst.head().unwrap().unwrap();
    assert_eq!(
        dst.commit_at(&head).unwrap().tags,
        vec!["git-import".to_string()]
    );
    let log = dst.log().unwrap();
    assert_eq!(log[0].1.message, "trit c2000", "尾注不应混进提交说明");
    assert_eq!(log[1].1.message, "trit c1000");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn import_reads_a_plain_git_repo() {
    let root = temp("import");
    let git_dir = root.join("git");
    std::fs::create_dir_all(&git_dir).unwrap();
    git_raw(&git_dir, &["init", "-q"]).unwrap();
    git_raw(&git_dir, &["config", "user.name", "bench"]).unwrap();
    git_raw(&git_dir, &["config", "user.email", "bench@example.com"]).unwrap();
    std::fs::write(git_dir.join("x.txt"), b"first").unwrap();
    git_raw(&git_dir, &["add", "-A"]).unwrap();
    git_raw(&git_dir, &["commit", "-qm", "first"]).unwrap();
    std::fs::write(git_dir.join("x.txt"), b"second").unwrap();
    git_raw(&git_dir, &["add", "-A"]).unwrap();
    git_raw(&git_dir, &["commit", "-qm", "second"]).unwrap();

    let mut repo = Repo::init(root.join("trit")).unwrap();
    let stats = import(&mut repo, &git_dir).unwrap();
    assert_eq!(stats.commits, 2);
    let files = head_files(&repo);
    assert_eq!(files.get("x.txt").unwrap().as_slice(), b"second");
    let log = repo.log().unwrap();
    assert_eq!(log[0].1.message, "second");
    assert_eq!(log[1].1.message, "first");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn export_paths_cannot_escape_the_git_worktree() {
    assert!(safe_join(Path::new("/repo"), "../escape").is_err());
    assert!(safe_join(Path::new("/repo"), "/abs").is_err());
    assert!(safe_join(Path::new("/repo"), "ok/inside").is_ok());
}

#[test]
fn empty_source_is_loud() {
    let root = temp("empty");
    let mut repo = Repo::init(root.join("src")).unwrap();
    assert!(matches!(
        export(&mut repo, &root.join("git")),
        Err(GitError::NoCommits)
    ));
    let _ = std::fs::remove_dir_all(&root);
}
