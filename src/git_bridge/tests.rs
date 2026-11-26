use std::collections::BTreeMap;

use super::*;
use crate::gate::ClaimSpec;
use crate::model::{Commit, Hlc};

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("trit-vcs-git-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn commit(repo: &mut Repo, files: &[(&str, &str)], now: u64) -> Hash {
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
        now_secs: now,
        ..Default::default()
    })
    .unwrap()
    .id
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
fn export_refuses_trit_merge_graph() {
    let root = temp("export-merge");
    let mut repo = Repo::init(root.join("src")).unwrap();
    let first = commit(&mut repo, &[("a.txt", "one")], 1_000);
    let second = commit(&mut repo, &[("a.txt", "two")], 2_000);
    let tree = repo.commit_at(&second).unwrap().tree;
    let merge = Commit::new(tree, "qoder:merge", "merge", Hlc::zero().tick(3))
        .with_parent(first)
        .with_parent(second);
    let merge_id = repo.store().put_chunk(&merge.encode().unwrap()).unwrap().0;
    std::fs::write(
        root.join("src").join(".tritvcs").join("HEAD"),
        format!("{merge_id}\n"),
    )
    .unwrap();

    assert!(matches!(
        export(&mut repo, &root.join("git")),
        Err(GitError::MergeGraphUnsupported { merges: 1 })
    ));
    let failed = repo
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "git_bridge")
        .expect("拒绝导出也要落事件");
    assert_eq!(failed.payload["action"], "export");
    assert_eq!(failed.payload["status"], "failed");
    assert_eq!(failed.payload["merge_commits"], 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn merge_graph_is_refused_unless_first_parent_is_explicit() {
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
    assert!(matches!(
        import(&mut dst, &git_dir),
        Err(GitError::MergeGraphUnsupported { merges: 1 })
    ));
    let events = dst.journal().events();
    let failed = events
        .iter()
        .rev()
        .find(|event| event.kind == "git_bridge")
        .expect("拒绝 merge 也要落事件");
    assert_eq!(failed.payload["status"], "failed");
    assert_eq!(failed.payload["merge_commits"], 1);

    let imported =
        import_with_options(&mut dst, &git_dir, &BridgeOptions { first_parent: true }).unwrap();
    assert_eq!(imported.commits, 2, "第一父链：base、merge");
    assert_eq!(imported.merge_commits, 1);
    let head = dst.head().unwrap().unwrap();
    assert!(
        dst.commit_at(&head)
            .unwrap()
            .tags
            .contains(&"git-merge".to_string()),
        "merge 提交应显式带 git-merge 标签"
    );
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
