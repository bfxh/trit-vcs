//! 命令行端到端：trit → Git 导出，再从 Git 导入另一个 trit 仓。

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
    let dir = std::env::temp_dir().join(format!("trit-vcs-gitcli-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn export_and_import_through_the_cli() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("跳过：本机没有 git");
        return;
    }
    let root = temp("flow");
    let src = root.join("src");
    fs::create_dir_all(&src).unwrap();
    assert!(run(&src, &["init"]).status.success());
    fs::write(src.join("a.txt"), b"hello").unwrap();
    assert!(run(&src, &["add", "a.txt"]).status.success());
    let committed = run(
        &src,
        &[
            "commit",
            "-m",
            "镜像一版",
            "--owner",
            "qoder:it",
            "--allow-unclaimed",
            "--tag",
            "vcs",
        ],
    );
    assert!(committed.status.success(), "{}", stderr(&committed));

    let git_dir = root.join("git");
    let git_text = git_dir.to_string_lossy().to_string();
    let map = root.join("map.json");
    let map_text = map.to_string_lossy().to_string();
    let exported = run(&src, &["git-export", &git_text, "--map", &map_text]);
    assert!(exported.status.success(), "{}", stderr(&exported));
    let export_audit = run(&src, &["audit", "log", "git_bridge", "--json"]);
    assert!(export_audit.status.success(), "{}", stderr(&export_audit));
    let export_events: serde_json::Value = serde_json::from_str(&stdout(&export_audit)).unwrap();
    let export_event = export_events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["payload"]["action"] == "export")
        .expect("导出应落 git_bridge 事件");
    assert_eq!(export_event["payload"]["status"], "ok");
    assert_eq!(export_event["payload"]["commits"], 1);

    let log = Command::new("git")
        .args(["log", "--format=%s%n%b"])
        .current_dir(&git_dir)
        .output()
        .unwrap();
    let log_text = String::from_utf8_lossy(&log.stdout);
    assert!(log_text.contains("镜像一版"), "{log_text}");
    assert!(
        log_text.contains("Trit-Tags: vcs"),
        "导出提交应带 trit 尾注：{log_text}"
    );

    let dst = root.join("dst");
    fs::create_dir_all(&dst).unwrap();
    assert!(run(&dst, &["init"]).status.success());
    let dst_text = dst.to_string_lossy().to_string();
    let imported = run(
        &dst,
        &[
            "git-import",
            &git_text,
            "--repo",
            &dst_text,
            "--map",
            &map_text,
        ],
    );
    assert!(imported.status.success(), "{}", stderr(&imported));

    let logged = run(&dst, &["log", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&logged)).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 1);
    assert_eq!(rows[0]["message"], "镜像一版");
    assert_eq!(rows[0]["tags"][0], "git-import");
    assert!(map.is_file(), "映射表应落盘");

    let audit = run(&dst, &["audit", "log", "git_bridge", "--json"]);
    assert!(audit.status.success(), "{}", stderr(&audit));
    let events: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    let imported = events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["payload"]["action"] == "import")
        .expect("导入应落 git_bridge 事件");
    assert_eq!(imported["payload"]["status"], "ok");
    assert_eq!(imported["payload"]["commits"], 1);
    assert_eq!(
        imported["payload"]["map_digest"].as_str().unwrap().len(),
        64
    );
    let _ = fs::remove_dir_all(&root);
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

#[test]
fn git_import_keeps_merge_graph_by_default_and_first_parent_degrades() {
    if Command::new("git").arg("--version").output().is_err() {
        eprintln!("跳过：本机没有 git");
        return;
    }
    let root = temp("merge");
    let git_dir = root.join("git");
    fs::create_dir_all(&git_dir).unwrap();
    git_ok(&git_dir, &["init", "-q", "-b", "main"]);
    git_ok(&git_dir, &["config", "user.name", "Alice"]);
    git_ok(&git_dir, &["config", "user.email", "alice@example.com"]);
    fs::write(git_dir.join("base.txt"), b"base").unwrap();
    git_ok(&git_dir, &["add", "base.txt"]);
    git_ok(&git_dir, &["commit", "-q", "-m", "base"]);
    git_ok(&git_dir, &["branch", "feature"]);
    git_ok(&git_dir, &["switch", "-q", "feature"]);
    fs::write(git_dir.join("feature.txt"), b"feature").unwrap();
    git_ok(&git_dir, &["add", "feature.txt"]);
    git_ok(&git_dir, &["commit", "-q", "-m", "feature"]);
    git_ok(&git_dir, &["switch", "-q", "main"]);
    git_ok(
        &git_dir,
        &["merge", "--no-ff", "-q", "-m", "merge", "feature"],
    );

    let dst = root.join("dst");
    fs::create_dir_all(&dst).unwrap();
    assert!(run(&dst, &["init"]).status.success());
    let git_text = git_dir.to_string_lossy().to_string();
    let dst_text = dst.to_string_lossy().to_string();
    let imported = run(&dst, &["git-import", &git_text, "--repo", &dst_text]);
    assert!(imported.status.success(), "{}", stderr(&imported));
    assert!(
        stdout(&imported).contains("保留 1 个 merge 提交"),
        "{}",
        stdout(&imported)
    );

    let audit = run(&dst, &["audit", "log", "git_bridge", "--json"]);
    let events: serde_json::Value = serde_json::from_str(&stdout(&audit)).unwrap();
    let event = events
        .as_array()
        .unwrap()
        .iter()
        .find(|event| event["payload"]["action"] == "import")
        .expect("导入应落事件");
    assert_eq!(event["payload"]["status"], "ok");
    assert_eq!(event["payload"]["merge_commits"], 1);
    assert_eq!(event["payload"]["first_parent"], false);

    let all = run(&dst, &["log", "--all", "--json"]);
    assert!(all.status.success(), "{}", stderr(&all));
    let rows: serde_json::Value = serde_json::from_str(&stdout(&all)).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 3, "{rows}");
    assert_eq!(rows[0]["message"], "merge", "{rows}");
    assert_eq!(rows[0]["parents"].as_array().unwrap().len(), 2, "{rows}");

    // 从导入后的 trit 再导出一次，Git 侧必须还是 merge（两个父）。
    let back = root.join("back");
    let back_text = back.to_string_lossy().to_string();
    let exported = run(&dst, &["git-export", &back_text]);
    assert!(exported.status.success(), "{}", stderr(&exported));
    let parents = Command::new("git")
        .args(["log", "-1", "--format=%P", "HEAD"])
        .current_dir(&back)
        .output()
        .unwrap();
    let parents = String::from_utf8_lossy(&parents.stdout);
    assert_eq!(parents.split_whitespace().count(), 2, "{parents}");

    let flat = root.join("flat");
    fs::create_dir_all(&flat).unwrap();
    assert!(run(&flat, &["init"]).status.success());
    let flat_text = flat.to_string_lossy().to_string();
    let degraded = run(
        &flat,
        &[
            "git-import",
            &git_text,
            "--repo",
            &flat_text,
            "--first-parent",
        ],
    );
    assert!(degraded.status.success(), "{}", stderr(&degraded));
    let logged = run(&flat, &["log", "--json"]);
    let rows: serde_json::Value = serde_json::from_str(&stdout(&logged)).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 2, "{rows}");
    assert!(
        rows[0]["tags"]
            .as_array()
            .unwrap()
            .iter()
            .any(|tag| tag == "git-merge"),
        "{rows}"
    );
    let _ = fs::remove_dir_all(&root);
}
