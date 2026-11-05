//! Git 桥命令：`git-export` / `git-import`。

use std::path::Path;
use std::process::ExitCode;

use trit_vcs::git_bridge;
use trit_vcs::repo::Repo;

use super::cli_fail::CliFail;
use super::verdict::{fail_err, fail_repo};
use super::{flag, positionals, repo_path};

fn write_map(path: Option<&str>, rows: Vec<serde_json::Value>) -> Result<(), CliFail> {
    let Some(path) = path else {
        return Ok(());
    };
    let encoded = serde_json::to_vec_pretty(&rows).map_err(|err| {
        CliFail::new(
            "cli_map_encode",
            format!("{path}: {err}"),
            ["映射表必须是 {id: hex} 的 JSON；这条内部序列化失败 ⇒ 把两侧提交 id 打出来看哪一条坏了".to_string()],
        )
    })?;
    std::fs::write(path, encoded).map_err(|err| {
        CliFail::local_io(
            path,
            &err.to_string(),
            [
                format!("换一个可写路径重跑：`--map {path}` 改成当前目录下的文件"),
                "映射表丢了不要紧：`trit-vcs git-export <git目录>` 不带 --map 也能出映射，只是再导一次会认不出旧对应".to_string(),
            ],
        )
    })
}

pub(crate) fn export_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_repo(&err, &root, "", args),
    };
    let ids = positionals(args, &["--repo", "--map"]);
    let Some(target) = ids.first() else {
        eprintln!("git-export 需要目标 Git 目录");
        return ExitCode::from(2);
    };
    match git_bridge::export(&repo, Path::new(target)) {
        Ok(stats) => {
            println!(
                "已导出 {} 个提交到 {}（写 {} 个文件）",
                stats.commits, target, stats.files_written
            );
            let rows = stats
                .map
                .iter()
                .map(|(trit, git)| serde_json::json!({"trit": trit.to_hex(), "git": git}))
                .collect();
            if let Err(err) = write_map(flag(args, "--map"), rows) {
                return fail_err(&err, &root, "", args);
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, &root, "", args),
    }
}

pub(crate) fn import_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_repo(&err, &root, "", args),
    };
    let ids = positionals(args, &["--repo", "--map"]);
    let Some(target) = ids.first() else {
        eprintln!("git-import 需要 Git 目录");
        return ExitCode::from(2);
    };
    match git_bridge::import(&mut repo, Path::new(target)) {
        Ok(stats) => {
            println!(
                "已导入 {} 个提交（{} 个文件条目）自 {}",
                stats.commits, stats.files, target
            );
            let rows = stats
                .map
                .iter()
                .map(|(git, trit)| serde_json::json!({"git": git, "trit": trit.to_hex()}))
                .collect();
            if let Err(err) = write_map(flag(args, "--map"), rows) {
                return fail_err(&err, &root, "", args);
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, &root, "", args),
    }
}
