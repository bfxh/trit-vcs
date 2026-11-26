//! Git 桥命令：`git-export` / `git-import`。

use std::path::Path;
use std::process::ExitCode;

use trit_vcs::git_bridge::{self, BridgeOptions};
use trit_vcs::repo::Repo;

use super::cli_fail::CliFail;
use super::verdict::{fail_err, fail_repo};
use super::{flag, has, positionals, repo_path};

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
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_repo(&err, &root, "", args),
    };
    let ids = positionals(args, &["--repo", "--map", "--first-parent"]);
    let Some(target) = ids.first() else {
        eprintln!("git-export 需要目标 Git 目录");
        return ExitCode::from(2);
    };
    let options = BridgeOptions {
        first_parent: has(args, "--first-parent"),
    };
    match git_bridge::export_with_options(&mut repo, Path::new(target), &options) {
        Ok(stats) => {
            println!(
                "已导出 {} 个提交到 {}（写 {} 个文件）",
                stats.commits, target, stats.files_written
            );
            if stats.merge_commits > 0 {
                if options.first_parent {
                    eprintln!(
                        "注意：按 --first-parent 线性化，忽略了 {} 个 merge 的次要父链；审计事件已记录",
                        stats.merge_commits
                    );
                } else {
                    println!("保留 {} 个 merge 提交（完整多父图）", stats.merge_commits);
                }
            }
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
    let ids = positionals(args, &["--repo", "--map", "--first-parent"]);
    let Some(target) = ids.first() else {
        eprintln!("git-import 需要 Git 目录");
        return ExitCode::from(2);
    };
    let options = BridgeOptions {
        first_parent: has(args, "--first-parent"),
    };
    match git_bridge::import_with_options(&mut repo, Path::new(target), &options) {
        Ok(stats) => {
            println!(
                "已导入 {} 个提交（{} 个文件条目）自 {}",
                stats.commits, stats.files, target
            );
            if stats.metadata_commits > 0 {
                println!(
                    "保留 {} 个提交的作者/提交者/时间元数据",
                    stats.metadata_commits
                );
            }
            if stats.merge_commits > 0 {
                if options.first_parent {
                    eprintln!(
                        "注意：按 --first-parent 线性化，丢弃 {} 个 merge 的次要父链；审计事件已记录",
                        stats.merge_commits
                    );
                } else {
                    println!("保留 {} 个 merge 提交（完整多父图）", stats.merge_commits);
                }
            }
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
