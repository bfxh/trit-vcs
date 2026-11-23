//! `sparse`：看/清持久 sparse 索引。
//!
//! 索引由前缀 `pull` / `checkout` 自动写；这里只做两件事——看一眼当前范围，
//! 或把它清掉（索引坏了不该阻塞工作，清掉只会退化成全量扫描）。

use std::process::ExitCode;

use trit_vcs::sparse::SparseIndex;

use super::{fail, has, repo_path};

fn short(value: &str) -> String {
    value.chars().take(12).collect()
}

pub(crate) fn sparse_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    if has(args, "--clear") {
        return match SparseIndex::clear(&root) {
            Ok(()) => {
                println!("已清除 sparse 索引：下一次 status 按全量工作树判");
                ExitCode::SUCCESS
            }
            Err(err) => fail(format!("清不掉 sparse 索引：{err}")),
        };
    }
    match SparseIndex::load(&root) {
        Some(index) => {
            if has(args, "--json") {
                let value = serde_json::json!({
                    "prefix": index.prefix,
                    "tree": index.tree,
                    "commit": index.commit,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "sparse 范围 {}（基准树 {}，来自提交 {}）",
                    index.prefix,
                    short(&index.tree),
                    index
                        .commit
                        .as_deref()
                        .map(short)
                        .unwrap_or_else(|| "-".to_string())
                );
            }
            ExitCode::SUCCESS
        }
        None => {
            println!("（没有 sparse 索引：当前按全量工作树判）");
            ExitCode::SUCCESS
        }
    }
}
