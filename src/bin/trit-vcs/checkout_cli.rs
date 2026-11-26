//! `checkout` 命令：还原工作树，并在 `--force` 放行未提交改动时落独立审计事件。

use std::process::ExitCode;

use trit_vcs::repo::Repo;
use trit_vcs::worktree;

use super::{fail, fail_err, fail_repo, flag, has, now_ms, positionals, repo_path};

pub(crate) fn checkout_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_repo(&err, &root, "", args),
    };
    let ids = positionals(args, &["--repo", "--prefix"]);
    let Some(target) = ids.first() else {
        eprintln!("checkout 需要提交 id");
        return ExitCode::from(2);
    };
    let Some(id) = trit_vcs::Hash::from_hex(target) else {
        return fail(format!("不是合法提交 id：{target}"));
    };
    let prefix = flag(args, "--prefix")
        .map(|raw| trit_vcs::sparse::normalize_prefix(raw).unwrap_or_else(|_| raw.to_string()));
    let prefix = prefix.as_deref();
    let force = has(args, "--force");
    // checkout 只改工作树，不在 state_digest；仍先取一次摘要，证明强制检出没有顺手改仓库状态。
    let state_before = match repo.state_digest() {
        Ok(digest) => digest.to_hex(),
        Err(err) => return fail_err(&err, &root, "", args),
    };
    match worktree::checkout_scoped(&repo, &id, prefix, force) {
        Ok(stats) => {
            let state_after = match repo.state_digest() {
                Ok(digest) => digest.to_hex(),
                Err(err) => return fail_err(&err, &root, "", args),
            };
            if force && stats.dirty > 0 {
                let event = serde_json::json!({
                    "schema": worktree::CHECKOUT_SCHEMA,
                    "commit": id.to_hex(),
                    "prefix": prefix,
                    "force": true,
                    "reason": "dirty_worktree",
                    "dirty": stats.dirty,
                    "dirty_sample": stats.dirty_sample,
                    "dirty_digest": stats.dirty_digest.map(|digest| digest.to_hex()),
                    "written": stats.written,
                    "skipped": stats.skipped,
                    "state_before": state_before,
                    "state_after": state_after,
                });
                if let Err(err) = repo.append_audit("checkout", event, now_ms()) {
                    return fail_err(&err, &root, "", args);
                }
            }
            let bypassed = if stats.dirty > 0 {
                format!("，放行 {} 个未提交改动", stats.dirty)
            } else {
                String::new()
            };
            println!(
                "已还原 {} 个文件、按范围跳过 {} 个（{}，前缀 {:?}）{bypassed}",
                stats.written,
                stats.skipped,
                id.short(),
                prefix.unwrap_or("全量")
            );
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, &root, "", args),
    }
}
