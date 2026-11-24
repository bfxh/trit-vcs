//! `policy`：查看当前门禁策略，或用受审计的方式整份替换它。
//!
//! `policy set` 的语义是“本次参数就是完整策略”：没带的开关一律归 false，
//! 不沿用旧 true。这样一次命令就能复现“谁在什么时候把哪项打开/关掉”。

use std::process::ExitCode;

use serde_json::json;
use trit_vcs::repo::{Policy, Repo};

use super::verdict::fail_err;
use super::{flag, has, now_secs, positionals, repo_path};

const USAGE: &str = "policy 用法：\n  \
     trit-vcs policy [--json] [--repo PATH]\n  \
     trit-vcs policy set --owner <宿主:会话id> [--require-witness] [--require-intent] [--require-signed-claims] [--json] [--repo PATH]";

fn show(repo: &Repo, args: &[String]) -> ExitCode {
    let policy = match repo.policy() {
        Ok(policy) => policy,
        Err(err) => return fail_err(&err, repo.root(), "", args),
    };
    if has(args, "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "require_witness": policy.require_witness,
                "require_intent": policy.require_intent,
                "require_signed_claims": policy.require_signed_claims,
            }))
            .unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("require_witness={}", policy.require_witness);
        println!("require_intent={}", policy.require_intent);
        println!("require_signed_claims={}", policy.require_signed_claims);
    }
    ExitCode::SUCCESS
}

fn set(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let owner = flag(args, "--owner").unwrap_or("");
    if owner.is_empty() {
        eprintln!("policy set 需要 --owner <宿主:会话id>");
        return ExitCode::from(2);
    }
    let policy = Policy {
        require_witness: has(args, "--require-witness"),
        require_intent: has(args, "--require-intent"),
        require_signed_claims: has(args, "--require-signed-claims"),
    };
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &root, owner, args),
    };
    match repo.set_policy(&policy, owner, now_secs() * 1000) {
        Ok(hash) => {
            if has(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "require_witness": policy.require_witness,
                        "require_intent": policy.require_intent,
                        "require_signed_claims": policy.require_signed_claims,
                        "policy": hash.to_hex(),
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "策略已更新：require_witness={} require_intent={} require_signed_claims={}（policy {}）",
                    policy.require_witness,
                    policy.require_intent,
                    policy.require_signed_claims,
                    hash.short()
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, repo.root(), owner, args),
    }
}

pub(crate) fn policy_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let words = positionals(args, &["--owner", "--repo"]);
    match words.first().map(String::as_str) {
        Some("set") => set(args),
        None | Some("show") => match Repo::open(&root) {
            Ok(repo) => show(&repo, args),
            Err(err) => fail_err(&err, &root, "", args),
        },
        Some(other) => {
            eprintln!("未知 policy 动作：{other}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
