//! `policy`：查看当前门禁策略，或用受审计的方式整份替换它。
//!
//! `policy set` 的语义是“本次参数就是完整策略”：没带的开关一律归 false，
//! 不沿用旧 true。这样一次命令就能复现“谁在什么时候把哪项打开/关掉”。

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;
use trit_vcs::repo::{Policy, Repo};

use super::verdict::fail_err;
use super::{flag, flags, has, now_secs, positionals, repo_path};

const USAGE: &str = "policy 用法：\n  \
     trit-vcs policy [--json] [--repo PATH]\n  \
     trit-vcs policy set --owner <宿主:会话id> [--require-witness] [--require-intent] [--require-signed-claims] [--require-signed-witness] [--require-signed-policy] [--policy-threshold N] [--policy-role auditor|release]... [--policy-principal-quorum] [--sign-key FILE]... [--json] [--repo PATH]";

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
                "require_signed_witness": policy.require_signed_witness,
                "require_signed_policy": policy.require_signed_policy,
                "policy_threshold": policy.policy_threshold,
                "policy_roles": policy.policy_roles,
                "policy_principal_quorum": policy.policy_principal_quorum,
            }))
            .unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("require_witness={}", policy.require_witness);
        println!("require_intent={}", policy.require_intent);
        println!("require_signed_claims={}", policy.require_signed_claims);
        println!("require_signed_witness={}", policy.require_signed_witness);
        println!("require_signed_policy={}", policy.require_signed_policy);
        println!("policy_threshold={}", policy.policy_threshold);
        println!("policy_roles={}", policy.policy_roles.join(","));
        println!("policy_principal_quorum={}", policy.policy_principal_quorum);
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
    let threshold = match flag(args, "--policy-threshold")
        .unwrap_or("1")
        .parse::<u8>()
    {
        Ok(value) if (1..=trit_vcs::repo::MAX_POLICY_THRESHOLD).contains(&value) => value,
        Ok(value) => {
            eprintln!(
                "policy_threshold 必须在 1..={}；收到 {value}",
                trit_vcs::repo::MAX_POLICY_THRESHOLD
            );
            return ExitCode::from(2);
        }
        Err(_) => {
            eprintln!(
                "--policy-threshold 需要 1..={} 的整数",
                trit_vcs::repo::MAX_POLICY_THRESHOLD
            );
            return ExitCode::from(2);
        }
    };
    let mut roles = flags(args, "--policy-role");
    if roles.is_empty() {
        roles.push("auditor".to_string());
    }
    let roles = match trit_vcs::repo::normalize_policy_roles(&roles) {
        Ok(roles) => roles,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };
    let policy = Policy {
        require_witness: has(args, "--require-witness"),
        require_intent: has(args, "--require-intent"),
        require_signed_claims: has(args, "--require-signed-claims"),
        require_signed_witness: has(args, "--require-signed-witness"),
        require_signed_policy: has(args, "--require-signed-policy"),
        policy_threshold: threshold,
        policy_roles: roles.clone(),
        policy_principal_quorum: has(args, "--policy-principal-quorum"),
    };
    let signer_paths = flags(args, "--sign-key")
        .into_iter()
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let signers = signer_paths.iter().map(Path::new).collect::<Vec<_>>();
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &root, owner, args),
    };
    match repo.set_policy_with_signers(&policy, owner, now_secs() * 1000, &signers) {
        Ok(hash) => {
            if has(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "require_witness": policy.require_witness,
                        "require_intent": policy.require_intent,
                        "require_signed_claims": policy.require_signed_claims,
                        "require_signed_witness": policy.require_signed_witness,
                        "require_signed_policy": policy.require_signed_policy,
                        "policy_threshold": policy.policy_threshold,
                        "policy_roles": policy.policy_roles,
                        "policy_principal_quorum": policy.policy_principal_quorum,
                        "signed": !signers.is_empty(),
                        "signer_count": signers.len(),
                        "policy": hash.to_hex(),
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "策略已更新：require_witness={} require_intent={} require_signed_claims={} require_signed_witness={} require_signed_policy={} policy_threshold={} policy_roles={} policy_principal_quorum={}（policy {}{}）",
                    policy.require_witness,
                    policy.require_intent,
                    policy.require_signed_claims,
                    policy.require_signed_witness,
                    policy.require_signed_policy,
                    policy.policy_threshold,
                    policy.policy_roles.join(","),
                    policy.policy_principal_quorum,
                    hash.short(),
                    if signers.is_empty() {
                        ""
                    } else if signers.len() == 1 {
                        "，已签名"
                    } else {
                        "，已多签"
                    }
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, repo.root(), owner, args),
    }
}

pub(crate) fn policy_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let words = positionals(
        args,
        &[
            "--owner",
            "--repo",
            "--sign-key",
            "--policy-threshold",
            "--policy-role",
        ],
    );
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
