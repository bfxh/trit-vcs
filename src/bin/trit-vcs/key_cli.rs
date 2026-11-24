//! `key`：查看信任表，或用受审计方式 add/revoke 一个 key 指纹。
//!
//! 这里管理的是“谁被信任”的元数据，不是签名工具；私钥生成/验签留给后续
//! Ed25519 层。命令仍走写前/写后协议，所以每次信任变更都有可复算的账。

use std::process::ExitCode;

use serde_json::json;
use trit_vcs::keys::TrustEntry;
use trit_vcs::repo::Repo;

use super::verdict::fail_err;
use super::{flag, has, now_secs, positionals, repo_path};

const USAGE: &str = "key 用法：\n  \
     trit-vcs key [list] [--json] [--repo PATH]\n  \
     trit-vcs key add --key-id <指纹> --principal <主体> [--role author|auditor|release|reader] --owner <宿主:会话id> [--json] [--repo PATH]\n  \
     trit-vcs key revoke --key-id <指纹> --reason <原因> --owner <宿主:会话id> [--json] [--repo PATH]";

fn list(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &root, "", args),
    };
    let store = match repo.keys() {
        Ok(store) => store,
        Err(err) => return fail_err(&err, repo.root(), "", args),
    };
    if has(args, "--json") {
        let entries: Vec<&TrustEntry> = store.keys.values().collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"keys": entries}))
                .unwrap_or_else(|_| "{}".to_string())
        );
    } else if store.keys.is_empty() {
        println!("信任表为空");
    } else {
        for entry in store.keys.values() {
            let status = if entry.is_revoked() {
                "revoked"
            } else {
                "trusted"
            };
            println!(
                "{} {} {} {}",
                entry.key_id, status, entry.role, entry.principal
            );
        }
    }
    ExitCode::SUCCESS
}

fn add(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let key_id = flag(args, "--key-id").unwrap_or("");
    let principal = flag(args, "--principal").unwrap_or("");
    let owner = flag(args, "--owner").unwrap_or("");
    let role = flag(args, "--role").unwrap_or("author");
    if key_id.is_empty() || principal.is_empty() || owner.is_empty() {
        eprintln!("key add 需要 --key-id、--principal 和 --owner\n{USAGE}");
        return ExitCode::from(2);
    }
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &root, owner, args),
    };
    let entry = TrustEntry {
        key_id: key_id.to_string(),
        principal: principal.to_string(),
        role: role.to_string(),
        added_at_ms: now_secs() * 1000,
        revoked_at_ms: None,
        revoke_reason: None,
    };
    match repo.add_key(entry, owner, now_secs() * 1000) {
        Ok(hash) => {
            if has(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "add",
                        "key_id": key_id,
                        "principal": principal,
                        "role": role,
                        "keyset": hash.to_hex(),
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("已信任 {}（{}，keyset {}）", key_id, role, hash.short());
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, repo.root(), owner, args),
    }
}

fn revoke(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let key_id = flag(args, "--key-id").unwrap_or("");
    let reason = flag(args, "--reason").unwrap_or("");
    let owner = flag(args, "--owner").unwrap_or("");
    if key_id.is_empty() || reason.is_empty() || owner.is_empty() {
        eprintln!("key revoke 需要 --key-id、--reason 和 --owner\n{USAGE}");
        return ExitCode::from(2);
    }
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &root, owner, args),
    };
    match repo.revoke_key(key_id, reason, owner, now_secs() * 1000) {
        Ok(hash) => {
            if has(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "revoke",
                        "key_id": key_id,
                        "reason": reason,
                        "keyset": hash.to_hex(),
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!("已吊销 {}（keyset {}）", key_id, hash.short());
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, repo.root(), owner, args),
    }
}

pub(crate) fn key_cmd(args: &[String]) -> ExitCode {
    let words = positionals(
        args,
        &[
            "--repo",
            "--key-id",
            "--principal",
            "--role",
            "--owner",
            "--reason",
        ],
    );
    match words.first().map(String::as_str) {
        None | Some("list") => list(args),
        Some("add") => add(args),
        Some("revoke") => revoke(args),
        Some(other) => {
            eprintln!("未知 key 动作：{other}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
