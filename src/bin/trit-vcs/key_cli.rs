//! `key`：生成 Ed25519 密钥、查看信任表、受审计 add/revoke 和查看公钥指纹。
//!
//! 私钥文件由 `key init` 生成；`key add --key-file` 只把公钥和指纹写进信任表；
//! 签名由 `commit --sign-key` 触发，信任表本身仍走写前/写后协议。

use std::path::Path;
use std::process::ExitCode;

use serde_json::json;
use trit_vcs::keys::TrustEntry;
use trit_vcs::repo::Repo;
use trit_vcs::signing::KeyFile;

use super::verdict::fail_err;
use super::{flag, has, now_secs, positionals, repo_path};

const USAGE: &str = "key 用法：\n  \
     trit-vcs key [list] [--json] [--repo PATH]\n  \
     trit-vcs key init --out <私钥文件> [--json]\n  \
     trit-vcs key add --key-id <指纹> --principal <主体> [--role author|auditor|release|reader] --owner <宿主:会话id> [--json] [--repo PATH]\n  \
     trit-vcs key add --key-file <私钥文件> --principal <主体> [--role ...] --owner <宿主:会话id> [--json] [--repo PATH]\n  \
     trit-vcs key revoke --key-id <指纹> --reason <原因> --owner <宿主:会话id> [--json] [--repo PATH]\n  \
     trit-vcs key rotate --old-key-file <旧私钥> --new-key-file <新私钥> --reason <原因> --owner <宿主:会话id> [--json] [--repo PATH]";

fn init(args: &[String]) -> ExitCode {
    let Some(path) = flag(args, "--out") else {
        eprintln!("key init 需要 --out <私钥文件>\n{USAGE}");
        return ExitCode::from(2);
    };
    let key = match KeyFile::generate() {
        Ok(key) => key,
        Err(err) => {
            eprintln!("生成密钥失败：{err}");
            return ExitCode::from(1);
        }
    };
    if let Err(err) = key.save_new(Path::new(path)) {
        eprintln!("写密钥文件失败：{err}");
        return ExitCode::from(1);
    }
    if has(args, "--json") {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "schema": key.schema,
                "key_id": key.key_id,
                "public": key.public,
                "out": path,
            }))
            .unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("已生成 {}（公钥 {}）", key.key_id, key.public);
        println!("私钥文件：{path}（不要提交进仓库）");
    }
    ExitCode::SUCCESS
}

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
    let mut key_id = flag(args, "--key-id").unwrap_or("").to_string();
    let principal = flag(args, "--principal").unwrap_or("");
    let owner = flag(args, "--owner").unwrap_or("");
    let role = flag(args, "--role").unwrap_or("author");
    let key_path = flag(args, "--key-file");
    let mut public_key = None;
    if let Some(path) = key_path {
        let key = match KeyFile::load(Path::new(path)) {
            Ok(key) => key,
            Err(err) => return fail_err(&err, &root, owner, args),
        };
        if !key_id.is_empty() && key_id != key.key_id {
            eprintln!("--key-id 与 --key-file 的指纹不一致");
            return ExitCode::from(2);
        }
        key_id = key.key_id;
        public_key = Some(key.public);
    }
    if key_id.is_empty() || principal.is_empty() || owner.is_empty() {
        eprintln!("key add 需要 --key-id 或 --key-file，以及 --principal 和 --owner\n{USAGE}");
        return ExitCode::from(2);
    }
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &root, owner, args),
    };
    let entry = TrustEntry {
        key_id: key_id.clone(),
        principal: principal.to_string(),
        role: role.to_string(),
        added_at_ms: now_secs() * 1000,
        public_key,
        rotated_from: None,
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

fn rotate(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let old_path = flag(args, "--old-key-file").unwrap_or("");
    let new_path = flag(args, "--new-key-file").unwrap_or("");
    let reason = flag(args, "--reason").unwrap_or("");
    let owner = flag(args, "--owner").unwrap_or("");
    if old_path.is_empty() || new_path.is_empty() || reason.is_empty() || owner.is_empty() {
        eprintln!("key rotate 需要 --old-key-file、--new-key-file、--reason 和 --owner\n{USAGE}");
        return ExitCode::from(2);
    }
    let old_key = match KeyFile::load(Path::new(old_path)) {
        Ok(key) => key,
        Err(err) => return fail_err(&err, &root, owner, args),
    };
    let new_key = match KeyFile::load(Path::new(new_path)) {
        Ok(key) => key,
        Err(err) => return fail_err(&err, &root, owner, args),
    };
    if old_key.key_id == new_key.key_id {
        eprintln!("旧钥和新钥是同一个 key_id；轮换要求新生成的 key");
        return ExitCode::from(2);
    }
    let mut repo = match Repo::open(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &root, owner, args),
    };
    let at_ms = now_secs() * 1000;
    match repo.rotate_key(&old_key, &new_key, reason, owner, at_ms) {
        Ok(hash) => {
            if has(args, "--json") {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "action": "rotate",
                        "old_key_id": old_key.key_id,
                        "key_id": new_key.key_id,
                        "reason": reason,
                        "keyset": hash.to_hex(),
                    }))
                    .unwrap_or_else(|_| "{}".to_string())
                );
            } else {
                println!(
                    "已轮换 {} -> {}（keyset {}）",
                    old_key.key_id,
                    new_key.key_id,
                    hash.short()
                );
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
            "--key-file",
            "--out",
            "--principal",
            "--role",
            "--owner",
            "--reason",
            "--old-key-file",
            "--new-key-file",
        ],
    );
    match words.first().map(String::as_str) {
        None | Some("list") => list(args),
        Some("init") => init(args),
        Some("add") => add(args),
        Some("revoke") => revoke(args),
        Some("rotate") => rotate(args),
        Some(other) => {
            eprintln!("未知 key 动作：{other}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
