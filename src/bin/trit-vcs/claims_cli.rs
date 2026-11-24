//! `claims`：跨仓认领账本的命令行（add / release / list / export）。
//!
//! 账本在**中央仓**里，多个工作树共用；`--claims` 仍接受导出的快照
//! （`claims export` 的产物与账本本身都是同一个 JSON 数组格式）。

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use trit_vcs::claims::{self, NewClaim};

use super::verdict::fail_err;
use super::{fail, flag, flags, has, now_secs, positionals};

const USAGE: &str = "claims 用法：\n  \
     trit-vcs claims add --central PATH --id ID --owner <宿主:会话id> --path P... [--ttl 秒] [--sign-key FILE] [--json]\n  \
     trit-vcs claims release --central PATH --id ID --owner <宿主:会话id> [--sign-key FILE] [--json]\n  \
     trit-vcs claims list --central PATH [--all] [--json]\n  \
     trit-vcs claims export --central PATH --out FILE";

fn central_path(args: &[String]) -> Option<PathBuf> {
    flag(args, "--central").map(PathBuf::from)
}

fn required<'a>(args: &'a [String], name: &str) -> Result<&'a str, ExitCode> {
    flag(args, name).ok_or_else(|| {
        eprintln!("{name} 是必填");
        ExitCode::from(2)
    })
}

fn sign_key_path(args: &[String]) -> Result<Option<&Path>, ExitCode> {
    let Some(index) = args.iter().position(|arg| arg == "--sign-key") else {
        return Ok(None);
    };
    let Some(value) = args.get(index + 1).filter(|value| !value.starts_with("--")) else {
        eprintln!("--sign-key 需要 <私钥文件>");
        return Err(ExitCode::from(2));
    };
    Ok(Some(Path::new(value)))
}

fn print_json(value: &serde_json::Value) -> ExitCode {
    println!(
        "{}",
        serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
    );
    ExitCode::SUCCESS
}

pub(crate) fn claims_cmd(args: &[String]) -> ExitCode {
    let Some(central) = central_path(args) else {
        eprintln!("claims 需要 --central PATH（中央仓目录）");
        return ExitCode::from(2);
    };
    let words = positionals(
        args,
        &[
            "--central",
            "--id",
            "--owner",
            "--path",
            "--ttl",
            "--out",
            "--sign-key",
        ],
    );
    let Some(action) = words.first().map(String::as_str) else {
        eprintln!("{USAGE}");
        return ExitCode::from(2);
    };
    let now = now_secs();
    match action {
        "add" => {
            let id = match required(args, "--id") {
                Ok(value) => value,
                Err(code) => return code,
            };
            let owner = match required(args, "--owner") {
                Ok(value) => value,
                Err(code) => return code,
            };
            let paths = flags(args, "--path");
            if paths.is_empty() {
                eprintln!("claims add 至少要一条 --path");
                return ExitCode::from(2);
            }
            let ttl = match flag(args, "--ttl") {
                Some(raw) => match raw.parse::<u64>() {
                    Ok(value) => value,
                    Err(_) => return fail(format!("--ttl 不是整数：{raw}")),
                },
                None => 900,
            };
            let sign_key = match sign_key_path(args) {
                Ok(path) => path,
                Err(code) => return code,
            };
            let result = match sign_key {
                Some(path) => claims::add_signed(
                    &central,
                    NewClaim {
                        id,
                        owner,
                        paths,
                        ttl_secs: ttl,
                    },
                    Path::new(path),
                    now,
                ),
                None => claims::add(
                    &central,
                    NewClaim {
                        id,
                        owner,
                        paths,
                        ttl_secs: ttl,
                    },
                    now,
                ),
            };
            match result {
                Ok(spec) => {
                    if has(args, "--json") {
                        return print_json(&serde_json::json!({
                            "ok": true,
                            "claim": spec,
                            "remaining_secs": spec.expires_at.saturating_sub(now),
                        }));
                    }
                    println!(
                        "认领已写：{}（{}，{} 条路径，剩 {} 秒；账本 {}）",
                        spec.id,
                        spec.owner,
                        spec.paths.len(),
                        spec.expires_at.saturating_sub(now),
                        claims::ledger_path(&central).display()
                    );
                    ExitCode::SUCCESS
                }
                Err(err) => fail_err(&err, &central, owner, args),
            }
        }
        "release" => {
            let id = match required(args, "--id") {
                Ok(value) => value,
                Err(code) => return code,
            };
            let owner = match required(args, "--owner") {
                Ok(value) => value,
                Err(code) => return code,
            };
            let sign_key = match sign_key_path(args) {
                Ok(path) => path,
                Err(code) => return code,
            };
            let result = match sign_key {
                Some(path) => claims::release_signed(&central, id, owner, path, now),
                None => claims::release(&central, id, owner, now),
            };
            match result {
                Ok(spec) => {
                    if has(args, "--json") {
                        return print_json(&serde_json::json!({"ok": true, "released": spec}));
                    }
                    println!("已释放：{}（{}）", spec.id, spec.owner);
                    ExitCode::SUCCESS
                }
                Err(err) => fail_err(&err, &central, owner, args),
            }
        }
        "list" => match claims::list(&central, now, has(args, "--all")) {
            Ok(claims) => {
                if has(args, "--json") {
                    return print_json(&serde_json::json!({
                        "digest": claims::digest(&claims),
                        "now": now,
                        "claims": claims,
                    }));
                }
                if claims.is_empty() {
                    println!(
                        "（没有{}认领）",
                        if has(args, "--all") { "" } else { "在效" }
                    );
                }
                for spec in &claims {
                    println!(
                        "{}  {}  路径 {} 条  剩 {} 秒{}",
                        spec.id,
                        spec.owner,
                        spec.paths.len(),
                        spec.expires_at.saturating_sub(now),
                        if spec.expires_at <= now {
                            "（已过期）"
                        } else {
                            ""
                        }
                    );
                }
                ExitCode::SUCCESS
            }
            Err(err) => fail_err(&err, &central, "", args),
        },
        "export" => {
            let out = match required(args, "--out") {
                Ok(value) => value,
                Err(code) => return code,
            };
            match claims::export(&central, Path::new(out)) {
                Ok(count) => {
                    println!("已导出 {count} 条认领 → {out}（可直接用于 --claims FILE）");
                    ExitCode::SUCCESS
                }
                Err(err) => fail_err(&err, &central, "", args),
            }
        }
        other => {
            eprintln!("未知 claims 子命令：{other}\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
