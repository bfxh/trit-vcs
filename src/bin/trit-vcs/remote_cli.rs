//! 网络命令：`serve`（中央仓 + token）、`publish/pull --remote`。
//!
//! token 只从 `--token-file` 或 `TRIT_VCS_TOKEN` 来，**不进 argv**：argv 会进进程列表、
//! shell 历史和日志，等于把凭据写在公告板上。

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use trit_vcs::net::{Client, Config, Server};
use trit_vcs::remote::{self, RemoteError};
use trit_vcs::repo::Repo;
use trit_vcs::view;

use super::verdict::fail_err;
use super::{fail, flag, has, positionals, repo_path};

const DEFAULT_BIND: &str = "127.0.0.1:7878";

fn read_token(args: &[String]) -> Result<String, ExitCode> {
    let raw = if let Some(path) = flag(args, "--token-file") {
        match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("读不到 token 文件 {path}：{err}");
                return Err(ExitCode::from(2));
            }
        }
    } else if let Ok(text) = std::env::var("TRIT_VCS_TOKEN") {
        text
    } else {
        eprintln!("需要 --token-file FILE（或环境变量 TRIT_VCS_TOKEN）：token 不进 argv");
        return Err(ExitCode::from(2));
    };
    let token = raw.trim().to_string();
    if token.len() < 16 {
        eprintln!("token 至少 16 字节（现在是 {} 字节）", token.len());
        return Err(ExitCode::from(2));
    }
    Ok(token)
}

pub(crate) fn serve_cmd(args: &[String]) -> ExitCode {
    let Some(dir) = flag(args, "--dir") else {
        eprintln!("serve 需要 --dir PATH（中央仓目录）");
        return ExitCode::from(2);
    };
    let token = match read_token(args) {
        Ok(token) => token,
        Err(code) => return code,
    };
    let bind = flag(args, "--bind").unwrap_or(DEFAULT_BIND);
    let mut config = Config::new(PathBuf::from(dir), bind, token);
    if let Some(actor) = flag(args, "--actor") {
        config.actor = Some(actor.to_string());
    }
    if let Some(raw) = flag(args, "--max-body-mb") {
        match raw.parse::<u64>() {
            Ok(mb) if mb > 0 => config.max_body = mb * 1024 * 1024,
            _ => return fail(format!("--max-body-mb 要 ≥1：{raw}")),
        }
    }
    if let Some(raw) = flag(args, "--max-object-mb") {
        match raw.parse::<usize>() {
            Ok(mb) if mb > 0 => config.limits.max_object = mb * 1024 * 1024,
            _ => return fail(format!("--max-object-mb 要 ≥1：{raw}")),
        }
    }
    if let Some(raw) = flag(args, "--max-conn") {
        match raw.parse::<usize>() {
            Ok(count) if count > 0 => config.max_connections = count,
            _ => return fail(format!("--max-conn 要 ≥1：{raw}")),
        }
    }
    if let Some(raw) = flag(args, "--read-timeout") {
        match raw.parse::<u64>() {
            Ok(secs) if secs > 0 => config.read_timeout = Duration::from_secs(secs),
            _ => return fail(format!("--read-timeout 要 ≥1 秒：{raw}")),
        }
    }
    match Server::start(config) {
        Ok(server) => {
            println!(
                "trit-vcs serve：http://{}（中央仓 {}，token 已设，Ctrl-C 停）",
                server.addr(),
                dir
            );
            println!("  边界：明文 HTTP、无 TLS；跨机请套 SSH 隧道/反代。网络不开放 force。");
            loop {
                std::thread::sleep(Duration::from_secs(3600));
            }
        }
        Err(err) => fail_err(&RemoteError::from(err), std::path::Path::new(dir), "", args),
    }
}

pub(crate) fn remote_publish(args: &[String], name: &str) -> ExitCode {
    if has(args, "--force") {
        return fail("网络不开放 --force：快进只进不退，改写历史只能在中央仓本地做");
    }
    let Some(remote_url) = flag(args, "--remote") else {
        unreachable!("调用方只在 --remote 时进来");
    };
    let token = match read_token(args) {
        Ok(token) => token,
        Err(code) => return code,
    };
    let mut client = match Repo::open(repo_path(args)) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &repo_path(args), "", args),
    };
    let commit = match flag(args, "--commit") {
        Some(hex) => match trit_vcs::Hash::from_hex(hex) {
            Some(id) => Some(id),
            None => return fail(format!("不是合法提交 id：{hex}")),
        },
        None => None,
    };
    let pin_enabled = !has(args, "--no-pin");
    match remote::publish_to_with(
        remote_url,
        &token,
        &mut client,
        name,
        commit.as_ref(),
        pin_enabled,
    ) {
        Ok(stats) => {
            println!(
                "已发布 {} → {remote_url} 的 ref {name}（{} 个对象，字节 {}）",
                stats
                    .commit
                    .map(|id| id.short())
                    .unwrap_or_else(|| "-".to_string()),
                stats.objects,
                stats.bytes
            );
            println!(
                "  关联 op_id {}，request_id {}",
                stats.op_id, stats.request_id
            );
            if let Some(view) = &stats.view {
                println!(
                    "  服务端视图：{} 条事件，根 {}，pin {}",
                    view.height,
                    view.root.short(),
                    stats
                        .pin_status
                        .map(|status| status.as_str())
                        .unwrap_or("unknown")
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, client.root(), "", args),
    }
}

pub(crate) fn remote_pull(args: &[String], name: &str) -> ExitCode {
    let Some(remote_url) = flag(args, "--remote") else {
        unreachable!("调用方只在 --remote 时进来");
    };
    let token = match read_token(args) {
        Ok(token) => token,
        Err(code) => return code,
    };
    let mut client = match Repo::open(repo_path(args)) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &repo_path(args), "", args),
    };
    let prefix = flag(args, "--prefix");
    let pin_enabled = !has(args, "--no-pin");
    match remote::pull_from_with(
        remote_url,
        &token,
        &mut client,
        name,
        prefix,
        has(args, "--force"),
        pin_enabled,
    ) {
        Ok(stats) => {
            println!(
                "已从 {remote_url} 拉取 ref {name}（提交 {}）：对象 {}，物化 {} 个文件",
                stats
                    .commit
                    .map(|id| id.short())
                    .unwrap_or_else(|| "-".to_string()),
                stats.objects,
                stats.written
            );
            println!(
                "  关联 op_id {}，request_id {}",
                stats.op_id, stats.request_id
            );
            if let Some(view) = &stats.view {
                println!(
                    "  服务端视图：{} 条事件，根 {}，pin {}",
                    view.height,
                    view.root.short(),
                    stats
                        .pin_status
                        .map(|status| status.as_str())
                        .unwrap_or("unknown")
                );
            }
            if prefix.is_none() {
                println!("  HEAD 与索引已落到该提交（status 从这里开始算）。");
            } else {
                println!("  前缀 pull 不擅动 HEAD：范围外的文件不会被算成删除。");
            }
            ExitCode::SUCCESS
        }
        Err(err) => fail_err(&err, client.root(), "", args),
    }
}

/// `view`：只读服务端视图，并与本地 pin 对账；不改工作树、不更新 pin。
pub(crate) fn view_cmd(args: &[String]) -> ExitCode {
    let ids = positionals(args, &["--repo", "--remote", "--token-file"]);
    let Some(name) = ids.first() else {
        eprintln!(
            "view 需要 ref 名：trit-vcs view main --remote http://host:port --token-file FILE"
        );
        return ExitCode::from(2);
    };
    let Some(remote_url) = flag(args, "--remote") else {
        eprintln!("view 需要 --remote http://host:port");
        return ExitCode::from(2);
    };
    let token = match read_token(args) {
        Ok(token) => token,
        Err(code) => return code,
    };
    let repo = match Repo::open(repo_path(args)) {
        Ok(repo) => repo,
        Err(err) => return fail_err(&err, &repo_path(args), "", args),
    };
    let client = match Client::new(remote_url, &token) {
        Ok(client) => client,
        Err(err) => return fail_err(&RemoteError::from(err), repo.root(), "", args),
    };
    let pin = match view::latest_pin(&repo, client.base(), name) {
        Ok(pin) => pin,
        Err(err) => return fail_err(&RemoteError::from(err), repo.root(), "", args),
    };
    let reply = match client.view(name, pin.as_ref().map(|pin| (pin.height, pin.root))) {
        Ok(reply) => reply,
        Err(err) => return fail_err(&RemoteError::from(err), repo.root(), "", args),
    };
    let status = match view::verify_pin(pin.as_ref(), &reply.snapshot, reply.consistency.as_ref()) {
        Ok(status) => status,
        Err(err) => {
            if has(args, "--json") {
                println!(
                    "{}",
                    serde_json::json!({
                        "ok": false,
                        "kind": err.kind(),
                        "message": err.to_string(),
                        "pin": pin.as_ref().map(view::Pin::to_json),
                        "view": reply.snapshot.to_json(),
                    })
                );
            }
            return fail_err(&RemoteError::from(err), repo.root(), "", args);
        }
    };
    if has(args, "--json") {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "remote": client.base(),
                "ref": name,
                "view": reply.snapshot.to_json(),
                "pin_before": pin.as_ref().map(view::Pin::to_json),
                "pin_status": status.as_str(),
                "request_id": reply.request_id,
            })
        );
    } else {
        println!(
            "服务端 {remote_url} 的 ref {name}：tip {}，{} 条事件，根 {}",
            reply
                .snapshot
                .tip
                .map(|id| id.short())
                .unwrap_or_else(|| "-".to_string()),
            reply.snapshot.height,
            reply.snapshot.root.short()
        );
        match &pin {
            Some(pin) => println!(
                "  本地 pin：{} 条事件，根 {}；对账 {}",
                pin.height,
                pin.root.short(),
                status.as_str()
            ),
            None => println!("  本地还没有 pin：这是首次信任（TOFU），成功后才会记进 journal"),
        }
    }
    ExitCode::SUCCESS
}
