//! 网络命令：`serve`（中央仓 + token）、`publish/pull --remote`。
//!
//! token 只从 `--token-file` 或 `TRIT_VCS_TOKEN` 来，**不进 argv**：argv 会进进程列表、
//! shell 历史和日志，等于把凭据写在公告板上。

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use trit_vcs::net::{Client, Config, Server, TokenBinding};
use trit_vcs::remote::{self, RemoteError};
use trit_vcs::repo::Repo;
use trit_vcs::view;

use super::verdict::fail_err;
use super::{fail, flag, has, positionals, repo_path};

const DEFAULT_BIND: &str = "127.0.0.1:7878";
const MAX_TOKENS: usize = 256;

fn token_source(args: &[String]) -> Result<String, ExitCode> {
    if let Some(path) = flag(args, "--token-file") {
        match std::fs::read_to_string(path) {
            Ok(text) => Ok(text),
            Err(err) => {
                eprintln!("读不到 token 文件 {path}：{err}");
                Err(ExitCode::from(2))
            }
        }
    } else if let Ok(text) = std::env::var("TRIT_VCS_TOKEN") {
        Ok(text)
    } else {
        eprintln!("需要 --token-file FILE（或环境变量 TRIT_VCS_TOKEN）：token 不进 argv");
        Err(ExitCode::from(2))
    }
}

/// 每行 `<token> [actor]`；`#` 开头与空行跳过。客户端仍只接受单条。
fn parse_token_bindings(raw: &str) -> Result<Vec<TokenBinding>, String> {
    let mut bindings = Vec::new();
    let mut seen = BTreeSet::new();
    for (index, line) in raw.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut fields = line.split_whitespace();
        let token = fields
            .next()
            .ok_or_else(|| format!("第 {} 行缺 token", index + 1))?;
        let actor = fields.next();
        if fields.next().is_some() {
            return Err(format!(
                "第 {} 行字段过多：只接受 `<token> [actor]`",
                index + 1
            ));
        }
        if token.len() < 16 || token.len() > 256 {
            return Err(format!("第 {} 行 token 长度必须 16–256 字节", index + 1));
        }
        if token.chars().any(|ch| ch.is_control()) {
            return Err(format!("第 {} 行 token 不能含控制字符", index + 1));
        }
        if let Some(actor) = actor
            && (actor.is_empty() || actor.len() > 128 || actor.chars().any(|ch| ch.is_control()))
        {
            return Err(format!(
                "第 {} 行 actor 必须 1–128 字节且不能含控制字符",
                index + 1
            ));
        }
        if !seen.insert(token.to_string()) {
            return Err(format!("第 {} 行 token 重复", index + 1));
        }
        if bindings.len() == MAX_TOKENS {
            return Err(format!("token 条目至多 {MAX_TOKENS} 条"));
        }
        bindings.push(TokenBinding {
            token: token.to_string(),
            actor: actor.map(str::to_string),
        });
    }
    if bindings.is_empty() {
        return Err("token 文件里没有有效条目".to_string());
    }
    Ok(bindings)
}

fn read_token(args: &[String]) -> Result<String, ExitCode> {
    let raw = token_source(args)?;
    let bindings = match parse_token_bindings(&raw) {
        Ok(bindings) => bindings,
        Err(err) => {
            eprintln!("token 文件不合法：{err}");
            return Err(ExitCode::from(2));
        }
    };
    if bindings.len() != 1 {
        eprintln!(
            "客户端只接受单 token；这个文件有 {} 条。服务端多 token 文件请给客户端单独一行。",
            bindings.len()
        );
        return Err(ExitCode::from(2));
    }
    Ok(bindings.into_iter().next().expect("至少一条").token)
}

fn read_token_bindings(args: &[String]) -> Result<Vec<TokenBinding>, ExitCode> {
    let raw = token_source(args)?;
    parse_token_bindings(&raw).map_err(|err| {
        eprintln!("token 文件不合法：{err}");
        ExitCode::from(2)
    })
}

pub(crate) fn serve_cmd(args: &[String]) -> ExitCode {
    let Some(dir) = flag(args, "--dir") else {
        eprintln!("serve 需要 --dir PATH（中央仓目录）");
        return ExitCode::from(2);
    };
    let bindings = match read_token_bindings(args) {
        Ok(bindings) => bindings,
        Err(code) => return code,
    };
    let bind = flag(args, "--bind").unwrap_or(DEFAULT_BIND);
    let primary = bindings[0].token.clone();
    let mut config = Config::new(PathBuf::from(dir), bind, primary);
    config.tokens = bindings;
    if let Some(actor) = flag(args, "--actor") {
        config.actor = Some(actor.to_string());
    }
    if let Some(path) = flag(args, "--view-key") {
        config.view_key_path = Some(PathBuf::from(path));
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
                match &stats.view_signer {
                    Some(signer) => println!("  视图签名：{signer}"),
                    None => println!("  视图没有签名（服务端未配置 --view-key）"),
                }
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
                match &stats.view_signer {
                    Some(signer) => println!("  视图签名：{signer}"),
                    None => println!("  视图没有签名（服务端未配置 --view-key）"),
                }
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
    let ids = positionals(
        args,
        &["--repo", "--remote", "--token-file", "--expect-view-key"],
    );
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
    let status = match view::verify_view_signature(
        pin.as_ref(),
        name,
        &reply.snapshot,
        reply.signature.as_ref(),
    ) {
        Ok(()) => match view::verify_pin(pin.as_ref(), &reply.snapshot, reply.consistency.as_ref())
        {
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
                            "signature": reply.signature.as_ref().map(view::ViewSignature::to_json),
                        })
                    );
                }
                return fail_err(&RemoteError::from(err), repo.root(), "", args);
            }
        },
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
                        "signature": reply.signature.as_ref().map(view::ViewSignature::to_json),
                    })
                );
            }
            return fail_err(&RemoteError::from(err), repo.root(), "", args);
        }
    };
    if let Some(expected) = flag(args, "--expect-view-key") {
        let actual = reply.signature.as_ref().map(|sig| sig.key_id.as_str());
        if actual != Some(expected) {
            return fail(format!(
                "服务端视图签名者是 {:?}，不是 --expect-view-key 要求 {expected}",
                actual.unwrap_or("未签名")
            ));
        }
    }
    if has(args, "--json") {
        println!(
            "{}",
            serde_json::json!({
                "ok": true,
                "remote": client.base(),
                "ref": name,
                "view": reply.snapshot.to_json(),
                "pin_before": pin.as_ref().map(view::Pin::to_json),
                "signature": reply.signature.as_ref().map(view::ViewSignature::to_json),
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
        match &reply.signature {
            Some(signature) => println!("  服务端签名：{}", signature.key_id),
            None => println!("  服务端没有签名：只能按单客户端 pin 对账，不能证明签名者身份"),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_file_grammar_ignores_comments_and_rejects_bad_lines() {
        let parsed =
            parse_token_bindings("# 服务端 token 表\n\n0123456789abcdef alice\nfedcba9876543210\n")
                .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].actor.as_deref(), Some("alice"));
        assert!(parsed[1].actor.is_none());

        for bad in [
            "0123456789abcdef alice extra\n",
            "0123456789abcdef\n0123456789abcdef bob\n",
            "short\n",
            "# 只有注释\n",
        ] {
            assert!(parse_token_bindings(bad).is_err(), "应拒绝：{bad}");
        }
    }
}
