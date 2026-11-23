//! `trit-vcs audit`：审计员入口。默认 `audit status`，失败返回非零。
//!
//! 这里不重复实现对账逻辑，只做三件事：打开仓库、调 `trit_vcs::audit`、把结果按
//! “人读的一屏 / `--json` 的机器可分支对象”两种出口打出来。

use std::process::ExitCode;

use trit_vcs::audit::{self, AuditError, AuditReport};
use trit_vcs::repo::Repo;

use crate::cli_fail::CliFail;
use crate::verdict::{fail_err, fail_repo, print_json};
use crate::{flag, has, repo_path};

pub(crate) fn audit_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let sub = args
        .get(1)
        .filter(|value| !value.starts_with("--"))
        .map(String::as_str)
        .unwrap_or("status");
    let repo = match sub {
        "log" | "show" => Repo::open(&root),
        _ => Repo::open_for_audit(&root),
    };
    let repo = match repo {
        Ok(repo) => repo,
        Err(err) => return fail_repo(&err, &root, "", args),
    };
    match sub {
        "status" | "verify" | "reconcile" => status_cmd(&repo, args),
        "log" => log_cmd(&repo, args),
        "show" => show_cmd(&repo, args),
        other => {
            eprintln!(
                "audit 未知子命令：{other}（可用：status / verify / reconcile / log / show）"
            );
            ExitCode::from(2)
        }
    }
}

fn status_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let report = match audit::status(repo) {
        Ok(report) => report,
        Err(err) => return fail_audit(&err, repo, args),
    };
    if has(args, "--json") {
        let code = print_json(audit::json(&report), args);
        return if report.ok { code } else { ExitCode::FAILURE };
    }
    render(&report);
    if report.ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn log_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let kind = args
        .get(2)
        .filter(|value| !value.starts_with("--"))
        .map(String::as_str);
    let from = flag(args, "--from").and_then(|value| value.parse::<u64>().ok());
    let to = flag(args, "--to").and_then(|value| value.parse::<u64>().ok());
    let rows = match audit::log(repo, kind, from, to) {
        Ok(rows) => rows,
        Err(err) => return fail_audit(&err, repo, args),
    };
    if has(args, "--json") {
        return print_json(serde_json::json!(rows), args);
    }
    for row in &rows {
        let seq = row
            .get("seq")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        let kind = row
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("-");
        let at = row
            .get("at_ms")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        println!(
            "{seq:>5}  {kind:<10}  {at}  {}",
            serde_json::to_string(&row.get("payload").cloned().unwrap_or_default())
                .unwrap_or_else(|_| "{}".to_string())
        );
    }
    if rows.is_empty() {
        println!("（没有匹配的事件）");
    }
    ExitCode::SUCCESS
}

fn show_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let Some(target) = args.get(2).filter(|value| !value.starts_with("--")) else {
        eprintln!("audit show 需要事件序号");
        return ExitCode::from(2);
    };
    let Ok(seq) = target.parse::<u64>() else {
        eprintln!("事件序号不是数字：{target}");
        return ExitCode::from(2);
    };
    let event = match audit::show(repo, seq) {
        Ok(event) => event,
        Err(err) => return fail_audit(&err, repo, args),
    };
    let Some(event) = event else {
        eprintln!("没有第 {seq} 条事件");
        return ExitCode::FAILURE;
    };
    if has(args, "--json") {
        return print_json(event, args);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&event).unwrap_or_else(|_| "{}".to_string())
    );
    ExitCode::SUCCESS
}

fn render(report: &AuditReport) {
    println!(
        "审计状态：{}  {}",
        report.level,
        if report.ok { "绿" } else { "红" }
    );
    println!(
        "  链：{}　事件：{} 条　开放操作：{} 个",
        if report.chain_ok { "绿" } else { "红" },
        report.events,
        report.open_ops
    );
    println!("  HEAD：{}", report.head.as_deref().unwrap_or("（空）"));
    if report.refs.is_empty() {
        println!("  refs：（无）");
    } else {
        for (name, id) in &report.refs {
            println!("  ref {name} → {id}");
        }
    }
    println!("  状态摘要：{}", report.state_digest);
    println!("  下一层：{}", report.next_level);
    for issue in &report.issues {
        println!("  [问题] {}：{}", issue.kind, issue.detail);
    }
    for warning in &report.warnings {
        println!("  [提示] {}：{}", warning.kind, warning.detail);
    }
    if report.level == "L1" {
        println!("  说明：L1 只证明链内自洽；要 L2 需要最新事件带 state_after 且对账无问题");
    }
    if report.level == "L2" {
        println!("  说明：L2 已把日志对到当前状态；签名检查点/仓外锚（L3）还没做");
    }
}

fn fail_audit(err: &AuditError, repo: &Repo, args: &[String]) -> ExitCode {
    match err {
        AuditError::Repo(inner) => fail_repo(inner, repo.root(), "", args),
        other => {
            let cli = CliFail::new(
                "audit",
                other.to_string(),
                [
                    "先跑 `trit-vcs verify --repo <仓库>` 确认对象库本身是绿的",
                    "再跑 `trit-vcs audit status --json --repo <仓库>` 看结构化问题",
                ],
            );
            fail_err(&cli, repo.root(), "", args)
        }
    }
}
