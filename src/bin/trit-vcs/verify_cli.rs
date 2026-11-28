//! 顶层 `verify`：对象/提交体检 + 审计对账，两个都绿才算绿。

use std::process::ExitCode;

use trit_vcs::audit;
use trit_vcs::repo::Repo;

use crate::cli_fail::CliFail;
use crate::verdict::{fail_err, fail_repo, print_json};
use crate::{has, repo_path};

pub(crate) fn verify_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    // 用审计入口打开：日志缺失/损坏不能在这里先报 io 错，否则 `verify` 只能
    // 看到“对象库没问题”，又把 `journal_missing` 留给了另一条命令。
    let repo = match Repo::open_for_audit(&root) {
        Ok(repo) => repo,
        Err(err) => return fail_repo(&err, &root, "", args),
    };
    let report = match repo.verify() {
        Ok(report) => report,
        Err(err) => return fail_err(&err, &root, "", args),
    };
    let audit_report = match audit::status(&repo) {
        Ok(report) => report,
        Err(err) => {
            let fail = CliFail::new(
                "verify_audit",
                format!("对象与提交检查通过，但审计对账读不出来：{err}"),
                ["trit-vcs audit status --json", "trit-vcs audit log --json"],
            );
            return fail_err(&fail, &root, "", args);
        }
    };
    let mut failures = audit_report
        .issues
        .iter()
        .map(|issue| format!("{}：{}", issue.kind, issue.detail))
        .collect::<Vec<_>>();
    if audit_report.open_ops > 0 {
        failures.push(format!(
            "open_ops：{} 个操作只有 op_begin、没有 op_result",
            audit_report.open_ops
        ));
    }
    if !audit_report.ok || !failures.is_empty() {
        let details = failures.join("；");
        let fail = CliFail::new(
            "verify_audit",
            format!("对象与提交检查通过，但日志对账失败：{details}"),
            ["trit-vcs audit status --json", "trit-vcs audit log --json"],
        );
        return fail_err(&fail, &root, "", args);
    }
    if has(args, "--json") {
        return print_json(
            serde_json::json!({
                "ok": true,
                "verify": {
                    "events": report.events,
                    "objects": report.objects,
                    "commits": report.commits,
                    "witnessed": report.witnessed,
                    "claim_sets": report.claim_sets,
                    "receipts": report.receipts,
                    "head": report.head,
                },
                "audit": audit::json(&audit_report),
            }),
            args,
        );
    }
    println!(
        "绿：事件 {} 条，对象 {} 个，提交 {} 条（带见证 {} 条，带认领快照 {} 条，判据回执 {} 条），HEAD {}；审计对账通过（开放操作 {} 个）",
        report.events,
        report.objects,
        report.commits,
        report.witnessed,
        report.claim_sets,
        report.receipts,
        report.head.unwrap_or_else(|| "-".to_string()),
        audit_report.open_ops
    );
    ExitCode::SUCCESS
}
