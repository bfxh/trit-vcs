//! TVAB 审计包 CLI：导出要求末端独立外锚，验证不打开仓库、不访问网络。

use std::path::Path;
use std::process::ExitCode;

use serde_json::{Value, json};
use trit_vcs::audit_bundle::{self, BundleReport};

use crate::cli_fail::CliFail;
use crate::verdict::{fail_err, print_json};
use crate::{flag, has, positionals, repo_path};

pub(super) fn bundle_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let Some(out) = flag(args, "--out").filter(|value| !value.is_empty()) else {
        return usage(
            "audit bundle 需要 --out <新文件>",
            "trit-vcs audit bundle --out repo.audit.tvab --anchor external-anchor.json --anchor-public-key <hex> --json",
            &root,
            args,
        );
    };
    let Some(anchor_path) = flag(args, "--anchor").filter(|value| !value.is_empty()) else {
        return usage(
            "audit bundle 需要 --anchor <独立外锚文件>",
            "trit-vcs audit bundle --out repo.audit.tvab --anchor external-anchor.json --anchor-public-key <hex> --json",
            &root,
            args,
        );
    };
    let Some(public) = flag(args, "--anchor-public-key").filter(|value| !value.is_empty()) else {
        return usage(
            "audit bundle 需要 --anchor-public-key <仓外公钥 hex>",
            "公钥必须来自仓库外的独立渠道，不能从包内或仓内 keys.json 推导",
            &root,
            args,
        );
    };
    let anchor = match audit_bundle::load_anchor(Path::new(anchor_path)) {
        Ok(value) => value,
        Err(err) => return fail_err(&err, &root, "", args),
    };
    match audit_bundle::export(&root, &anchor, public, Path::new(out)) {
        Ok(report) => {
            if has(args, "--json") {
                let mut value = match report_value(&report) {
                    Ok(value) => value,
                    Err(err) => return fail_err(&err, &root, "", args),
                };
                value["out"] = json!(out);
                print_json(value, args)
            } else {
                println!(
                    "已写离线审计包 {out}：{} 条事件 / {} 个对象 / {} 字节，外锚覆盖 {} 条",
                    report.events, report.objects, report.bytes, report.anchor.height
                );
                ExitCode::SUCCESS
            }
        }
        Err(err) => fail_err(&err, &root, "", args),
    }
}

pub(super) fn verify_bundle_cmd(args: &[String]) -> ExitCode {
    let root = repo_path(args);
    let positionals = positionals(args, &["--anchor-public-key", "--repo", "--budget"]);
    let Some(path) = positionals.get(1).filter(|value| !value.is_empty()) else {
        return usage(
            "audit verify-bundle 需要 <TVAB 文件>",
            "trit-vcs audit verify-bundle repo.audit.tvab --anchor-public-key <hex> --offline --json",
            &root,
            args,
        );
    };
    let Some(public) = flag(args, "--anchor-public-key").filter(|value| !value.is_empty()) else {
        return usage(
            "audit verify-bundle 需要 --anchor-public-key <仓外公钥 hex>",
            "验包只认这里钉住的公钥，不读取包内或仓内 keys.json",
            &root,
            args,
        );
    };
    match audit_bundle::verify_file(Path::new(path), public) {
        Ok(report) => {
            if has(args, "--json") {
                let value = match report_value(&report) {
                    Ok(value) => value,
                    Err(err) => return fail_err(&err, &root, "", args),
                };
                print_json(value, args)
            } else {
                println!(
                    "离线审计包有效：{} 条事件 / {} 个对象 / {} 字节，检查点 #{}，root {}",
                    report.events,
                    report.objects,
                    report.bytes,
                    report.anchor.checkpoint,
                    report.anchor.merkle_root
                );
                ExitCode::SUCCESS
            }
        }
        Err(err) => fail_err(&err, &root, "", args),
    }
}

fn report_value(report: &BundleReport) -> Result<Value, CliFail> {
    let mut value = serde_json::to_value(report).map_err(|err| {
        CliFail::new(
            "audit_bundle_bad",
            format!("审计包报告序列化失败：{err}"),
            ["重试命令；仍失败时报告 CLI 版本与 JSON 输出"],
        )
    })?;
    value["offline"] = json!(true);
    Ok(value)
}

fn usage(message: &str, next: &str, root: &Path, args: &[String]) -> ExitCode {
    fail_err(&CliFail::usage(message, [next.to_string()]), root, "", args)
}
