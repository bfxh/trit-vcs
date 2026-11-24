//! 独立外锚的 CLI 接线；验锚只使用调用方明确钉住的外部公钥。

use std::path::Path;
use std::process::ExitCode;

use serde_json::Value;
use trit_vcs::checkpoint::external;
use trit_vcs::repo::Repo;

use super::audit_cli::{checkpoint_ref, fail_anchor, write_new_json};
use crate::cli_fail::CliFail;
use crate::verdict::{fail_err, print_json};
use crate::{flag, has, now_ms};

pub(super) fn external_anchor_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let checkpoint = match checkpoint_ref(repo, args, "--checkpoint", "audit external-anchor") {
        Ok(value) => value,
        Err(err) => return fail_err(&err, repo.root(), "", args),
    };
    let Some(key_path) = flag(args, "--key-file").filter(|value| !value.is_empty()) else {
        return fail_err(
            &CliFail::usage(
                "audit external-anchor 需要 --key-file <外部签者私钥>",
                [
                    "trit-vcs audit external-anchor --checkpoint <seq> --key-file <file> --anchor-public-key <hex> --out <file>",
                ],
            ),
            repo.root(),
            "",
            args,
        );
    };
    let Some(public) = flag(args, "--anchor-public-key").filter(|value| !value.is_empty()) else {
        return fail_err(
            &CliFail::usage(
                "audit external-anchor 需要 --anchor-public-key <独立公钥 hex>",
                ["公钥必须来自仓库外的信任渠道；不能从本仓 keys.json 临时推导"],
            ),
            repo.root(),
            "",
            args,
        );
    };
    let Some(out) = flag(args, "--out").filter(|value| !value.is_empty()) else {
        return fail_err(
            &CliFail::usage(
                "audit external-anchor 需要 --out <仓库外文件>",
                [
                    "trit-vcs audit external-anchor --checkpoint <seq> --key-file <file> --anchor-public-key <hex> --out <file>",
                ],
            ),
            repo.root(),
            "",
            args,
        );
    };
    let value = match external::from_checkpoint(
        repo,
        checkpoint.seq,
        Path::new(key_path),
        public,
        now_ms(),
    ) {
        Ok(value) => value,
        Err(err) => return fail_anchor(&err, repo, args),
    };
    let outcome = match external::verify_against_repo(repo, &value, public) {
        Ok(value) => value,
        Err(err) => return fail_anchor(&err, repo, args),
    };
    if let Err(err) = write_new_json(out, &value) {
        return fail_err(&err, repo.root(), "", args);
    }
    if has(args, "--json") {
        return print_json(
            serde_json::to_value(serde_json::json!({
                "ok": true,
                "out": out,
                "anchor": outcome,
            }))
            .unwrap_or(Value::Null),
            args,
        );
    }
    println!(
        "已写独立外锚 {out}：检查点 #{}，前缀 {} 条，root {}",
        checkpoint.seq, outcome.height, outcome.merkle_root
    );
    ExitCode::SUCCESS
}

pub(super) fn verify_external_anchor_cmd(repo: &Repo, args: &[String]) -> ExitCode {
    let Some(path) = flag(args, "--anchor").filter(|value| !value.is_empty()) else {
        return fail_err(
            &CliFail::usage(
                "audit verify-external-anchor 需要 --anchor <仓库外文件>",
                [
                    "trit-vcs audit verify-external-anchor --anchor <file> --anchor-public-key <hex> --json",
                ],
            ),
            repo.root(),
            "",
            args,
        );
    };
    let Some(public) = flag(args, "--anchor-public-key").filter(|value| !value.is_empty()) else {
        return fail_err(
            &CliFail::usage(
                "audit verify-external-anchor 需要 --anchor-public-key <独立公钥 hex>",
                ["验锚只认这里钉住的公钥，不读取仓内信任表"],
            ),
            repo.root(),
            "",
            args,
        );
    };
    let value = match external::load(Path::new(path)) {
        Ok(value) => value,
        Err(err) => return fail_anchor(&err, repo, args),
    };
    let outcome = match external::verify_against_repo(repo, &value, public) {
        Ok(value) => value,
        Err(err) => return fail_anchor(&err, repo, args),
    };
    if has(args, "--json") {
        return print_json(serde_json::to_value(outcome).unwrap_or(Value::Null), args);
    }
    println!(
        "独立外锚有效：检查点 #{}，前缀 {} 条，root {}",
        outcome.checkpoint, outcome.height, outcome.merkle_root
    );
    ExitCode::SUCCESS
}
