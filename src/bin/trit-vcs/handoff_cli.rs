//! `handoff` / `handoff-verify`：提交 → 自包含包（目录或单文件 `TVHP`）→ 逐项复核。
//!
//! 包是派生物：不手改、不合并；要更新就重新 `handoff`。`--bundle` 出单文件，`verify` 自动识别两种形态。

use std::path::Path;
use std::process::ExitCode;

use trit_vcs::handoff::{self, HandoffError};
use trit_vcs::repo::Repo;

use super::{flag, has, positionals, repo_path};

pub(crate) fn handoff_cmd(args: &[String]) -> Result<ExitCode, HandoffError> {
    let ids = positionals(args, &["--repo", "--out"]);
    let Some(id_text) = ids.first() else {
        return Err(HandoffError::Usage(
            "handoff 需要 <提交id> 和 --out <包目录|FILE.tvhp>".to_string(),
        ));
    };
    let Some(out) = flag(args, "--out") else {
        return Err(HandoffError::Usage(
            "handoff 需要 --out <包目录|FILE.tvhp>（单文件加 --bundle）".to_string(),
        ));
    };
    let Some(commit_id) = trit_vcs::Hash::from_hex(id_text) else {
        return Err(HandoffError::Usage(format!(
            "不是合法提交 id（要 64 位 hex）：{id_text}"
        )));
    };
    let repo = Repo::open(repo_path(args))?;
    let report = if has(args, "--bundle") {
        handoff::build_bundle(&repo, &commit_id, Path::new(out))?
    } else {
        handoff::build(&repo, &commit_id, Path::new(out))?
    };
    println!(
        "交接包 {}：commit {}，{} 个部件，包 id {}",
        report.out.display(),
        report.commit.short(),
        report.components,
        report.package_id.short()
    );
    Ok(ExitCode::SUCCESS)
}

pub(crate) fn verify_cmd(args: &[String]) -> Result<ExitCode, HandoffError> {
    let ids = positionals(args, &["--repo"]);
    let Some(package) = ids.first() else {
        return Err(HandoffError::Usage(
            "handoff-verify 需要 <包目录|FILE.tvhp>".to_string(),
        ));
    };
    let repo = match flag(args, "--repo") {
        Some(_) => Some(Repo::open(repo_path(args))?),
        None => None,
    };
    let report = handoff::verify(Path::new(package), repo.as_ref())?;
    println!(
        "OK 交接包 {}：commit {}，{} 个部件，{} 个被引用对象，包 id {}",
        package,
        report.commit.short(),
        report.components,
        report.objects,
        report.package_id.short()
    );
    Ok(ExitCode::SUCCESS)
}
