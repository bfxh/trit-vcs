//! `--verify-accept` 的接线：只有显式开这个开关才执行提交里记的判据命令。
//!
//! 三条硬前置（缺一条就不许跑，宁可判红也不猜）：
//!  1. 默认关：不带 `--verify-accept` 时零执行（连 `--claims` 都不要求）。
//!  2. 要 `--claims FILE`：跑之前先确认"这次改动落在在效认领里"（`gate::check` 判 `Allowed`）；
//!     认领以外的改动 ⇒ 说明这条命令可能来自别人，拒绝执行。
//!  3. 命令形状由 `trit_vcs::accept` 把关：argv、无 shell 元字符、超时、输出截断与密钥打码。
//!
//! 为什么认领面是安全边界：`pull` / `import` 进来的提交带着别人的 accept，
//! "能跑"不等于"该跑"——认领是仓里唯一说清"这段路径此刻归谁动"的判据。

use std::time::Duration;

use trit_vcs::Hash;
use trit_vcs::accept;
use trit_vcs::gate::{self, load_claims};
use trit_vcs::model::Intent;
use trit_vcs::repo::Repo;

use super::cli_fail::CliFail;
use super::{flag, has};

pub(crate) fn enabled(args: &[String]) -> bool {
    has(args, "--verify-accept")
}

/// 跑提交里记的判据；返回 `Ok(())` 表示"全过或本来就没开/没判据"。
///
/// `tree` / `base` 是这次的树与它的基线树，用来算改动路径 ⇒ 判别认领覆盖。
pub(crate) fn verify(
    repo: &Repo,
    intent: Option<&Intent>,
    tree: &Hash,
    base: Option<&Hash>,
    session: &str,
    args: &[String],
) -> Result<(), CliFail> {
    if !enabled(args) {
        return Ok(());
    }
    let Some(intent) = intent else {
        return Ok(());
    };
    if intent.accept.is_empty() {
        return Ok(());
    }

    let claims_path = flag(args, "--claims").ok_or_else(|| {
        CliFail::new(
            "accept_needs_claims",
            "--verify-accept 要同时给 --claims FILE（判据只对认领范围内的改动执行）",
            [
                "给认领表：`--claims <认领表.json>`（形状同 commit 的 --claims）".to_string(),
                "不想跑判据就删掉 --verify-accept（默认就是关的）".to_string(),
            ],
        )
    })?;
    let claims = load_claims(std::path::Path::new(claims_path)).map_err(|err| {
        CliFail::new(
            "cli_claims_unreadable",
            err,
            [format!("确认 {claims_path} 是 JSON 数组（每项 {{id, owner, paths, acquired_at, expires_at}}）")],
        )
    })?;

    let paths = changed_paths(repo, tree, base)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let verdict = gate::check(&claims, session, &paths, now);
    if !verdict.allowed() {
        return Err(CliFail::new(
            "accept_unclaimed",
            format!(
                "判据不跑：这次改动不在在效认领里（判决 {}，{} 个路径）",
                verdict.label(),
                paths.len()
            ),
            [
                "先看一眼是哪条路径没被覆盖：`trit-vcs status`（判据执行面不替人猜归属）"
                    .to_string(),
                "补认领或换一条覆盖这些路径的认领表，再加 --verify-accept".to_string(),
            ],
        ));
    }

    let timeout = flag(args, "--accept-timeout")
        .and_then(|raw| raw.parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(accept::DEFAULT_TIMEOUT);
    // 判据可能写坏仓库（它在本机跑任意 argv）：跑之前后各体检一次，多/少一个对象、HEAD 变了都算红。
    let before = verify_fresh(repo)?;
    let report = accept::run(
        &intent.accept,
        repo.root(),
        timeout,
        accept::DEFAULT_OUTPUT_CAP,
    )
    .map_err(|err| {
        CliFail::new(
            "accept_shell_meta",
            err.to_string(),
            [
                "判据要写成 argv（`cargo test -q --test x`），不要用管道/重定向/`sh -c`"
                    .to_string(),
                "要跑脚本就先把它提交进仓，再让判据调用那个文件".to_string(),
            ],
        )
    })?;

    let after = verify_fresh(repo)?;
    if (before.events, before.objects, before.commits, &before.head)
        != (after.events, after.objects, after.commits, &after.head)
    {
        return Err(CliFail::new(
            "accept_mutated_repo",
            format!(
                "判据跑完之后仓库变了（事件 {}→{}，对象 {}→{}，提交 {}→{}，HEAD {:?}→{:?}）",
                before.events,
                after.events,
                before.objects,
                after.objects,
                before.commits,
                after.commits,
                before.head,
                after.head
            ),
            [
                "判据不许写仓库：先 `trit-vcs verify` 看坏在哪，再从对等仓补对象".to_string(),
                "把判据改成只读（测试只读源码；要造临时仓就写到仓库外面）".to_string(),
            ],
        ));
    }

    for outcome in &report.outcomes {
        let state = if outcome.passed() {
            "过"
        } else if outcome.timed_out {
            "超时"
        } else {
            "没过"
        };
        eprintln!(
            "判据 {state}：{}（exit={:?}，{} ms，输出 {} B{}）",
            outcome.command,
            outcome.exit,
            outcome.duration_ms,
            outcome.output_bytes,
            if outcome.truncated {
                "，已截断"
            } else {
                ""
            }
        );
    }

    if report.passed() {
        eprintln!("判据 {} 条全过", report.outcomes.len());
        return Ok(());
    }

    let failed = report.failed().next().expect("没通过就一定有失败项");
    let why = if failed.timed_out {
        format!(
            "超时（{} ms，上限 {} s）",
            failed.duration_ms,
            timeout.as_secs()
        )
    } else {
        format!("exit={:?}", failed.exit)
    };
    let excerpt: String = failed.output_excerpt.chars().take(400).collect();
    Err(CliFail::new(
        "accept_failed",
        format!(
            "判据没通过（{} 条里 {} 条红）：{}（{why}）{}",
            report.outcomes.len(),
            report.failed().count(),
            failed.command,
            if excerpt.trim().is_empty() {
                String::new()
            } else {
                format!("\n  {excerpt}")
            }
        ),
        [
            format!("先手动跑一遍看全量输出：{}", failed.command),
            "修好之后重跑同一条命令（判据是提交的一部分，不会自己变）".to_string(),
        ],
    ))
}

/// 重新打开一次再体检：判据可能刚写过盘，拿旧句柄读会看到**过期缓存**
/// （实测表现是"对象缺失"这种误诊，而真正的问题是"判据写了仓库"）。
fn verify_fresh(repo: &Repo) -> Result<trit_vcs::repo::VerifyReport, CliFail> {
    let fresh = Repo::open(repo.root()).map_err(CliFail::from)?;
    fresh.verify().map_err(CliFail::from)
}

/// 改动路径 = 这次树与基线树的对称差（新增/改/删都算）。
fn changed_paths(repo: &Repo, tree: &Hash, base: Option<&Hash>) -> Result<Vec<String>, CliFail> {
    let current = repo
        .store()
        .tree_entries(tree)
        .map_err(|err| CliFail::from(trit_vcs::repo::RepoError::Store(err)))?;
    let previous = match base {
        Some(base) => repo
            .store()
            .tree_entries(base)
            .map_err(|err| CliFail::from(trit_vcs::repo::RepoError::Store(err)))?,
        None => Default::default(),
    };
    let mut paths: Vec<String> = current
        .keys()
        .chain(previous.keys())
        .filter(|path| current.get(*path) != previous.get(*path))
        .cloned()
        .collect();
    paths.sort();
    paths.dedup();
    Ok(paths)
}
