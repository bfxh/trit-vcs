//! 参数 → 结构化输入的那几个 helper：把「读命令行」和「判红」放在一起，
//! 这样 `commit` / `preflight` / `add` / `witness` 走的是同一份输入，预检看到的和真提交要的不分叉。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use trit_vcs::gate::{ClaimSpec, load_claims};
use trit_vcs::model::Intent;
use trit_vcs::repo::{CommitRequest, Repo};

use super::cli_fail::CliFail;
use super::{flag, flags, has, now_secs};

/// 从参数造提交请求：`commit` 与 `preflight` 共用，保证预检看的和真提交要的是同一份输入。
pub(crate) fn commit_request(args: &[String]) -> Result<CommitRequest, CliFail> {
    let hint = "trit-vcs preflight -m \"做了什么\" --owner <宿主:会话id> --repo <仓目录>  # 补齐后先预检，别直接 commit";
    let message = flag(args, "-m")
        .or_else(|| flag(args, "--message"))
        .ok_or_else(|| CliFail::usage("commit/preflight 需要 -m <说明>", [hint]))?;
    let owner = flag(args, "--owner").ok_or_else(|| {
        CliFail::usage(
            "commit/preflight 需要 --owner <宿主:会话id>（未认领的提交默认拒，owner 是判决的输入）",
            [
                hint,
                "认领表形状：JSON 数组，每项 {id, owner, paths, acquired_at, expires_at}",
            ],
        )
    })?;
    let claims: Vec<ClaimSpec> = match flag(args, "--claims") {
        Some(path) => load_claims(Path::new(path)).map_err(|err| {
            CliFail::new(
                "cli_claims_unreadable",
                err,
                [
                    format!("确认 {path} 存在且是 JSON 数组（每项 {{id, owner, paths, acquired_at, expires_at}}）"),
                    "重新导一份：`trit-vcs preflight --claims <同一份表> ...` 能过闸再 commit".to_string(),
                ],
            )
        })?,
        None => Vec::new(),
    };
    let witness = match flag(args, "--witness") {
        Some(path) => Some(std::fs::read(path).map_err(|err| {
            CliFail::local_io(
                path,
                &err.to_string(),
                [
                    "重跑见证并落文件：`trit-vcs witness --out <同一份文件> -- <判据命令>`"
                        .to_string(),
                ],
            )
        })?),
        None => None,
    };
    let accept = flags(args, "--accept");
    let intent = match flag(args, "--goal") {
        Some(goal) => Some(Intent::new(goal, accept)),
        None if !accept.is_empty() => {
            return Err(CliFail::usage(
                "--accept 需要同时给 --goal（判据得挂在一条目标上，否则事后没人知道它在验什么）",
                ["补上 --goal \"为什么这步算完成\"，或去掉 --accept".to_string()],
            ));
        }
        None => None,
    };
    Ok(CommitRequest {
        message: message.to_string(),
        session: owner.to_string(),
        claims,
        evidence: flags(args, "--evidence"),
        tags: flags(args, "--tag"),
        allow_unclaimed: has(args, "--allow-unclaimed"),
        witness,
        intent,
        parent_override: None,
        now_secs: now_secs(),
    })
}

/// 见证对象：优先暂存区（尚未提交的树），否则 HEAD 的树。
pub(crate) fn current_tree(
    repo: &Repo,
) -> Result<(trit_vcs::Hash, Option<trit_vcs::Hash>), CliFail> {
    let base = repo.head()?;
    let base_tree = match base {
        Some(id) => Some(repo.commit_at(&id)?.tree),
        None => None,
    };
    let tree = match repo.index()? {
        Some(index) => trit_vcs::Hash::from_hex(&index.tree).ok_or_else(|| {
            CliFail::new(
                "cli_index_bad_tree",
                format!("index 里的树 id 非法：{}", index.tree),
                [
                    "trit-vcs verify  # 先确认对象库本身没坏".to_string(),
                    "清掉暂存区重来：`trit-vcs add <文件>` 会重写 index".to_string(),
                ],
            )
        })?,
        None => base_tree.ok_or_else(|| {
            CliFail::usage(
                "仓库里既没有暂存区也没有提交",
                [
                    "trit-vcs add <文件>  # 先暂存，再 commit / witness".to_string(),
                    "空仓也能 commit：`trit-vcs commit -m ... --owner ...`（但要先 add 才有内容）"
                        .to_string(),
                ],
            )
        })?,
    };
    Ok((tree, base_tree))
}

/// 收集要暂存的文件：路径相对仓库根，目录会递归展开（跳过 `.tritvcs` 与 `.git`）。
pub(crate) fn collect(
    root: &Path,
    targets: &[String],
) -> Result<BTreeMap<String, Vec<u8>>, CliFail> {
    let mut out = BTreeMap::new();
    let mut push = |path: &Path| -> Result<(), CliFail> {
        let rel = path
            .strip_prefix(root)
            .map_err(|_| {
                CliFail::new(
                    "cli_path_outside_repo",
                    format!("不在仓库内：{}", path.display()),
                    [format!(
                        "用仓库根 `{}` 之下的相对路径：trit-vcs add <相对路径>",
                        root.display()
                    )],
                )
            })?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = std::fs::read(path).map_err(|e| {
            CliFail::local_io(
                &path.display().to_string(),
                &e.to_string(),
                ["先确认文件没被别的进程独占：`trit-vcs status` 看它是否还在".to_string()],
            )
        })?;
        out.insert(rel, bytes);
        Ok(())
    };
    for target in targets {
        let path = root.join(target);
        if path.is_dir() {
            for entry in walk(&path).map_err(|e| {
                CliFail::local_io(
                    &path.display().to_string(),
                    &e.to_string(),
                    ["列一下目录确认权限：`trit-vcs status --prefix <目录>`".to_string()],
                )
            })? {
                push(&entry)?;
            }
        } else if path.is_file() {
            push(&path)?;
        } else {
            return Err(CliFail::new(
                "cli_path_missing",
                format!("找不到：{}", path.display()),
                [
                    format!("trit-vcs status --repo {}", root.display()),
                    "路径是相对仓库根的；目录会被递归展开，`.tritvcs` 与 `.git` 会跳过".to_string(),
                ],
            ));
        }
    }
    Ok(out)
}

fn walk(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in std::fs::read_dir(current)? {
            let path = entry?.path();
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == ".tritvcs" || name == ".git" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}
