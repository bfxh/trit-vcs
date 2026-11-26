//! Git 双向桥 v2：trit-vcs ⇄ 真 Git 仓（用系统 `git` 做适配，不引 libgit2）。
//!
//! 导出的每个 Git 提交带 `Trit-Id/Session/Tags/Evidence` 尾注，便于反查；
//! 导入逐提交重建，文件内容逐字节搬运。v2 保留多父图、Git 作者/提交者/时间；
//! `--first-parent` 仍是显式降级，只走第一父链。仍不搬 submodule/tag，也不导入 Git 签名信任。

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::hash::Hash;
use crate::model::Commit;
use crate::repo::{CommitRequest, Repo, RepoError};
use crate::store::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum GitError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("仓库: {0}")]
    Repo(#[from] RepoError),
    #[error("对象库: {0}")]
    Store(#[from] StoreError),
    #[error("git {args} 失败：{stderr}")]
    Git { args: String, stderr: String },
    #[error("Git 路径不是 UTF-8：{0}")]
    BadPath(String),
    #[error("源仓还没有提交")]
    NoCommits,
    #[error("Git 图不成立：{0}")]
    Graph(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct BridgeOptions {
    /// 显式允许丢掉 merge 的次要父链，只导入/导出第一父链。
    pub first_parent: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExportStats {
    pub commits: usize,
    pub files_written: usize,
    pub merge_commits: usize,
    pub metadata_commits: usize,
    /// (trit 提交 id, git 提交 sha)
    pub map: Vec<(Hash, String)>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ImportStats {
    pub commits: usize,
    pub files: usize,
    pub merge_commits: usize,
    pub metadata_commits: usize,
    /// (git 提交 sha, trit 提交 id)
    pub map: Vec<(String, Hash)>,
}

fn git_raw(dir: &Path, args: &[&str]) -> Result<Vec<u8>, GitError> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .output()
        .map_err(|err| GitError::Git {
            args: args.join(" "),
            stderr: err.to_string(),
        })?;
    if !output.status.success() {
        return Err(GitError::Git {
            args: args.join(" "),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    Ok(output.stdout)
}

fn git_text(dir: &Path, args: &[&str]) -> Result<String, GitError> {
    Ok(String::from_utf8_lossy(&git_raw(dir, args)?).to_string())
}

#[derive(Clone, Debug, Default)]
struct GitMeta {
    author_name: String,
    author_email: String,
    author_at: Option<u64>,
    committer_name: String,
    committer_email: String,
    committer_at: Option<u64>,
    parents: Vec<String>,
    signature_status: String,
}

impl GitMeta {
    fn has_identity(&self) -> bool {
        !self.author_name.is_empty()
            || !self.author_email.is_empty()
            || !self.committer_name.is_empty()
            || !self.committer_email.is_empty()
    }

    fn evidence(&self) -> Vec<String> {
        let mut out = Vec::new();
        if !self.author_name.is_empty() || !self.author_email.is_empty() {
            out.push(format!(
                "git-author:{} <{}>",
                one_line(&self.author_name),
                one_line(&self.author_email)
            ));
        }
        if let Some(at) = self.author_at {
            out.push(format!("git-author-at:{at}"));
        }
        if !self.committer_name.is_empty() || !self.committer_email.is_empty() {
            out.push(format!(
                "git-committer:{} <{}>",
                one_line(&self.committer_name),
                one_line(&self.committer_email)
            ));
        }
        if let Some(at) = self.committer_at {
            out.push(format!("git-committer-at:{at}"));
        }
        if !self.parents.is_empty() {
            out.push(format!("git-parents:{}", self.parents.join(" ")));
        }
        if !self.signature_status.is_empty() {
            out.push(format!("git-signature-status:{}", self.signature_status));
        }
        out
    }
}

fn one_line(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect()
}

fn parse_identity(value: &str) -> Option<(String, String)> {
    let (name, rest) = value.rsplit_once(" <")?;
    let email = rest.strip_suffix('>')?;
    Some((name.to_string(), email.to_string()))
}

fn meta_from_evidence(commit: &crate::model::Commit) -> GitMeta {
    let mut meta = GitMeta::default();
    for evidence in &commit.evidence {
        let Some(value) = evidence.strip_prefix("git-") else {
            continue;
        };
        if let Some(identity) = value.strip_prefix("author:") {
            if let Some((name, email)) = parse_identity(identity) {
                meta.author_name = name;
                meta.author_email = email;
            }
        } else if let Some(at) = value.strip_prefix("author-at:") {
            meta.author_at = at.parse().ok();
        } else if let Some(identity) = value.strip_prefix("committer:") {
            if let Some((name, email)) = parse_identity(identity) {
                meta.committer_name = name;
                meta.committer_email = email;
            }
        } else if let Some(at) = value.strip_prefix("committer-at:") {
            meta.committer_at = at.parse().ok();
        } else if let Some(parents) = value.strip_prefix("parents:") {
            meta.parents = parents.split_whitespace().map(str::to_string).collect();
        } else if let Some(status) = value.strip_prefix("signature-status:") {
            meta.signature_status = status.to_string();
        }
    }
    meta
}

fn read_meta(git_dir: &Path, sha: &str) -> Result<GitMeta, GitError> {
    let format = "%an%x00%ae%x00%at%x00%cn%x00%ce%x00%ct%x00%P%x00%G?";
    let format_arg = format!("--format={format}");
    let raw = git_raw(git_dir, &["show", "-s", &format_arg, sha])?;
    let text = String::from_utf8_lossy(&raw);
    let fields: Vec<&str> = text.trim_end_matches(['\r', '\n']).split('\x00').collect();
    if fields.len() < 8 {
        return Err(GitError::Git {
            args: format!("show -s --format {format} {sha}"),
            stderr: format!("期望 8 个字段，实际 {}", fields.len()),
        });
    }
    Ok(GitMeta {
        author_name: fields[0].to_string(),
        author_email: fields[1].to_string(),
        author_at: fields[2].parse().ok(),
        committer_name: fields[3].to_string(),
        committer_email: fields[4].to_string(),
        committer_at: fields[5].parse().ok(),
        parents: fields[6].split_whitespace().map(str::to_string).collect(),
        signature_status: fields[7].to_string(),
    })
}

fn git_commit_tree(
    dir: &Path,
    tree: &str,
    parents: &[String],
    message: &str,
    meta: &GitMeta,
) -> Result<String, GitError> {
    let mut command = Command::new("git");
    command.args(["commit-tree", tree]);
    for parent in parents {
        command.args(["-p", parent]);
    }
    command.args(["-m", message]).current_dir(dir);
    if !meta.author_name.is_empty() && !meta.author_email.is_empty() {
        command
            .env("GIT_AUTHOR_NAME", one_line(&meta.author_name))
            .env("GIT_AUTHOR_EMAIL", one_line(&meta.author_email));
    }
    if let Some(at) = meta.author_at {
        command.env("GIT_AUTHOR_DATE", format!("@{at} +0000"));
    }
    if !meta.committer_name.is_empty() && !meta.committer_email.is_empty() {
        command
            .env("GIT_COMMITTER_NAME", one_line(&meta.committer_name))
            .env("GIT_COMMITTER_EMAIL", one_line(&meta.committer_email));
    }
    if let Some(at) = meta.committer_at {
        command.env("GIT_COMMITTER_DATE", format!("@{at} +0000"));
    }
    let output = command.output().map_err(|err| GitError::Git {
        args: format!("commit-tree {tree}"),
        stderr: err.to_string(),
    })?;
    if !output.status.success() {
        return Err(GitError::Git {
            args: "commit-tree".to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if sha.len() != 40 {
        return Err(GitError::Git {
            args: "commit-tree".to_string(),
            stderr: format!("期望 40 位提交 sha，实际 {sha:?}"),
        });
    }
    Ok(sha)
}

fn existing_head(dir: &Path) -> Result<Option<String>, GitError> {
    let output = Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", "HEAD"])
        .current_dir(dir)
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok((sha.len() == 40).then_some(sha))
}

/// 把目标仓当前分支移到导出的图顶端，并同步工作树/索引。
fn set_head(dir: &Path, sha: &str) -> Result<(), GitError> {
    let branch = git_text(dir, &["symbolic-ref", "--quiet", "--short", "HEAD"])?
        .trim()
        .to_string();
    if branch.is_empty() {
        return Err(GitError::Graph(
            "目标 Git 仓的 HEAD 是 detached；先切到一个分支再导出".to_string(),
        ));
    }
    let refname = format!("refs/heads/{branch}");
    git_raw(dir, &["update-ref", &refname, sha])?;
    git_raw(dir, &["reset", "--hard", sha])?;
    Ok(())
}

fn record_bridge(
    repo: &mut Repo,
    action: &str,
    status: &str,
    stats: &BridgeStats,
    error: Option<&str>,
) {
    let payload = serde_json::json!({
        "schema": "trit-git-bridge-v2",
        "action": action,
        "status": status,
        "first_parent": stats.first_parent,
        "commits": stats.commits,
        "files": stats.files,
        "merge_commits": stats.merge_commits,
        "metadata_commits": stats.metadata_commits,
        "map_digest": Hash::of(stats.map_text.as_bytes()).to_hex(),
        "error": error,
    });
    if let Err(err) = repo.append_audit("git_bridge", payload, wall_ms()) {
        eprintln!("trit-vcs: git_bridge 事件无法落账：{err}");
    }
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Clone, Debug, Default)]
struct BridgeStats {
    first_parent: bool,
    commits: usize,
    files: usize,
    merge_commits: usize,
    metadata_commits: usize,
    map_text: String,
}

fn merge_count(git_dir: &Path, first_parent: bool) -> Result<usize, GitError> {
    let mut args = vec!["rev-list", "--count", "--merges"];
    if first_parent {
        args.push("--first-parent");
    }
    args.push("HEAD");
    let text = git_text(git_dir, &args)?;
    Ok(text.trim().parse::<usize>().unwrap_or(0))
}

fn ensure_repo(git_dir: &Path) -> Result<(), GitError> {
    std::fs::create_dir_all(git_dir)?;
    if !git_dir.join(".git").is_dir() {
        git_raw(git_dir, &["init", "-q"])?;
    }
    // 身份只作用于本仓，避免改动用户全局配置。
    git_raw(git_dir, &["config", "user.name", "trit-vcs"])?;
    git_raw(git_dir, &["config", "user.email", "trit-vcs@localhost"])?;
    Ok(())
}

fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, GitError> {
    let cleaned = rel.replace('\\', "/");
    if cleaned.starts_with('/')
        || cleaned
            .split('/')
            .any(|part| part.is_empty() || part == "..")
    {
        return Err(GitError::BadPath(rel.to_string()));
    }
    Ok(root.join(cleaned))
}

fn walk_files(root: &Path) -> Result<Vec<(String, PathBuf)>, GitError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name == ".git" {
                continue;
            }
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                let rel = path
                    .strip_prefix(root)
                    .map_err(|_| GitError::BadPath(path.display().to_string()))?
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, path));
            }
        }
    }
    Ok(out)
}

fn trailer_line(id: Hash, commit: &crate::model::Commit) -> String {
    let mut out = String::new();
    out.push_str(&format!("\n\nTrit-Id: {}\n", id.to_hex()));
    out.push_str(&format!("Trit-Session: {}\n", commit.session));
    if !commit.tags.is_empty() {
        out.push_str(&format!("Trit-Tags: {}\n", commit.tags.join(",")));
    }
    for evidence in &commit.evidence {
        out.push_str(&format!("Trit-Evidence: {evidence}\n"));
    }
    out
}

/// 把 trit 仓的完整多父图按旧→新写进 `git_dir`（没有 `.git` 就初始化）。
pub fn export(repo: &mut Repo, git_dir: &Path) -> Result<ExportStats, GitError> {
    export_with_options(repo, git_dir, &BridgeOptions::default())
}

/// 导出；默认保留完整多父图，`first_parent` 是显式降级。
pub fn export_with_options(
    repo: &mut Repo,
    git_dir: &Path,
    options: &BridgeOptions,
) -> Result<ExportStats, GitError> {
    let mut stats = ExportStats::default();
    let mut bridge = BridgeStats::default();
    let result = export_inner(repo, git_dir, options, &mut stats, &mut bridge);
    match result {
        Ok(()) => {
            record_bridge(repo, "export", "ok", &bridge, None);
            Ok(stats)
        }
        Err(err) => {
            record_bridge(repo, "export", "failed", &bridge, Some(&err.to_string()));
            Err(err)
        }
    }
}

fn export_inner(
    repo: &mut Repo,
    git_dir: &Path,
    options: &BridgeOptions,
    stats: &mut ExportStats,
    bridge: &mut BridgeStats,
) -> Result<(), GitError> {
    let commits = if options.first_parent {
        repo.log()?.into_iter().rev().collect::<Vec<_>>()
    } else {
        repo.log_all()?.into_iter().rev().collect::<Vec<_>>()
    };
    if commits.is_empty() {
        return Err(GitError::NoCommits);
    }
    let merges = commits
        .iter()
        .filter(|(_, commit)| commit.parents.len() > 1)
        .count();
    bridge.first_parent = options.first_parent;
    bridge.merge_commits = merges;
    stats.merge_commits = merges;
    ensure_repo(git_dir)?;
    let existing = existing_head(git_dir)?;
    let mut shas: HashMap<Hash, String> = HashMap::new();
    let mut last = None;
    for (id, commit) in &commits {
        materialize(repo, git_dir, commit, stats)?;
        let tree = git_text(git_dir, &["write-tree"])?.trim().to_string();
        let selected: Vec<Hash> = if options.first_parent {
            commit.parents.iter().take(1).copied().collect()
        } else {
            commit.parents.clone()
        };
        let mut parents = Vec::new();
        if selected.is_empty() {
            if let Some(head) = &existing {
                // 目标仓已有历史时沿用旧行为：新导入的根提交挂在原 HEAD 上，不丢旧历史。
                parents.push(head.clone());
            }
        } else {
            for parent in &selected {
                let Some(sha) = shas.get(parent) else {
                    return Err(GitError::Graph(format!(
                        "提交 {} 的父 {} 尚未导出（遍历顺序不成立）",
                        id.to_hex(),
                        parent.to_hex()
                    )));
                };
                parents.push(sha.clone());
            }
        }
        let meta = meta_from_evidence(commit);
        if meta.has_identity() {
            stats.metadata_commits += 1;
            bridge.metadata_commits += 1;
        }
        let message = format!("{}{}", commit.message, trailer_line(*id, commit));
        let sha = git_commit_tree(git_dir, &tree, &parents, &message, &meta)?;
        shas.insert(*id, sha.clone());
        stats.map.push((*id, sha.clone()));
        bridge
            .map_text
            .push_str(&format!("{} {sha}\n", id.to_hex()));
        stats.commits += 1;
        bridge.commits += 1;
        last = Some(sha);
    }
    if let Some(sha) = last {
        set_head(git_dir, &sha)?;
    }
    bridge.files = stats.files_written;
    Ok(())
}

fn materialize(
    repo: &Repo,
    git_dir: &Path,
    commit: &Commit,
    stats: &mut ExportStats,
) -> Result<(), GitError> {
    let entries = repo.store().tree_entries(&commit.tree)?;
    let wanted: BTreeSet<&str> = entries.keys().map(String::as_str).collect();
    // 先同步新增/修改，再删掉上一版有、这一版没有的文件。
    for (path, file_id) in &entries {
        let bytes = repo.store().get_file(file_id)?;
        let target = safe_join(git_dir, path)?;
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let same = std::fs::read(&target)
            .map(|old| old == bytes)
            .unwrap_or(false);
        if !same {
            std::fs::write(&target, &bytes)?;
            stats.files_written += 1;
        }
    }
    for (rel, path) in walk_files(git_dir)? {
        if !wanted.contains(rel.as_str()) {
            std::fs::remove_file(path)?;
        }
    }
    git_raw(git_dir, &["add", "-A"])?;
    Ok(())
}

struct GitBlob {
    path: String,
    object: String,
}

fn list_blobs(git_dir: &Path, sha: &str) -> Result<Vec<GitBlob>, GitError> {
    let raw = git_raw(git_dir, &["ls-tree", "-r", "-z", sha])?;
    let mut out = Vec::new();
    for record in raw.split(|byte| *byte == 0) {
        if record.is_empty() {
            continue;
        }
        let Some(tab) = record.iter().position(|byte| *byte == b'\t') else {
            continue;
        };
        let meta = &record[..tab];
        let path = &record[tab + 1..];
        let meta = String::from_utf8_lossy(meta);
        let mut fields = meta.split_whitespace();
        let _mode = fields.next();
        let kind = fields.next().unwrap_or("");
        let object = fields.next().unwrap_or("");
        if kind != "blob" {
            continue; // submodule / tree 不搬
        }
        let path = String::from_utf8(path.to_vec())
            .map_err(|_| GitError::BadPath(String::from_utf8_lossy(path).to_string()))?;
        out.push(GitBlob {
            path,
            object: object.to_string(),
        });
    }
    Ok(out)
}

fn strip_trailers(message: &str) -> String {
    let mut lines: Vec<&str> = message.lines().collect();
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    while lines
        .last()
        .is_some_and(|line| line.trim_start().starts_with("Trit-"))
    {
        lines.pop();
    }
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }
    lines.join("\n")
}

/// 把 `git_dir` 逐提交导入当前 trit 仓（提交说明保留，证据写 git sha 与原作者元数据）。
pub fn import(repo: &mut Repo, git_dir: &Path) -> Result<ImportStats, GitError> {
    import_with_options(repo, git_dir, &BridgeOptions::default())
}

/// 导入；默认保留完整多父图，`first_parent` 是显式降级。
pub fn import_with_options(
    repo: &mut Repo,
    git_dir: &Path,
    options: &BridgeOptions,
) -> Result<ImportStats, GitError> {
    let mut stats = ImportStats::default();
    let mut bridge = BridgeStats::default();
    let result = import_inner(repo, git_dir, options, &mut stats, &mut bridge);
    match result {
        Ok(()) => {
            record_bridge(repo, "import", "ok", &bridge, None);
            Ok(stats)
        }
        Err(err) => {
            record_bridge(repo, "import", "failed", &bridge, Some(&err.to_string()));
            Err(err)
        }
    }
}

fn import_inner(
    repo: &mut Repo,
    git_dir: &Path,
    options: &BridgeOptions,
    stats: &mut ImportStats,
    bridge: &mut BridgeStats,
) -> Result<(), GitError> {
    let imported_merges = merge_count(git_dir, options.first_parent)?;
    stats.merge_commits = imported_merges;
    bridge.first_parent = options.first_parent;
    bridge.merge_commits = imported_merges;
    let mut args = vec!["rev-list", "--reverse", "--topo-order"];
    if options.first_parent {
        args.push("--first-parent");
    }
    args.push("HEAD");
    let log = git_text(git_dir, &args)?;
    let mut imported: HashMap<String, Hash> = HashMap::new();
    for sha in log.lines().map(str::trim).filter(|line| !line.is_empty()) {
        let mut files = BTreeMap::new();
        for blob in list_blobs(git_dir, sha)? {
            files.insert(
                blob.path,
                git_raw(git_dir, &["cat-file", "blob", &blob.object])?,
            );
        }
        let message = git_text(git_dir, &["show", "-s", "--format=%B", sha])
            .map(|text| strip_trailers(&text))
            .unwrap_or_default();
        let meta = read_meta(git_dir, sha)?;
        let mut parents = Vec::new();
        for parent in &meta.parents {
            if options.first_parent && !parents.is_empty() {
                break;
            }
            let Some(id) = imported.get(parent) else {
                return Err(GitError::Graph(format!(
                    "Git 提交 {sha} 的父 {parent} 尚未导入（拓扑序不成立）"
                )));
            };
            parents.push(*id);
        }
        let now = meta.committer_at.or(meta.author_at).unwrap_or(0).max(1);
        repo.stage(&files, now)?;
        stats.files += files.len();
        bridge.files = stats.files;
        let mut evidence = vec![format!("git:{sha}")];
        evidence.extend(meta.evidence());
        if meta.has_identity() {
            stats.metadata_commits += 1;
            bridge.metadata_commits += 1;
        }
        let mut tags = vec!["git-import".to_string()];
        if meta.parents.len() > 1 {
            tags.push("git-merge".to_string());
        }
        let outcome = repo.commit(CommitRequest {
            message,
            session: format!(
                "git:{}",
                if meta.author_name.is_empty() {
                    "bridge"
                } else {
                    &meta.author_name
                }
            ),
            claims: Vec::new(),
            evidence,
            tags,
            allow_unclaimed: true,
            witness: None,
            intent: None,
            parents_override: Some(parents),
            now_secs: now,
        })?;
        stats.map.push((sha.to_string(), outcome.id));
        stats.commits += 1;
        bridge.commits += 1;
        bridge
            .map_text
            .push_str(&format!("{sha} {}\n", outcome.id.to_hex()));
        imported.insert(sha.to_string(), outcome.id);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
