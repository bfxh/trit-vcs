//! 网络同步的语义层：`publish`（把提交闭包与父链发到中央仓的命名 ref）、
//! `pull`（取一个 ref 的闭包并物化）。
//!
//! 这一层只做**判定**，不做 HTTP（在 `net`）也不做线格式（在 `wire`）：
//! - publish 的对象集是"提交闭包 + 第一父链的提交对象"，封顶 `ANCESTOR_CAP` 条；
//! - 服务端收完对象后必须能证明：tip 是提交、树闭包齐全、且新 tip 是现有 ref 的后代；
//! - **网络不开放 force**：快进只进不退，改写历史只能在中央仓本地做（这是边界不是缺口）；
//! - pull 的 `prefix` 只过滤树清单与对象闭包；全量 pull 才会把 HEAD 与索引落到被拉的提交，
//!   前缀 pull 不擅动 HEAD（否则 `status` 会把范围外的文件全算成删除）。

use crate::bundle::{self, BundleError};
use crate::hash::Hash;
use crate::model::Commit;
use crate::net::{Client, Limits, NetError, PullReply};
use crate::remediation::{Context, Remediable};
use crate::repo::{Repo, RepoError};
use crate::store::{Store, StoreError};
use crate::wire::{self, WireError};
use crate::worktree::{self, WorktreeError};

/// 一次 publish 最多带上多少条父提交（再多也不该一次把整个历史搬完）。
pub const ANCESTOR_CAP: usize = 4_096;

#[derive(Debug, thiserror::Error)]
pub enum RemoteError {
    #[error("网络: {0}")]
    Net(#[from] NetError),
    #[error("对象流: {0}")]
    Wire(#[from] WireError),
    #[error("对象库: {0}")]
    Store(#[from] StoreError),
    #[error("仓库: {0}")]
    Repo(#[from] RepoError),
    #[error("传输: {0}")]
    Bundle(#[from] BundleError),
    #[error("工作树: {0}")]
    Worktree(#[from] WorktreeError),
    #[error("提交 {0} 不在中央仓：客户端没把 tip 的闭包发上来")]
    TipMissing(String),
    #[error("历史不完整：{0}")]
    HistoryGap(String),
    #[error("树不完整：{0}")]
    TreeIncomplete(String),
}

impl RemoteError {
    /// HTTP 状态码：同一种判决在服务端与客户端必须落到同一个档位。
    pub fn status(&self) -> u16 {
        match self {
            RemoteError::Net(inner) => inner.status(),
            RemoteError::Wire(_) => 400,
            RemoteError::Repo(RepoError::BadRefName(_)) => 400,
            RemoteError::Repo(RepoError::UnknownRef(_)) => 404,
            RemoteError::Repo(RepoError::NonFastForward { .. }) => 409,
            RemoteError::TipMissing(_)
            | RemoteError::HistoryGap(_)
            | RemoteError::TreeIncomplete(_)
            | RemoteError::Repo(RepoError::UnknownCommit(_)) => 409,
            RemoteError::Repo(RepoError::Store(StoreError::Missing(_))) => 404,
            RemoteError::Store(StoreError::Missing(_)) => 404,
            _ => 500,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            RemoteError::Net(inner) => inner.kind(),
            RemoteError::Wire(_) => "wire_bad_stream",
            RemoteError::Store(inner) => crate::remediation::kind_store(inner),
            RemoteError::Repo(inner) => crate::remediation::kind(inner),
            RemoteError::Bundle(_) => "wire_bad_bundle",
            RemoteError::Worktree(_) => "worktree_conflict",
            RemoteError::TipMissing(_) => "tip_missing",
            RemoteError::HistoryGap(_) => "history_gap",
            RemoteError::TreeIncomplete(_) => "tree_incomplete",
        }
    }
}

/// 发布读数：发了多少对象、多少字节。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PublishStats {
    pub commit: Option<Hash>,
    pub objects: usize,
    pub bytes: u64,
}

/// 拉取读数：服务端声明与实际收到的对象、物化结果。
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PullStats {
    pub commit: Option<Hash>,
    pub written: usize,
    pub skipped: usize,
    pub objects: usize,
}

impl Remediable for RemoteError {
    fn kind(&self) -> &'static str {
        RemoteError::kind(self)
    }

    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        let repo = ctx.dir.display().to_string();
        match self {
            RemoteError::Net(inner) => NetError::commands(inner, ctx),
            RemoteError::Wire(_) => vec![
                format!("{repo} 的对象流坏了：重跑同一条 publish/pull（内容寻址会只补缺块）"),
                "对方版本太旧或流被截断时，先用 `trit-vcs serve --token-file` 的同一版本重试"
                    .to_string(),
            ],
            RemoteError::Repo(inner) => crate::remediation::commands(inner, ctx),
            RemoteError::Bundle(_) => vec![format!(
                "重跑一次；仍然失败就 `trit-vcs verify --repo {repo}` 确认对象库"
            )],
            RemoteError::Store(inner) => crate::remediation::commands_store(inner, ctx),
            RemoteError::Worktree(_) => vec![format!(
                "`trit-vcs status --repo {repo}` 看哪些文件挡着，先提交或加 --force"
            )],
            RemoteError::TipMissing(commit) => vec![
                format!(
                    "中央仓缺 {commit}：在源仓跑 `trit-vcs publish <ref> --remote http://… --token-file <文件>`"
                ),
                format!("确认 tip 是提交：`trit-vcs log --repo {repo}`"),
            ],
            RemoteError::HistoryGap(detail) => vec![
                detail.to_string(),
                format!(
                    "先 `trit-vcs pull <ref> --remote http://… --repo {repo}` 把父链补齐，再重发"
                ),
            ],
            RemoteError::TreeIncomplete(detail) => vec![
                detail.to_string(),
                format!(
                    "重跑一次 publish（对象流会补齐缺的块）；或先 `trit-vcs verify --repo {repo}`"
                ),
            ],
        }
    }
}

/// 客户端 publish：把 `commit`（缺省 HEAD）的闭包与第一父链发到 `ref`。
pub fn publish_to(
    remote: &str,
    token: &str,
    repo: &Repo,
    name: &str,
    commit: Option<&Hash>,
) -> Result<PublishStats, RemoteError> {
    Repo::validate_ref(name)?;
    let tip = match commit {
        Some(id) => *id,
        None => repo.head()?.ok_or(RepoError::NothingStaged)?,
    };
    let body = publish_body(repo, tip)?;
    let client = Client::new(remote, token)?;
    let reply = client.publish(name, &tip, &body, repo.store())?;
    let _ = reply;
    Ok(PublishStats {
        commit: Some(tip),
        objects: body.count() as usize,
        bytes: body.byte_len(repo.store())?,
    })
}

/// 发布要发的对象：提交闭包（tip 的树/文件映射/块）+ 第一父链的提交对象（去重）。
pub fn publish_body(repo: &Repo, tip: Hash) -> Result<wire::Body, RemoteError> {
    let store = repo.store();
    let mut body = wire::Body {
        objects: Vec::new(),
        inline: Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    for id in bundle::commit_closure(store, tip)? {
        if seen.insert(id) {
            body.objects.push(id);
        }
    }
    let mut cursor = repo.commit_at(&tip)?.parents.first().copied();
    let mut steps = 0usize;
    while let Some(id) = cursor {
        if !store.has_chunk(&id) {
            return Err(RemoteError::HistoryGap(format!(
                "本地缺父提交 {id}：先把历史补齐（trit-vcs pull / import）"
            )));
        }
        if seen.insert(id) {
            body.objects.push(id);
        }
        let parsed: Commit = repo.commit_at(&id)?;
        cursor = parsed.parents.first().copied();
        steps += 1;
        if steps > ANCESTOR_CAP {
            return Err(RemoteError::HistoryGap(format!(
                "父链超过 {ANCESTOR_CAP} 条：先把中央仓的 ref 往前推一段再发"
            )));
        }
    }
    Ok(body)
}

/// 服务端收完对象后的判定：ref 名、tip 是提交、树闭包齐全、快进。
///
/// 返回 `(tip, 旧 ref)`；对象写入由调用方（`net`）在收流时完成。
pub fn accept_publish(
    central: &mut Repo,
    name: &str,
    tip: &Hash,
) -> Result<Option<Hash>, RemoteError> {
    Repo::validate_ref(name)?;
    let commit = central.commit_at(tip).map_err(|err| match err {
        RepoError::Store(StoreError::Missing(_)) | RepoError::UnknownCommit(_) => {
            RemoteError::TipMissing(tip.to_hex())
        }
        other => other.into(),
    })?;
    ensure_tree_present(central.store(), &commit.tree)?;
    let previous = central.ref_commit(name)?;
    if let Some(current) = previous
        && current != *tip
    {
        let base = central.merge_base(tip, &current).map_err(|err| match err {
            RepoError::Store(StoreError::Missing(_)) => RemoteError::HistoryGap(format!(
                "中央仓缺 {current} 的父链，判不了快进：先在该仓本地补齐（trit-vcs pull）"
            )),
            other => other.into(),
        })?;
        if base != Some(current) {
            return Err(RepoError::NonFastForward {
                name: name.to_string(),
                current: current.short(),
                incoming: tip.short(),
            }
            .into());
        }
    }
    central.set_ref(name, tip)?;
    Ok(previous)
}

/// pull 的发送计划：`tip` 的过滤树清单 + 条目闭包 + tip 提交对象。
#[derive(Clone, Debug)]
pub struct PullPlan {
    pub tip: Hash,
    pub manifest: Hash,
    pub files: usize,
    pub body: wire::Body,
}

impl PullPlan {
    pub fn objects(&self) -> usize {
        self.body.count() as usize
    }
}

pub fn pull_plan(
    central: &Repo,
    name: &str,
    prefix: Option<&str>,
) -> Result<PullPlan, RemoteError> {
    let tip = central
        .ref_commit(name)?
        .ok_or_else(|| RepoError::UnknownRef(name.to_string()))?;
    let commit = central.commit_at(&tip)?;
    let manifest = bundle::manifest(central.store(), commit.tree, prefix)?;
    let mut body = wire::Body {
        objects: vec![tip],
        inline: vec![(manifest.id, manifest.bytes.clone())],
    };
    for id in bundle::entries_closure(central.store(), &manifest.entries)? {
        if !body.objects.contains(&id) {
            body.objects.push(id);
        }
    }
    Ok(PullPlan {
        tip,
        manifest: manifest.id,
        files: manifest.entries.len(),
        body,
    })
}

/// 客户端 pull：取回闭包、物化；全量 pull 才把 HEAD/索引落到被拉的提交。
pub fn pull_from(
    remote: &str,
    token: &str,
    repo: &mut Repo,
    name: &str,
    prefix: Option<&str>,
    force: bool,
) -> Result<PullStats, RemoteError> {
    let client = Client::new(remote, token)?;
    let reply = client.pull(name, prefix, repo.store(), Limits::default())?;
    apply_pull(repo, &reply, prefix, force, name)
}

fn apply_pull(
    repo: &mut Repo,
    reply: &PullReply,
    prefix: Option<&str>,
    force: bool,
    name: &str,
) -> Result<PullStats, RemoteError> {
    if !repo.store().has_chunk(&reply.tip) {
        return Err(RemoteError::TipMissing(reply.tip.to_hex()));
    }
    let commit = repo.commit_at(&reply.tip)?;
    let entries = repo.store().tree_entries(&reply.manifest)?;
    if entries.len() != reply.files {
        return Err(RemoteError::HistoryGap(format!(
            "清单条目数与回执不符：服务端说 {}，本地读到 {}",
            reply.files,
            entries.len()
        )));
    }
    if prefix.is_none() && reply.manifest != commit.tree {
        return Err(RemoteError::HistoryGap(format!(
            "全量 pull 的清单必须是提交的树：提交说 {}，回执说 {}",
            commit.tree.short(),
            reply.manifest.short()
        )));
    }
    ensure_tree_present(repo.store(), &reply.manifest)?;
    if prefix.is_none() {
        check_fast_forward(repo, reply.tip, name, force)?;
        if !force && let Some(paths) = repo.staged_paths()? {
            return Err(WorktreeError::Dirty(paths.len(), paths).into());
        }
    }
    let stats = worktree::materialize(repo.store(), &reply.manifest, repo.root(), prefix, force)?;
    if prefix.is_none() {
        let paths: Vec<String> = entries.keys().cloned().collect();
        repo.adopt(&reply.tip, &reply.manifest, &paths)?;
    } else if let Some(prefix) = prefix {
        let index = crate::sparse::SparseIndex::new(prefix, reply.manifest, Some(reply.tip))
            .map_err(WorktreeError::Sparse)?;
        index.save(repo.root()).map_err(WorktreeError::Sparse)?;
    }
    Ok(PullStats {
        commit: Some(reply.tip),
        written: stats.written,
        skipped: stats.skipped,
        objects: reply.objects,
    })
}

fn check_fast_forward(
    repo: &Repo,
    commit: Hash,
    name: &str,
    force: bool,
) -> Result<(), RemoteError> {
    let Some(head) = repo.head()? else {
        return Ok(());
    };
    if head == commit {
        return Ok(());
    }
    let base = repo.merge_base(&commit, &head)?;
    if force || base == Some(head) {
        return Ok(());
    }
    Err(RepoError::NonFastForward {
        name: name.to_string(),
        current: head.short(),
        incoming: commit.short(),
    }
    .into())
}

/// 服务端/客户端共用的完整性闸门：树里的每个文件映射与每个块都必须在库里。
///
/// 只查"在不在"（读时仍逐块校验）；这是为了拒绝"ref 指到一棵缺块的树"，
/// 否则下一次 pull 会在别人机器上炸，而不是在发布这一端炸。
pub fn ensure_tree_present(store: &Store, tree: &Hash) -> Result<(), RemoteError> {
    let entries = store.tree_entries(tree)?;
    for (path, file_id) in entries {
        if !store.has_chunk(&file_id) {
            return Err(RemoteError::TreeIncomplete(format!(
                "文件映射 {file_id} 不在库里（路径 {path}）"
            )));
        }
        let map = store.file_map(&file_id)?;
        for chunk in map.chunks {
            if !store.has_chunk(&chunk) {
                return Err(RemoteError::TreeIncomplete(format!(
                    "块 {chunk} 不在库里（路径 {path}）"
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::time::Duration;

    use super::*;
    use crate::gate::ClaimSpec;
    use crate::net::{Config, Server};
    use crate::repo::CommitRequest;

    const TOKEN: &str = "0123456789abcdef";

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trit-vcs-remote-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn commit_all(repo: &mut Repo, files: &BTreeMap<String, Vec<u8>>, now: u64) -> Hash {
        repo.stage(files, now).unwrap();
        repo.commit(CommitRequest {
            message: format!("c{now}"),
            session: "qoder:remote".to_string(),
            claims: vec![ClaimSpec {
                id: format!("c{now}"),
                owner: "qoder:remote".to_string(),
                paths: files.keys().cloned().collect(),
                acquired_at: 1,
                expires_at: u64::MAX / 2,
            }],
            now_secs: now,
            ..Default::default()
        })
        .unwrap()
        .id
    }

    fn start(root: &std::path::Path) -> Server {
        let mut config = Config::new(root.join("central"), "127.0.0.1:0", TOKEN);
        config.read_timeout = Duration::from_secs(20);
        config.max_body = 64 * 1024 * 1024;
        Server::start(config).unwrap()
    }

    #[test]
    fn publish_then_full_pull_adopts_head() {
        let root = temp("full");
        let mut src = Repo::init(root.join("src")).unwrap();
        let files = BTreeMap::from([
            ("gen/a.txt".to_string(), b"aaa\n".to_vec()),
            ("gen/b.txt".to_string(), b"bbb\n".to_vec()),
        ]);
        commit_all(&mut src, &files, 1_000);
        let server = start(&root);
        let remote = format!("http://{}", server.addr());
        let stats = publish_to(&remote, TOKEN, &src, "main", None).unwrap();
        assert!(stats.objects > 0);

        let client_dir = root.join("client");
        std::fs::create_dir_all(&client_dir).unwrap();
        let mut client = Repo::init(&client_dir).unwrap();
        let pulled = pull_from(&remote, TOKEN, &mut client, "main", None, false).unwrap();
        assert_eq!(pulled.written, 2);
        assert_eq!(client.head().unwrap(), Some(pulled.commit.unwrap()));
        assert!(
            worktree::status(&client).unwrap().is_empty(),
            "pull 后 status 必须干净"
        );
        assert!(client.index().unwrap().is_some(), "索引要落到被拉的树");
        assert_eq!(client.log().unwrap().len(), 1);
        server.shutdown();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prefix_pull_materializes_only_that_dir_and_keeps_head() {
        let root = temp("prefix");
        let mut src = Repo::init(root.join("src")).unwrap();
        let files = BTreeMap::from([
            ("gen/d00/a.txt".to_string(), b"a\n".to_vec()),
            ("gen/d01/b.txt".to_string(), b"b\n".to_vec()),
        ]);
        commit_all(&mut src, &files, 1_000);
        let server = start(&root);
        let remote = format!("http://{}", server.addr());
        publish_to(&remote, TOKEN, &src, "main", None).unwrap();

        let client_dir = root.join("client");
        std::fs::create_dir_all(&client_dir).unwrap();
        let mut client = Repo::init(&client_dir).unwrap();
        let pulled =
            pull_from(&remote, TOKEN, &mut client, "main", Some("gen/d00"), false).unwrap();
        assert_eq!(pulled.written, 1);
        assert!(client_dir.join("gen/d00/a.txt").is_file());
        assert!(!client_dir.join("gen/d01").exists());
        assert!(client.head().unwrap().is_none(), "前缀 pull 不擅动 HEAD");
        server.shutdown();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_token_and_non_fast_forward_are_loud() {
        let root = temp("gates");
        let mut src = Repo::init(root.join("src")).unwrap();
        let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
        commit_all(&mut src, &files, 1_000);
        let server = start(&root);
        let remote = format!("http://{}", server.addr());
        publish_to(&remote, TOKEN, &src, "main", None).unwrap();

        let err = publish_to(&remote, "wrong-token-0000", &src, "main", None).unwrap_err();
        assert!(
            matches!(err, RemoteError::Net(NetError::Status(401, _))),
            "{err}"
        );
        let central = Repo::open(root.join("central")).unwrap();
        let auth = central
            .journal()
            .events()
            .iter()
            .find(|event| event.kind == "auth")
            .expect("错的 token 必须留下 auth 事件");
        assert_eq!(auth.payload["decision"], "denied");
        assert_eq!(auth.payload["reason"], "bad_token");
        assert_eq!(auth.payload["method"], "POST");
        assert_eq!(auth.payload["path"], "/v1/publish");
        assert_eq!(
            auth.payload["state_before"], auth.payload["state_after"],
            "鉴权失败不改仓库状态"
        );

        // 另一个客户端从零起一条不相干的历史：不是 main 的后代 ⇒ 409。
        let other_dir = root.join("other");
        std::fs::create_dir_all(&other_dir).unwrap();
        let mut other = Repo::init(&other_dir).unwrap();
        let other_files = BTreeMap::from([("x.txt".to_string(), b"x\n".to_vec())]);
        commit_all(&mut other, &other_files, 2_000);
        let err = publish_to(&remote, TOKEN, &other, "main", None).unwrap_err();
        assert!(
            matches!(
                err,
                RemoteError::Repo(RepoError::NonFastForward { .. })
                    | RemoteError::Net(NetError::Status(409, _))
            ),
            "{err}"
        );
        assert_eq!(
            pull_plan(&Repo::open(root.join("central")).unwrap(), "main", None)
                .unwrap()
                .tip,
            src.head().unwrap().unwrap(),
            "被拒的 publish 不该把 ref 挪走"
        );
        server.shutdown();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn second_pull_is_idempotent_and_incremental() {
        let root = temp("again");
        let mut src = Repo::init(root.join("src")).unwrap();
        let files = BTreeMap::from([("a.txt".to_string(), b"a\n".to_vec())]);
        commit_all(&mut src, &files, 1_000);
        let server = start(&root);
        let remote = format!("http://{}", server.addr());
        publish_to(&remote, TOKEN, &src, "main", None).unwrap();

        let client_dir = root.join("client");
        std::fs::create_dir_all(&client_dir).unwrap();
        let mut client = Repo::init(&client_dir).unwrap();
        let first = pull_from(&remote, TOKEN, &mut client, "main", None, false).unwrap();
        let second = pull_from(&remote, TOKEN, &mut client, "main", None, false).unwrap();
        assert_eq!(second.written, 0);
        assert!(second.objects <= first.objects, "重复拉不该再多搬对象");
        assert!(worktree::status(&client).unwrap().is_empty());
        server.shutdown();
        let _ = std::fs::remove_dir_all(&root);
    }
}
