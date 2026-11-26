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
use crate::sync;
use crate::view::{self, Pin, PinStatus, Snapshot, ViewError, ViewSignature};
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
    #[error("跨机视图：{0}")]
    View(#[from] ViewError),
    #[error("服务端视图与同步回执不一致：{0}")]
    ViewMismatch(String),
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
            | RemoteError::View(_)
            | RemoteError::ViewMismatch(_)
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
            RemoteError::Worktree(inner) => crate::remediation::kind_worktree(inner),
            RemoteError::TipMissing(_) => "tip_missing",
            RemoteError::HistoryGap(_) => "history_gap",
            RemoteError::TreeIncomplete(_) => "tree_incomplete",
            RemoteError::View(inner) => inner.kind(),
            RemoteError::ViewMismatch(_) => "remote_view_mismatch",
        }
    }
}

/// 发布读数：发了多少对象、多少字节。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublishStats {
    pub commit: Option<Hash>,
    pub objects: usize,
    pub bytes: u64,
    pub op_id: String,
    pub request_id: String,
    pub view: Option<Snapshot>,
    pub view_signer: Option<String>,
    pub pin_status: Option<PinStatus>,
}

/// 拉取读数：服务端声明与实际收到的对象、物化结果。
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PullStats {
    pub commit: Option<Hash>,
    pub written: usize,
    pub skipped: usize,
    pub objects: usize,
    pub op_id: String,
    pub request_id: String,
    pub view: Option<Snapshot>,
    pub view_signer: Option<String>,
    pub pin_status: Option<PinStatus>,
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
            RemoteError::View(inner) => inner.commands(),
            RemoteError::ViewMismatch(detail) => vec![
                detail.to_string(),
                "不要改写工作树；先 `trit-vcs view <ref> --remote http://… --token-file <文件> --json` 对服务端视图".to_string(),
                "如果服务端刚换过 ref，重跑一次 pull；仍然不一致就按回滚/分裂视图处理".to_string(),
            ],
        }
    }
}

/// 客户端 publish：把 `commit`（缺省 HEAD）的闭包与第一父链发到 `ref`。
pub fn publish_to(
    remote: &str,
    token: &str,
    repo: &mut Repo,
    name: &str,
    commit: Option<&Hash>,
) -> Result<PublishStats, RemoteError> {
    publish_to_with(remote, token, repo, name, commit, true)
}

/// `pin=false` 只用于明确的兼容降级：不读/不写视图，也就不检测服务端回滚与改写。
pub fn publish_to_with(
    remote: &str,
    token: &str,
    repo: &mut Repo,
    name: &str,
    commit: Option<&Hash>,
    pin_enabled: bool,
) -> Result<PublishStats, RemoteError> {
    Repo::validate_ref(name)?;
    let tip = match commit {
        Some(id) => *id,
        None => repo.head()?.ok_or(RepoError::NothingStaged)?,
    };
    let body = publish_body(repo, tip)?;
    let bytes = body.byte_len(repo.store())?;
    let op_id = sync::new_op_id();
    let client = Client::new(remote, token)?;
    let remote_base = client.base().to_string();
    let pinned = if pin_enabled {
        match precheck_pin(&client, repo, name) {
            Ok(pin) => pin,
            Err(err) => {
                repo.record_deny(
                    "publish",
                    err.kind(),
                    &err.to_string(),
                    serde_json::json!({
                        "ref": name,
                        "commit": tip.to_hex(),
                        "op_id": op_id,
                        "remote": remote_base,
                    }),
                );
                return Err(err);
            }
        }
    } else {
        None
    };
    let reply = client.publish(name, &tip, &body, repo.store(), &op_id)?;
    let (snapshot, signature, pin_status) = if pin_enabled {
        match finish_view(&client, name, &pinned, tip) {
            Ok((view, status, signature)) => (Some(view), signature, Some(status)),
            Err(err) => {
                repo.record_deny(
                    "publish",
                    err.kind(),
                    &err.to_string(),
                    serde_json::json!({
                        "ref": name,
                        "commit": tip.to_hex(),
                        "request_id": reply.request_id,
                        "op_id": op_id,
                        "remote": remote_base,
                    }),
                );
                return Err(err);
            }
        }
    } else {
        (None, None, None)
    };
    sync::append(
        repo,
        &sync::SyncSuccess {
            action: "publish",
            op_id: &op_id,
            transport: "http",
            side: "source",
            request_id: Some(&reply.request_id),
            actor: None,
            name,
            commit: tip,
            stage: "recorded",
            detail: serde_json::json!({
                "objects": body.count(),
                "bytes": bytes,
                "remote": remote_base,
                "view": snapshot.as_ref().map(|view| {
                    crate::view::evidence_json(
                        view,
                        pinned.as_ref(),
                        pin_status.unwrap_or(PinStatus::First),
                        signature.as_ref(),
                    )
                }),
            }),
        },
        sync::now_ms(),
    )?;
    Ok(PublishStats {
        commit: Some(tip),
        objects: body.count() as usize,
        bytes,
        op_id,
        request_id: reply.request_id,
        view: snapshot,
        view_signer: signature.map(|signature| signature.key_id),
        pin_status,
    })
}

/// 联网前先验本地 pin：服务端如果已经回滚/换链，连对象都不要发、不要收。
fn precheck_pin(client: &Client, repo: &Repo, name: &str) -> Result<Option<Pin>, RemoteError> {
    let Some(pin) = view::latest_pin(repo, client.base(), name)? else {
        return Ok(None);
    };
    let reply = client.view(name, Some((pin.height, pin.root)))?;
    view::verify_view_signature(Some(&pin), name, &reply.snapshot, reply.signature.as_ref())?;
    view::verify_pin(Some(&pin), &reply.snapshot, reply.consistency.as_ref())?;
    Ok(Some(pin))
}

/// 同步成功后取服务端视图：证明这次仍扩展了上一次 pin，并核对 ref tip 与回执一致。
fn finish_view(
    client: &Client,
    name: &str,
    pin: &Option<Pin>,
    expected_tip: Hash,
) -> Result<(Snapshot, PinStatus, Option<ViewSignature>), RemoteError> {
    let reply = client.view(name, pin.as_ref().map(|pin| (pin.height, pin.root)))?;
    view::verify_view_signature(
        pin.as_ref(),
        name,
        &reply.snapshot,
        reply.signature.as_ref(),
    )?;
    let status = view::verify_pin(pin.as_ref(), &reply.snapshot, reply.consistency.as_ref())?;
    if reply.snapshot.tip != Some(expected_tip) {
        return Err(RemoteError::ViewMismatch(format!(
            "服务端视图的 ref {name} 指向 {:?}，同步回执是 {}",
            reply
                .snapshot
                .tip
                .map(|id| id.short())
                .unwrap_or_else(|| "-".to_string()),
            expected_tip.short()
        )));
    }
    Ok((reply.snapshot, status, reply.signature))
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
    for id in sync::commit_evidence(repo, &tip)? {
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
        for evidence in sync::commit_evidence(repo, &id)? {
            if seen.insert(evidence) {
                body.objects.push(evidence);
            }
        }
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
    accept_publish_correlated(central, name, tip, &sync::new_op_id(), None, None, "local")
}

pub(crate) fn accept_publish_correlated(
    central: &mut Repo,
    name: &str,
    tip: &Hash,
    op_id: &str,
    request_id: Option<&str>,
    actor: Option<&str>,
    transport: &str,
) -> Result<Option<Hash>, RemoteError> {
    Repo::validate_ref(name)?;
    let commit = central.commit_at(tip).map_err(|err| match err {
        RepoError::Store(StoreError::Missing(_)) | RepoError::UnknownCommit(_) => {
            RemoteError::TipMissing(tip.to_hex())
        }
        other => other.into(),
    })?;
    ensure_tree_present(central.store(), &commit.tree)?;
    let _guard = central.lock_state()?;
    let state_before = central.state_digest()?;
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
    central.set_ref_audited_locked(name, tip)?;
    sync::append_locked(
        central,
        &sync::SyncSuccess {
            action: "publish",
            op_id,
            transport,
            side: "central",
            request_id,
            actor,
            name,
            commit: *tip,
            stage: "applied",
            detail: serde_json::json!({"previous": previous.map(|id| id.to_hex()), "forced": false}),
        },
        state_before,
        sync::now_ms(),
    )?;
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
    for id in sync::commit_evidence(central, &tip)? {
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
    pull_from_with(remote, token, repo, name, prefix, force, true)
}

/// `pin=false` 只用于明确的兼容降级：不读/不写视图，也就不检测服务端回滚与改写。
pub fn pull_from_with(
    remote: &str,
    token: &str,
    repo: &mut Repo,
    name: &str,
    prefix: Option<&str>,
    force: bool,
    pin_enabled: bool,
) -> Result<PullStats, RemoteError> {
    // 全量 pull 会覆盖工作树；在发请求、收对象之前就把脏工作树挡住。
    // 否则拒绝虽然会记账，但对象库里已经多出一批不可达对象，写前约束就漏了。
    if prefix.is_none() && !force {
        let changes = worktree::status(repo)?;
        if !changes.is_empty() {
            let paths: Vec<String> = changes.iter().map(|change| change.path.clone()).collect();
            let err: RemoteError = WorktreeError::Dirty(paths.len(), paths).into();
            repo.record_deny(
                "pull",
                "worktree_dirty",
                &err.to_string(),
                serde_json::json!({"ref": name, "prefix": prefix}),
            );
            return Err(err);
        }
    }
    let op_id = sync::new_op_id();
    let client = Client::new(remote, token)?;
    let remote_base = client.base().to_string();
    let pinned = if pin_enabled {
        match precheck_pin(&client, repo, name) {
            Ok(pin) => pin,
            Err(err) => {
                repo.record_deny(
                    "pull",
                    err.kind(),
                    &err.to_string(),
                    serde_json::json!({
                        "ref": name,
                        "prefix": prefix,
                        "op_id": op_id,
                        "remote": remote_base,
                    }),
                );
                return Err(err);
            }
        }
    } else {
        None
    };
    let reply = client.pull(name, prefix, repo.store(), Limits::default(), &op_id)?;
    let (snapshot, signature, pin_status) = if pin_enabled {
        match finish_view(&client, name, &pinned, reply.tip) {
            Ok((view, status, signature)) => (Some(view), signature, Some(status)),
            Err(err) => {
                repo.record_deny(
                    "pull",
                    err.kind(),
                    &err.to_string(),
                    serde_json::json!({
                        "ref": name,
                        "prefix": prefix,
                        "tip": reply.tip.to_hex(),
                        "request_id": reply.request_id,
                        "op_id": op_id,
                        "remote": remote_base,
                    }),
                );
                return Err(err);
            }
        }
    } else {
        (None, None, None)
    };
    let view_signer = signature.as_ref().map(|signature| signature.key_id.clone());
    let view_evidence = snapshot.as_ref().map(|view| {
        view::evidence_json(
            view,
            pinned.as_ref(),
            pin_status.unwrap_or(PinStatus::First),
            signature.as_ref(),
        )
    });
    let result = apply_pull(
        repo,
        &reply,
        prefix,
        force,
        name,
        &op_id,
        &remote_base,
        view_evidence,
    );
    if let Err(err) = &result {
        repo.record_deny(
            "pull",
            err.kind(),
            &err.to_string(),
            serde_json::json!({
                "ref": name,
                "prefix": prefix,
                "tip": reply.tip.to_hex(),
                "request_id": reply.request_id,
                "op_id": op_id,
            }),
        );
    }
    let mut stats = result?;
    stats.view = snapshot;
    stats.view_signer = view_signer;
    stats.pin_status = pin_status;
    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn apply_pull(
    repo: &mut Repo,
    reply: &PullReply,
    prefix: Option<&str>,
    force: bool,
    name: &str,
    op_id: &str,
    remote: &str,
    view_evidence: Option<serde_json::Value>,
) -> Result<PullStats, RemoteError> {
    if !repo.store().has_chunk(&reply.tip) {
        return Err(RemoteError::TipMissing(reply.tip.to_hex()));
    }
    let commit = repo.commit_at(&reply.tip)?;
    for evidence in sync::commit_evidence(repo, &reply.tip)? {
        if !repo.store().has_chunk(&evidence) {
            return Err(RemoteError::HistoryGap(format!(
                "提交 {} 的证据对象 {evidence} 没随 pull 传来",
                reply.tip.short()
            )));
        }
    }
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
    let _guard = repo.lock_state()?;
    let state_before = repo.state_digest()?;
    if prefix.is_none() {
        check_fast_forward(repo, reply.tip, name, force)?;
        if !force && let Some(paths) = repo.staged_paths()? {
            return Err(WorktreeError::Dirty(paths.len(), paths).into());
        }
    }
    let stats = worktree::materialize(repo.store(), &reply.manifest, repo.root(), prefix, force)?;
    if prefix.is_none() {
        let paths: Vec<String> = entries.keys().cloned().collect();
        repo.adopt_audited_locked(&reply.tip, &reply.manifest, &paths)?;
    } else if let Some(prefix) = prefix {
        let index = crate::sparse::SparseIndex::new(prefix, reply.manifest, Some(reply.tip))
            .map_err(WorktreeError::Sparse)?;
        index.save(repo.root()).map_err(WorktreeError::Sparse)?;
    }
    sync::append_locked(
        repo,
        &sync::SyncSuccess {
            action: "pull",
            op_id,
            transport: "http",
            side: "client",
            request_id: Some(&reply.request_id),
            actor: None,
            name,
            commit: reply.tip,
            stage: "applied",
            detail: serde_json::json!({
                "prefix": prefix,
                "forced": force,
                "written": stats.written,
                "skipped": stats.skipped,
                "remote": remote,
                "view": view_evidence,
            }),
        },
        state_before,
        sync::now_ms(),
    )?;
    Ok(PullStats {
        commit: Some(reply.tip),
        written: stats.written,
        skipped: stats.skipped,
        objects: reply.objects,
        op_id: op_id.to_string(),
        request_id: reply.request_id.clone(),
        ..Default::default()
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
mod tests;
#[cfg(test)]
mod view_tests;
