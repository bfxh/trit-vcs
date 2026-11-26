//! 中央仓 + 按需物化：`publish` 把命名 ref **往前推**（非后代判红），`pull` 只取一个目录的对象并稀疏物化。
//!
//! 搬运走内容寻址：目标已有的块直接跳过，所以第二次拉几乎零字节。
//! v0 是本地/离线（中央仓是另一个目录）；网络、鉴权、跨机认领表都还没做，不在这里宣称。

use crate::bundle::{self, TransferStats};
use crate::hash::Hash;
use crate::repo::{Repo, RepoError};
use crate::sync;
use crate::worktree::{self, WorktreeError};

fn same_repository(left: &Repo, right: &Repo) -> bool {
    fn identity(repo: &Repo) -> std::path::PathBuf {
        let path = repo.root().join(crate::repo::DIR);
        path.canonicalize().unwrap_or(path)
    }
    identity(left) == identity(right)
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, thiserror::Error)]
pub enum CentralError {
    #[error("仓库: {0}")]
    Repo(#[from] RepoError),
    #[error("传输: {0}")]
    Bundle(#[from] bundle::BundleError),
    #[error("工作树: {0}")]
    Worktree(#[from] WorktreeError),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishStats {
    pub commit: Hash,
    pub transfer: TransferStats,
    pub op_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PullStats {
    pub commit: Hash,
    pub transfer: TransferStats,
    pub written: usize,
    pub skipped: usize,
    pub op_id: String,
}

/// 补父链的上限：再多也不该一次搬完整个仓库历史。
const ANCESTOR_CAP: usize = 4_096;

/// 把客户端的某个提交（缺省 HEAD）搬到中央仓，并写上命名 ref。
///
/// ref **只允许往前推**：新提交必须是现有 ref 的后代，否则判红（`--force` 才改写）。
/// 多个智能体共用一个中央仓时，甩掉别人的历史比丢一个文件贵得多。
/// 顺序是先搬对象再判 ref：对象内容寻址且不可变，搬了不挪 ref 盖不掉任何东西；
/// 判红时 ref 一定还在原位（非法名字在搬任何东西之前就被拒）。
pub fn publish(
    client: &mut Repo,
    central: &mut Repo,
    name: &str,
    commit: Option<&Hash>,
    force: bool,
) -> Result<PublishStats, CentralError> {
    Repo::validate_ref(name)?;
    let resolved = match commit {
        Some(id) => *id,
        None => client.head()?.ok_or(RepoError::NothingStaged)?,
    };
    let mut objects = bundle::commit_closure(client.store(), resolved)?;
    let ancestors =
        bundle::missing_ancestors(client.store(), central.store(), resolved, ANCESTOR_CAP)?;
    objects.extend(ancestors.iter().copied());
    for id in std::iter::once(resolved).chain(ancestors) {
        for evidence in sync::commit_evidence(client, &id)? {
            if !objects.contains(&evidence) {
                objects.push(evidence);
            }
        }
    }
    let transfer = bundle::transfer(client.store(), central.store(), &objects)?;
    let op_id = sync::new_op_id();
    let _guard = central.lock_state()?;
    let state_before = central.state_digest()?;
    let previous = central.ref_commit(name)?;
    let mut forced = false;
    if let Some(current) = previous {
        let descendant =
            current == resolved || central.merge_base(&resolved, &current)? == Some(current);
        if !descendant {
            if !force {
                return Err(CentralError::Repo(RepoError::NonFastForward {
                    name: name.to_string(),
                    current: current.short(),
                    incoming: resolved.short(),
                }));
            }
            forced = true;
        }
    }
    central.set_ref_audited_locked(name, &resolved)?;
    sync::append_locked(
        central,
        &sync::SyncSuccess {
            action: "publish",
            op_id: &op_id,
            transport: "local",
            side: "central",
            request_id: None,
            actor: None,
            name,
            commit: resolved,
            stage: "applied",
            detail: serde_json::json!({
                "previous": previous.map(|id| id.to_hex()),
                "forced": forced,
            }),
        },
        state_before,
        now_ms(),
    )?;
    drop(_guard);
    sync::append(
        client,
        &sync::SyncSuccess {
            action: "publish",
            op_id: &op_id,
            transport: "local",
            side: "source",
            request_id: None,
            actor: None,
            name,
            commit: resolved,
            stage: "recorded",
            detail: serde_json::json!({
                "objects": transfer.objects,
                "bytes": transfer.sent_bytes,
            }),
        },
        now_ms(),
    )?;
    Ok(PublishStats {
        commit: resolved,
        transfer,
        op_id,
    })
}

/// 从中央仓拉一个 ref：`prefix` 给定时只搬该目录的树清单与对象闭包，并只物化该目录。
pub fn pull(
    central: &mut Repo,
    client: &mut Repo,
    name: &str,
    prefix: Option<&str>,
    force: bool,
) -> Result<PullStats, CentralError> {
    // ref_commit 自己校验名字：这里不必重复一道挡不住任何副作用的守卫。
    let commit = central
        .ref_commit(name)?
        .ok_or_else(|| RepoError::UnknownRef(name.to_string()))?;
    let commit_obj = central.commit_at(&commit)?;
    // 走和包传输同一条路：发"过滤后的树清单"，原树整体不进客户端。
    let list = bundle::manifest(central.store(), commit_obj.tree, prefix)?;
    let _guard = client.lock_state()?;
    let state_before = client.state_digest()?;
    if prefix.is_none() {
        // 全量 pull 会动 HEAD 与索引：先判快进、再判"有没有 add 了没 commit 的东西"，
        // 两件都过了才开始写工作树（失败时一个字节都不该动）。
        if let Some(head) = client.head()?
            && head != commit
        {
            let base = client.merge_base(&commit, &head)?;
            if !force && base != Some(head) {
                return Err(CentralError::Repo(RepoError::NonFastForward {
                    name: name.to_string(),
                    current: head.short(),
                    incoming: commit.short(),
                }));
            }
        }
        if !force && let Some(paths) = client.staged_paths()? {
            return Err(CentralError::Worktree(WorktreeError::Dirty(
                paths.len(),
                paths,
            )));
        }
    }
    let mut objects = vec![commit];
    objects.extend(bundle::entries_closure(central.store(), &list.entries)?);
    for evidence in sync::commit_evidence(central, &commit)? {
        if !objects.contains(&evidence) {
            objects.push(evidence);
        }
    }
    let transfer = bundle::transfer_scoped(central.store(), client.store(), &objects, &list)?;
    let op_id = sync::new_op_id();
    let central_success = sync::SyncSuccess {
        action: "pull",
        op_id: &op_id,
        transport: "local",
        side: "central",
        request_id: None,
        actor: None,
        name,
        commit,
        stage: "prepared",
        detail: serde_json::json!({"prefix": prefix, "files": list.entries.len()}),
    };
    if same_repository(central, client) {
        sync::append_locked(central, &central_success, state_before, now_ms())?;
    } else {
        sync::append(central, &central_success, now_ms())?;
    }
    let stats = worktree::materialize(client.store(), &list.id, client.root(), prefix, force)?;
    match prefix {
        None => {
            let paths: Vec<String> = list.entries.keys().cloned().collect();
            client.adopt_audited_locked(&commit, &list.id, &paths)?;
        }
        Some(prefix) => {
            // 前缀 pull 不挪 HEAD，但要把"只检出了这个范围、基准是这棵树"记下来：
            // 下一次 `status` 才有得比，范围外的文件也不会被算成新增/删除。
            let index = crate::sparse::SparseIndex::new(prefix, list.id, Some(commit))
                .map_err(WorktreeError::Sparse)?;
            index.save(client.root()).map_err(WorktreeError::Sparse)?;
        }
    }
    sync::append_locked(
        client,
        &sync::SyncSuccess {
            action: "pull",
            op_id: &op_id,
            transport: "local",
            side: "client",
            request_id: None,
            actor: None,
            name,
            commit,
            stage: "applied",
            detail: serde_json::json!({
                "prefix": prefix,
                "forced": force,
                "written": stats.written,
                "skipped": stats.skipped,
            }),
        },
        state_before,
        now_ms(),
    )?;
    Ok(PullStats {
        commit,
        transfer,
        written: stats.written,
        skipped: stats.skipped,
        op_id,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::gate::ClaimSpec;
    use crate::repo::CommitRequest;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trit-vcs-central-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn corpus(dirs: usize, per: usize) -> BTreeMap<String, Vec<u8>> {
        let mut out = BTreeMap::new();
        for d in 0..dirs {
            for f in 0..per {
                out.insert(
                    format!("gen/d{d:02}/f{f}.txt"),
                    format!(
                        "dir {d} file {f} body
"
                    )
                    .into_bytes(),
                );
            }
        }
        out
    }

    fn commit_all(repo: &mut Repo, files: &BTreeMap<String, Vec<u8>>, now: u64) -> Hash {
        repo.stage(files, now).unwrap();
        repo.commit(CommitRequest {
            message: format!("c{now}"),
            session: "qoder:central".to_string(),
            claims: vec![ClaimSpec {
                id: format!("c{now}"),
                owner: "qoder:central".to_string(),
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

    fn commit_node(repo: &mut Repo, name: &str, parents: Vec<Hash>, now: u64) -> Hash {
        let files = BTreeMap::from([(format!("{name}.txt"), name.as_bytes().to_vec())]);
        repo.stage(&files, now).unwrap();
        repo.commit(CommitRequest {
            message: name.to_string(),
            session: "qoder:central".to_string(),
            claims: Vec::new(),
            allow_unclaimed: true,
            parents_override: Some(parents),
            now_secs: now,
            ..Default::default()
        })
        .unwrap()
        .id
    }

    fn open_repo(path: &std::path::Path) -> Repo {
        std::fs::create_dir_all(path).unwrap();
        Repo::init(path).unwrap()
    }

    fn assert_local_sync(repo: &Repo, action: &str, side: &str, op_id: &str) {
        let event = repo
            .journal()
            .events()
            .iter()
            .find(|event| {
                event.kind == action
                    && event.payload["schema"] == sync::SCHEMA
                    && event.payload["side"] == side
            })
            .unwrap_or_else(|| panic!("缺 {action}/{side} 本地事件"));
        assert_eq!(event.payload["op_id"], op_id);
        assert_eq!(event.payload["transport"], "local");
        assert!(event.payload["request_id"].is_null());
        assert!(event.payload["actor"].is_null());
        assert_eq!(event.payload["name"], "main");
    }

    fn assert_audit_clean(repo: &Repo) {
        let report = crate::audit::status(repo).unwrap();
        assert!(report.ok, "{}: {:#?}", repo.root().display(), report.issues);
    }

    #[test]
    fn state_lock_blocks_publish_and_pull() {
        let root = temp("state-lock");
        let files = corpus(1, 1);
        let mut src = open_repo(&root.join("src"));
        commit_all(&mut src, &files, 1_000);
        let mut central = open_repo(&root.join("central"));
        publish(&mut src, &mut central, "main", None, false).unwrap();
        let mut client = open_repo(&root.join("client"));

        let guard = crate::claims::lock(central.root()).unwrap();
        assert!(matches!(
            publish(&mut src, &mut central, "main", None, false),
            Err(CentralError::Repo(RepoError::StateLocked(_)))
        ));
        drop(guard);

        let guard = crate::claims::lock(client.root()).unwrap();
        assert!(matches!(
            pull(&mut central, &mut client, "main", Some("gen/d00"), false),
            Err(CentralError::Repo(RepoError::StateLocked(_)))
        ));
        drop(guard);
        assert!(pull(&mut central, &mut client, "main", Some("gen/d00"), false).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn publish_then_pull_prefix_sends_only_that_closure() {
        let root = temp("pull");
        let files = corpus(20, 10)
            .into_iter()
            .map(|(path, body)| (path, body.repeat(40)))
            .collect();
        let mut src = open_repo(&root.join("src"));
        let commit = commit_all(&mut src, &files, 1_000);

        let mut central = open_repo(&root.join("central"));
        let published = publish(&mut src, &mut central, "main", None, false).unwrap();
        assert_eq!(published.commit, commit);
        assert_local_sync(&src, "publish", "source", &published.op_id);
        assert_local_sync(&central, "publish", "central", &published.op_id);
        assert!(published.transfer.sent_bytes > 0);
        assert_eq!(central.ref_commit("main").unwrap(), Some(commit));

        let client_dir = root.join("client");
        let mut client = open_repo(&client_dir);
        let pulled = pull(&mut central, &mut client, "main", Some("gen/d00"), false).unwrap();
        assert_local_sync(&central, "pull", "central", &pulled.op_id);
        assert_local_sync(&client, "pull", "client", &pulled.op_id);
        assert!(
            pulled.transfer.sent_bytes * 10 < published.transfer.total_bytes,
            "单目录应远小于全量：{} vs {}",
            pulled.transfer.sent_bytes,
            published.transfer.total_bytes
        );
        assert!(client_dir.join("gen/d00/f0.txt").is_file());
        assert!(!client_dir.join("gen/d01").exists(), "范围外不该被物化");
        assert_eq!(pulled.written, 10, "只该写这个目录的 10 个文件");
        let full_tree = central.commit_at(&commit).unwrap().tree;
        assert!(
            !client.store().has_chunk(&full_tree),
            "整棵原树不该进客户端（否则单目录 = 全量）"
        );

        let again = pull(&mut central, &mut client, "main", Some("gen/d00"), false).unwrap();
        assert_eq!(again.transfer.sent_bytes, 0, "第二次不该再传内容");
        assert_eq!(again.written, 0, "已一致就不该重写");
        assert_audit_clean(&src);
        assert_audit_clean(&central);
        assert_audit_clean(&client);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn publish_carries_side_branch_commit_objects() {
        let root = temp("publish-side-parent");
        let mut src = open_repo(&root.join("src"));
        let base = commit_node(&mut src, "base", vec![], 1_000);
        let left = commit_node(&mut src, "left", vec![base], 1_001);
        let right = commit_node(&mut src, "right", vec![base], 1_002);
        let merge = commit_node(&mut src, "merge", vec![left, right], 1_003);
        let tip = commit_node(&mut src, "tip", vec![merge], 1_004);

        let mut central = open_repo(&root.join("central"));
        publish(&mut src, &mut central, "main", Some(&left), false).unwrap();
        publish(&mut src, &mut central, "main", Some(&tip), false).unwrap();
        assert_eq!(central.ref_commit("main").unwrap(), Some(tip));
        for id in [base, left, right, merge, tip] {
            assert!(
                central.store().has_chunk(&id),
                "中央仓缺父提交 {id}：publish 不能只走第一父"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn same_repository_pull_uses_one_state_lock() {
        let root = temp("same-repository-pull");
        let files = corpus(1, 1);
        let shared_dir = root.join("shared");
        let mut client = open_repo(&shared_dir);
        let commit = commit_all(&mut client, &files, 1_000);
        client.set_ref("main", &commit).unwrap();
        let mut central = crate::repo::Repo::open(&shared_dir).unwrap();
        let other = open_repo(&root.join("other"));
        assert!(same_repository(&central, &client));
        assert!(!same_repository(&central, &other));
        drop(other);
        let state_before = client.state_digest().unwrap();

        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let result = pull(&mut central, &mut client, "main", Some("gen/d00"), false);
            tx.send((result, central, client)).unwrap();
        });
        let (result, central, client) = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("同仓 pull 递归抢锁，五秒内没有返回");
        let pulled = result.unwrap();
        assert_local_sync(&central, "pull", "central", &pulled.op_id);
        assert_local_sync(&client, "pull", "client", &pulled.op_id);
        let prepared = central
            .journal()
            .events()
            .iter()
            .find(|event| event.kind == "pull" && event.payload["side"] == "central")
            .unwrap();
        assert_eq!(prepared.payload["state_before"], state_before.to_hex());
        assert_audit_clean(&central);
        assert_audit_clean(&client);
        worker.join().unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pull_refuses_to_overwrite_local_changes() {
        let root = temp("dirty");
        let files = corpus(3, 2);
        let mut src = open_repo(&root.join("src"));
        commit_all(&mut src, &files, 1_000);
        let mut central = open_repo(&root.join("central"));
        publish(&mut src, &mut central, "main", None, false).unwrap();

        let client_dir = root.join("client");
        let mut client = open_repo(&client_dir);
        pull(&mut central, &mut client, "main", Some("gen/d00"), false).unwrap();
        std::fs::write(client_dir.join("gen/d00/f0.txt"), b"local edit").unwrap();

        let err = pull(&mut central, &mut client, "main", Some("gen/d00"), false).unwrap_err();
        assert!(
            matches!(
                err,
                CentralError::Worktree(worktree::WorktreeError::Dirty(..))
            ),
            "{err:?}"
        );
        assert_eq!(
            std::fs::read(client_dir.join("gen/d00/f0.txt")).unwrap(),
            b"local edit",
            "报错时一个字节都不该动"
        );
        let forced = pull(&mut central, &mut client, "main", Some("gen/d00"), true).unwrap();
        assert_eq!(forced.written, 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn refs_are_named_and_listed() {
        let root = temp("refs");
        let mut src = open_repo(&root.join("src"));
        let files = corpus(2, 1);
        let first = commit_all(&mut src, &files, 1_000);
        let mut central = open_repo(&root.join("central"));
        publish(&mut src, &mut central, "nightly", Some(&first), false).unwrap();
        publish(&mut src, &mut central, "main", Some(&first), false).unwrap();
        let refs = central.list_refs().unwrap();
        assert_eq!(
            refs.iter()
                .map(|(name, _)| name.as_str())
                .collect::<Vec<_>>(),
            vec!["main", "nightly"]
        );
        let kinds: Vec<&str> = central
            .journal()
            .events()
            .iter()
            .filter(|event| event.kind == "ref")
            .map(|_| "ref")
            .collect();
        assert_eq!(kinds.len(), 2, "每次写 ref 都要进哈希链");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn bad_names_and_missing_refs_are_loud() {
        let root = temp("errors");
        let mut src = open_repo(&root.join("src"));
        let files = corpus(1, 1);
        commit_all(&mut src, &files, 1_000);
        let mut central = open_repo(&root.join("central"));
        for name in ["", "a/b", "..", ".hidden", "a b", &"x".repeat(65)] {
            assert!(
                matches!(
                    publish(&mut src, &mut central, name, None, false),
                    Err(CentralError::Repo(RepoError::BadRefName(_)))
                ),
                "{name:?} 必须被拒"
            );
        }
        assert_eq!(
            central.store().stats().unwrap().objects,
            0,
            "非法名必须在搬对象之前就被拒（名字坏了不该先往中央仓写块）"
        );
        let mut client = open_repo(&root.join("client"));
        assert!(matches!(
            pull(&mut central, &mut client, "main", None, false).unwrap_err(),
            CentralError::Repo(RepoError::UnknownRef(_))
        ));
        assert!(
            matches!(
                pull(&mut central, &mut client, "a/b", None, false).unwrap_err(),
                CentralError::Repo(RepoError::BadRefName(_))
            ),
            "pull 侧的非法名由 ref_commit 挡住，且不能落到别处"
        );
        assert_eq!(
            client.store().stats().unwrap().objects,
            0,
            "被拒的 pull 不该在客户端留下任何对象"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn publish_only_moves_a_ref_forwards() {
        let root = temp("forward");
        let files = corpus(2, 1);
        let mut src = open_repo(&root.join("src"));
        let first = commit_all(&mut src, &files, 1_000);
        let second = commit_all(&mut src, &corpus(2, 2), 1_001);

        // 中央仓是空的：先推 HEAD（second），父链得跟着补齐
        let mut central = open_repo(&root.join("central"));
        publish(&mut src, &mut central, "main", Some(&second), false).unwrap();
        assert_eq!(central.ref_commit("main").unwrap(), Some(second));
        assert!(
            central.commit_at(&first).is_ok(),
            "父提交对象必须一起搬来，否则中央仓连分叉都判不了"
        );

        // 直接退回父提交 ⇒ 判红，且 ref 还在原位
        let err = publish(&mut src, &mut central, "main", Some(&first), false).unwrap_err();
        assert!(
            matches!(err, CentralError::Repo(RepoError::NonFastForward { .. })),
            "{err:?}"
        );
        assert_eq!(central.ref_commit("main").unwrap(), Some(second));

        // 另起一条分叉线（父指针强行指回 first）⇒ 同样判红
        let diverged = {
            let other = corpus(1, 1);
            src.stage(&other, 1_005).unwrap();
            src.commit(CommitRequest {
                message: "diverged".to_string(),
                session: "qoder:central".to_string(),
                claims: vec![ClaimSpec {
                    id: "c5".to_string(),
                    owner: "qoder:central".to_string(),
                    paths: other.keys().cloned().collect(),
                    acquired_at: 1,
                    expires_at: u64::MAX / 2,
                }],
                parents_override: Some(vec![first]),
                now_secs: 1_005,
                ..Default::default()
            })
            .unwrap()
            .id
        };
        assert!(matches!(
            publish(&mut src, &mut central, "main", Some(&diverged), false).unwrap_err(),
            CentralError::Repo(RepoError::NonFastForward { .. })
        ));
        assert_eq!(
            central.ref_commit("main").unwrap(),
            Some(second),
            "分叉提交不该把 ref 挪走"
        );

        // 显式改写（--force）才允许
        publish(&mut src, &mut central, "main", Some(&diverged), true).unwrap();
        assert_eq!(central.ref_commit("main").unwrap(), Some(diverged));
        // 幂等重推同一个提交不算倒退
        publish(&mut src, &mut central, "main", Some(&diverged), false).unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn pull_without_prefix_materializes_everything() {
        let root = temp("full");
        let files = corpus(4, 2);
        let mut src = open_repo(&root.join("src"));
        commit_all(&mut src, &files, 1_000);
        let mut central = open_repo(&root.join("central"));
        publish(&mut src, &mut central, "main", None, false).unwrap();

        let client_dir = root.join("client");
        let mut client = open_repo(&client_dir);
        let pulled = pull(&mut central, &mut client, "main", None, false).unwrap();
        assert_eq!(pulled.written, 8, "全量 pull 该写满 8 个文件");
        let full_tree = central.commit_at(&pulled.commit).unwrap().tree;
        assert!(
            client.store().has_chunk(&full_tree),
            "不限定范围时清单就是原树，必须落进客户端"
        );
        let _ = std::fs::remove_dir_all(&root);
    }
}
