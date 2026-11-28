//! 操作级状态快照：写路径崩溃后，下一次持锁写操作先回到操作前的一致状态。
//!
//! 快照只覆盖 `state_digest` 的输入（HEAD/index/refs/policy/claims/keys），
//! 不碰对象库、日志和工作树。`txn.tmp` 完整落盘后原子改名为 `txn`；恢复只
//! 认 `txn/`，半个 `txn.tmp` 直接丢掉。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::repo::{Repo, RepoError};
use crate::store::ObjectWatermark;

const TXN: &str = "txn";
const TMP: &str = "txn.tmp";
const TRASH: &str = "txn.trash";
const FIXED: &[&str] = &[
    "HEAD",
    "index.json",
    "policy.json",
    "claims.json",
    "keys.json",
];

#[derive(Debug, Serialize, Deserialize)]
struct Meta {
    id: String,
    op: String,
    args: Value,
    state_before: String,
    #[serde(default)]
    objects: Option<ObjectWatermark>,
    files: Vec<FileMeta>,
}

#[derive(Debug, Serialize, Deserialize)]
struct FileMeta {
    path: String,
    present: bool,
    backup: Option<String>,
}

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn txn_dir(repo: &Repo) -> PathBuf {
    Repo::dir(repo.root()).join(TXN)
}

fn tmp_dir(repo: &Repo) -> PathBuf {
    Repo::dir(repo.root()).join(TMP)
}

fn meta_path(dir: &Path) -> PathBuf {
    dir.join("meta.json")
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<(), RepoError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<(), RepoError> {
    // Windows 没有可移植的目录 fsync；文件本身仍逐个 sync_all。
    Ok(())
}

fn rel_path(base: &Path, path: &Path) -> Result<String, RepoError> {
    let rel = path
        .strip_prefix(base)
        .map_err(|_| RepoError::TxnCorrupt(format!("快照路径不在仓库内：{}", path.display())))?;
    Ok(rel
        .components()
        .map(|part| part.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/"))
}

fn collect_refs(
    dir: &Path,
    base: &Path,
    out: &mut BTreeMap<String, Vec<u8>>,
) -> Result<(), RepoError> {
    if !dir.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if entry.file_type()?.is_dir() {
            collect_refs(&path, base, out)?;
            continue;
        }
        out.insert(rel_path(base, &path)?, fs::read(&path)?);
    }
    Ok(())
}

/// 当前状态下所有会被 `state_digest` 计入的文件；`None` 表示文件不存在。
fn state_files(repo: &Repo) -> Result<BTreeMap<String, Option<Vec<u8>>>, RepoError> {
    let base = Repo::dir(repo.root());
    let mut files = BTreeMap::new();
    for rel in FIXED {
        let path = base.join(rel);
        files.insert(
            (*rel).to_string(),
            if path.is_file() {
                Some(fs::read(&path)?)
            } else {
                None
            },
        );
    }
    let mut refs = BTreeMap::new();
    collect_refs(&base.join("refs"), &base, &mut refs)?;
    for (path, bytes) in refs {
        files.insert(path, Some(bytes));
    }
    Ok(files)
}

fn write_snapshot(
    repo: &Repo,
    meta: &Meta,
    files: &BTreeMap<String, Option<Vec<u8>>>,
) -> Result<(), RepoError> {
    let tmp = tmp_dir(repo);
    if tmp.exists() {
        fs::remove_dir_all(&tmp)?;
    }
    fs::create_dir_all(tmp.join("before"))?;
    for (index, file) in meta.files.iter().enumerate() {
        if !file.present {
            continue;
        }
        let Some(Some(bytes)) = files.get(&file.path) else {
            return Err(RepoError::TxnCorrupt(format!(
                "快照清单与状态文件不一致：{}",
                file.path
            )));
        };
        let backup = tmp.join("before").join(index.to_string());
        let mut out = fs::File::create(&backup)?;
        out.write_all(bytes)?;
        out.sync_all()?;
        drop(out);
    }
    let meta_bytes =
        serde_json::to_vec_pretty(meta).map_err(|e| RepoError::TxnCorrupt(e.to_string()))?;
    let path = meta_path(&tmp);
    let mut out = fs::File::create(&path)?;
    out.write_all(&meta_bytes)?;
    out.sync_all()?;
    drop(out);
    sync_dir(&tmp)?;
    if txn_dir(repo).exists() {
        return Err(RepoError::TxnCorrupt(
            "已有未恢复事务，不能开始新操作".to_string(),
        ));
    }
    fs::rename(&tmp, txn_dir(repo))?;
    sync_dir(&Repo::dir(repo.root()))?;
    Ok(())
}

fn read_meta(dir: &Path) -> Result<Meta, RepoError> {
    let bytes = fs::read(meta_path(dir))
        .map_err(|e| RepoError::TxnCorrupt(format!("读 meta.json 失败：{e}")))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| RepoError::TxnCorrupt(format!("meta.json 不成立：{e}")))
}

fn restore(repo: &Repo, meta: &Meta) -> Result<(), RepoError> {
    let base = Repo::dir(repo.root());
    let manifest_refs: BTreeSet<String> = meta
        .files
        .iter()
        .filter(|file| file.path.starts_with("refs/"))
        .map(|file| file.path.clone())
        .collect();
    let mut current_refs = BTreeMap::new();
    collect_refs(&base.join("refs"), &base, &mut current_refs)?;
    for path in current_refs.keys() {
        if !manifest_refs.contains(path) {
            let target = base.join(path);
            if target.is_file() {
                fs::remove_file(target)?;
            }
        }
    }
    for file in &meta.files {
        let target = base.join(&file.path);
        if file.present {
            let backup = file
                .backup
                .as_ref()
                .ok_or_else(|| RepoError::TxnCorrupt(format!("{} 缺备份路径", file.path)))?;
            let bytes = fs::read(txn_dir(repo).join(backup))
                .map_err(|e| RepoError::TxnCorrupt(format!("读 {} 备份失败：{e}", file.path)))?;
            if let Some(parent) = target.parent() {
                fs::create_dir_all(parent)?;
            }
            let mut out = fs::File::create(&target)?;
            out.write_all(&bytes)?;
            out.sync_all()?;
        } else if target.is_file() {
            fs::remove_file(&target)?;
        }
    }
    sync_dir(&base)?;
    Ok(())
}

fn remove_txn(repo: &Repo) -> Result<(), RepoError> {
    let txn = txn_dir(repo);
    let trash = Repo::dir(repo.root()).join(TRASH);
    if txn.exists() {
        if trash.exists() {
            fs::remove_dir_all(&trash)?;
        }
        // 先把完整目录原子挪开，再慢慢删；删到一半崩掉也不会留下“有 txn
        // 但 meta.json 已没了”的不可恢复现场。
        fs::rename(&txn, &trash)?;
    }
    if trash.exists() {
        fs::remove_dir_all(&trash)?;
    }
    let tmp = tmp_dir(repo);
    if tmp.exists() {
        fs::remove_dir_all(&tmp)?;
    }
    Ok(())
}

impl Repo {
    /// 只读检查：有未恢复事务时返回它的 id/op，供 `audit` 判 `txn_pending`。
    pub fn pending_txn(&self) -> Option<String> {
        let dir = txn_dir(self);
        if !dir.is_dir() {
            return None;
        }
        match read_meta(&dir) {
            Ok(meta) => Some(format!("{}#{}", meta.op, meta.id)),
            Err(_) => Some("corrupt".to_string()),
        }
    }

    pub(crate) fn new_txn_id(state_before: &str, seq: u64) -> String {
        // 由“操作前状态 + 下一条事件序号”导出，保证同样的历史得到同样的 id：
        // 事件哈希不能因为进程/时钟不同而漂移，否则 checkpoint 对账不可复现。
        format!("{state_before}-{seq}")
    }

    pub(crate) fn prepare_txn_locked(
        &mut self,
        id: &str,
        op: &str,
        args: &Value,
        state_before: &str,
    ) -> Result<(), RepoError> {
        let before = state_files(self)?;
        let objects = Some(self.store.watermark()?);
        let files = before
            .keys()
            .enumerate()
            .map(|(index, path)| FileMeta {
                path: path.clone(),
                present: before.get(path).is_some_and(Option::is_some),
                backup: before
                    .get(path)
                    .is_some_and(Option::is_some)
                    .then(|| format!("before/{index}")),
            })
            .collect();
        let meta = Meta {
            id: id.to_string(),
            op: op.to_string(),
            args: args.clone(),
            state_before: state_before.to_string(),
            objects,
            files,
        };
        write_snapshot(self, &meta, &before)
    }

    pub(crate) fn clear_txn_locked(&mut self) -> Result<(), RepoError> {
        remove_txn(self)
    }

    /// 持锁恢复：没有 `op_begin` 的 txn 丢弃；有 `op_begin` 无 `op_result` 的
    /// 回滚快照并补一条 recovered 的 `op_result`；已有 `op_result` 的只清目录。
    pub(crate) fn recover_txn_locked(&mut self) -> Result<(), RepoError> {
        let dir = txn_dir(self);
        if !dir.is_dir() {
            let _ = remove_txn(self);
            return Ok(());
        }
        let meta = read_meta(&dir)?;
        let state = self.state_digest()?.to_hex();
        let events = self.journal().events();
        let begin = events
            .iter()
            .rev()
            .find(|event| {
                event.kind == "op_begin"
                    && event.payload.get("txn_id").and_then(Value::as_str) == Some(meta.id.as_str())
            })
            .map(|event| (event.seq, event.hash));
        let result = begin.and_then(|(seq, _)| {
            events
                .iter()
                .rev()
                .find(|event| {
                    event.kind == "op_result"
                        && event.payload.get("begin").and_then(Value::as_u64) == Some(seq)
                })
                .map(|event| event.payload.clone())
        });
        match (begin, result) {
            (None, _) => {
                if state != meta.state_before {
                    return Err(RepoError::TxnCorrupt(format!(
                        "没有 op_begin，但状态已偏离快照（期望 {}，实际 {state}）",
                        meta.state_before
                    )));
                }
                remove_txn(self)?;
            }
            (Some((seq, hash)), None) => {
                restore(self, &meta)?;
                let restored = self.state_digest()?.to_hex();
                if restored != meta.state_before {
                    return Err(RepoError::TxnCorrupt(format!(
                        "回滚后状态与快照不一致（期望 {}，实际 {restored}）",
                        meta.state_before
                    )));
                }
                if let Some(objects) = meta.objects {
                    // 状态已经安全回到操作前，再回收操作体可能写进对象库的
                    // 新块和索引行；对象只追加，截回旧水位不会碰到历史对象。
                    self.store.truncate_to(objects)?;
                }
                self.journal_mut().append(
                    "op_result",
                    json!({
                        "op": meta.op,
                        "begin": seq,
                        "begin_hash": hash.to_hex(),
                        "status": "failed",
                        "state_after": restored,
                        "result": {"error": "recovered_after_crash", "recovered": true},
                        "recovered": true,
                    }),
                    wall_ms(),
                )?;
                remove_txn(self)?;
            }
            (Some(_), Some(payload)) => {
                let after = payload
                    .get("state_after")
                    .and_then(Value::as_str)
                    .ok_or_else(|| RepoError::TxnCorrupt("op_result 缺 state_after".to_string()))?;
                if state != after {
                    return Err(RepoError::TxnCorrupt(format!(
                        "已有 op_result，但状态不等于 state_after（期望 {after}，实际 {state}）"
                    )));
                }
                remove_txn(self)?;
            }
        }
        Ok(())
    }
}
