//! 单文件离线审计包：原始事件链、仓库状态、独立推导的证据对象闭包与独立外锚。

mod container;
mod evidence;

use std::collections::BTreeSet;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::audit::{self, AuditError, AuditReport};
use crate::checkpoint::anchor::{AnchorError, AnchorOutcome};
use crate::checkpoint::external::{self, ExternalAnchor};
use crate::claims::ClaimsError;
use crate::hash::Hash;
use crate::remediation::{Context, Remediable};
use crate::repo::{DIR, Repo, RepoError};
use crate::store::StoreError;

use container::{
    Decoded, Piece, open_regular_file, read_file, validate_piece_name, write_new_file,
};
pub use container::{
    MAGIC, MAX_BUNDLE_BYTES, MAX_EVENTS, MAX_MANIFEST_BYTES, MAX_PIECE_BYTES, MAX_PIECES, Manifest,
    PieceRef, SCHEMA,
};

const MAX_ANCHOR_BYTES: u64 = 1024 * 1024;
const OBJECT_PREFIX: &str = "object:";

#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("审计包 JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("仓库: {0}")]
    Repo(#[from] RepoError),
    #[error("对象库: {0}")]
    Store(#[from] StoreError),
    #[error("审计: {0}")]
    Audit(#[from] AuditError),
    #[error("外锚: {0}")]
    Anchor(#[from] AnchorError),
    #[error("{kind}: {detail}")]
    Invalid { kind: &'static str, detail: String },
}

impl BundleError {
    pub(crate) fn invalid(kind: &'static str, detail: impl Into<String>) -> Self {
        Self::Invalid {
            kind,
            detail: detail.into(),
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::Io(_) => "audit_bundle_io",
            Self::Json(_) => "audit_bundle_bad",
            Self::Repo(err) => err.kind(),
            Self::Store(err) => crate::remediation::kind_store(err),
            Self::Audit(AuditError::Io(_)) => "audit_bundle_io",
            Self::Audit(AuditError::Repo(_)) => "audit_bundle_repo",
            Self::Audit(AuditError::Journal(_)) => "audit_bundle_journal",
            Self::Anchor(err) => err.kind(),
            Self::Invalid { kind, .. } => kind,
        }
    }
}

impl Remediable for BundleError {
    fn kind(&self) -> &'static str {
        BundleError::kind(self)
    }

    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        let repo = ctx.dir.display().to_string();
        match self.kind() {
            "anchor_untrusted" | "anchor_signature_invalid" => vec![
                "从仓库外的独立渠道重新取得锚公钥；不要从包内 keys.json 推导".to_string(),
                "核对 --anchor-public-key 与外锚文件，再重新验证".to_string(),
            ],
            "audit_bundle_incomplete" => vec![
                format!("cargo run -p trit-vcs -- audit status --json --repo {repo}"),
                "修复审计问题后重新打检查点与独立外锚，再导出 TVAB".to_string(),
            ],
            "audit_bundle_hash_mismatch" | "audit_bundle_truncated" | "audit_bundle_trailing" => {
                vec!["向包提供方重新索取完整 TVAB；不要修补后继续信任".to_string()]
            }
            "audit_bundle_exists" => {
                vec!["换一个新的 --out 路径；TVAB 导出拒绝覆盖旧文件".to_string()]
            }
            "state_locked" => {
                vec!["等正在写入仓库的进程结束后重试；不要删除 claims.lock".to_string()]
            }
            _ => vec![
                "核对错误详情、文件路径与 --anchor-public-key 后重试".to_string(),
                "仍失败时向包提供方索取未经修补的完整 TVAB".to_string(),
            ],
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct BundleReport {
    pub ok: bool,
    pub package_id: String,
    pub events: usize,
    pub objects: usize,
    pub pieces: usize,
    pub bytes: u64,
    pub anchor: AnchorOutcome,
    pub audit: AuditReport,
}

pub fn load_anchor(path: &Path) -> Result<ExternalAnchor, BundleError> {
    let file = open_regular_file(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_ANCHOR_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ANCHOR_BYTES {
        return Err(BundleError::invalid(
            "audit_bundle_too_large",
            format!("外锚文件超过 {} 字节", MAX_ANCHOR_BYTES),
        ));
    }
    Ok(serde_json::from_slice(&bytes)?)
}

pub fn export(
    root: &Path,
    anchor: &ExternalAnchor,
    pinned_public: &str,
    out: &Path,
) -> Result<BundleReport, BundleError> {
    if !root.join(DIR).is_dir() {
        return Err(RepoError::NotInitialized(root.join(DIR).display().to_string()).into());
    }
    let _guard = lock_repo(root)?;
    let repo = Repo::open(root)?;
    let anchor_outcome = external::verify_against_repo(&repo, anchor, pinned_public)?;
    let events = require_checkpoint_completion(&repo, anchor)?;
    let audit = require_clean_audit(&repo)?;
    let required_objects = evidence::validate(&repo)?;
    let mut pieces = state_pieces(&repo)?;
    for id in required_objects {
        let bytes = repo.store().get_chunk(&id)?;
        pieces.push(make_piece(
            format!("{OBJECT_PREFIX}{}", id.to_hex()),
            bytes,
        )?);
    }
    pieces.sort_by(|left, right| left.reference.name.cmp(&right.reference.name));
    let manifest = Manifest {
        schema: SCHEMA,
        event_count: events,
        state_digest: audit.state_digest.clone(),
        anchor: anchor.clone(),
        pieces: pieces.iter().map(|piece| piece.reference.clone()).collect(),
    };
    let package_id = Hash::of(&serde_json::to_vec(&manifest)?).to_hex();
    let objects = pieces
        .iter()
        .filter(|piece| piece.reference.name.starts_with(OBJECT_PREFIX))
        .count();
    let bytes = write_new_file(out, &manifest, &pieces)?;
    Ok(BundleReport {
        ok: true,
        package_id,
        events,
        objects,
        pieces: pieces.len(),
        bytes,
        anchor: anchor_outcome,
        audit,
    })
}

pub fn verify_file(path: &Path, pinned_public: &str) -> Result<BundleReport, BundleError> {
    let decoded = read_file(path)?;
    let package_id = Hash::of(&decoded.manifest_bytes).to_hex();
    decoded.manifest.anchor.verify_with_key(pinned_public)?;
    let mut temp = TempRepo::new()?;
    let result = (|| -> Result<BundleReport, BundleError> {
        restore(&temp, &decoded)?;
        let repo = Repo::open(temp.root())?;
        let anchor_outcome =
            external::verify_against_repo(&repo, &decoded.manifest.anchor, pinned_public)?;
        let events = require_checkpoint_completion(&repo, &decoded.manifest.anchor)?;
        if events != decoded.manifest.event_count {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                format!(
                    "manifest 记 {} 条事件，重建日志实际 {} 条",
                    decoded.manifest.event_count, events
                ),
            ));
        }
        let digest = repo.state_digest()?;
        if digest.to_hex() != decoded.manifest.state_digest {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                format!(
                    "manifest 状态摘要 {} 与重建仓库 {} 不符",
                    decoded.manifest.state_digest,
                    digest.to_hex()
                ),
            ));
        }
        let audit = require_clean_audit(&repo)?;
        let required_objects = evidence::validate(&repo)?;
        let objects = decoded
            .pieces
            .iter()
            .filter(|piece| piece.reference.name.starts_with(OBJECT_PREFIX))
            .count();
        let packaged = decoded
            .pieces
            .iter()
            .filter_map(|piece| piece.reference.name.strip_prefix(OBJECT_PREFIX))
            .map(Hash::from_hex)
            .collect::<Option<BTreeSet<_>>>()
            .ok_or_else(|| BundleError::invalid("audit_bundle_bad", "对象部件名含非法摘要"))?;
        if repo.store().ids().into_iter().collect::<BTreeSet<_>>() != packaged {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                "重建对象库 ID 集合与 manifest 对象部件集合不符",
            ));
        }
        if required_objects != packaged {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                "manifest 对象部件集合与日志/状态独立推导的证据闭包不符",
            ));
        }
        Ok(BundleReport {
            ok: true,
            package_id,
            events,
            objects,
            pieces: decoded.pieces.len(),
            bytes: decoded.bytes,
            anchor: anchor_outcome,
            audit,
        })
    })();
    match temp.cleanup() {
        Ok(()) => result,
        Err(cleanup) => match result {
            Ok(_) => {
                eprintln!(
                    "TVAB 验证完成，但临时仓库 {} 清理失败：{cleanup}",
                    temp.root().display()
                );
                Err(cleanup)
            }
            Err(original) => {
                eprintln!(
                    "TVAB 验证失败，且临时仓库 {} 清理失败：{cleanup}",
                    temp.root().display()
                );
                Err(original)
            }
        },
    }
}

fn lock_repo(root: &Path) -> Result<crate::claims::LockGuard, BundleError> {
    crate::claims::lock(root).map_err(|err| match err {
        ClaimsError::Locked(path) => RepoError::StateLocked(path).into(),
        ClaimsError::Io(err) => RepoError::Io(err).into(),
        other => RepoError::BadHead(other.to_string()).into(),
    })
}

fn require_checkpoint_completion(
    repo: &Repo,
    anchor: &ExternalAnchor,
) -> Result<usize, BundleError> {
    let events = repo.journal().events();
    let expected = anchor
        .height
        .checked_add(2)
        .ok_or_else(|| BundleError::invalid("audit_bundle_incomplete", "独立外锚高度溢出"))?;
    if events.len() != expected {
        return Err(BundleError::invalid(
            "audit_bundle_incomplete",
            format!(
                "独立外锚覆盖 {} 条事件；TVAB 只接受其后唯一的 checkpoint op_result，实际却有 {} 条",
                anchor.height.saturating_add(1),
                events.len()
            ),
        ));
    }
    let (Some(begin), Some(checkpoint), Some(result)) = (
        anchor.height.checked_sub(1).and_then(|seq| events.get(seq)),
        events.get(anchor.height),
        events.get(anchor.height + 1),
    ) else {
        return Err(BundleError::invalid(
            "audit_bundle_incomplete",
            "独立外锚前后缺少 checkpoint 操作闭环",
        ));
    };
    let digest = repo.state_digest()?;
    let state_before = begin
        .payload
        .get("state_before")
        .and_then(serde_json::Value::as_str)
        .and_then(Hash::from_hex);
    let checkpoint_before = checkpoint
        .payload
        .get("state_before")
        .and_then(serde_json::Value::as_str)
        .and_then(Hash::from_hex);
    let checkpoint_after = checkpoint
        .payload
        .get("state_after")
        .and_then(serde_json::Value::as_str)
        .and_then(Hash::from_hex);
    let state_after = result
        .payload
        .get("state_after")
        .and_then(serde_json::Value::as_str)
        .and_then(Hash::from_hex);
    let valid_shape = begin.kind == "op_begin"
        && begin.payload.get("op").and_then(serde_json::Value::as_str) == Some("checkpoint")
        && checkpoint.kind == "checkpoint"
        && checkpoint.hash == anchor.checkpoint
        && result.kind == "op_result"
        && result
            .payload
            .as_object()
            .is_some_and(|object| object.len() == 6)
        && result.payload.get("op").and_then(serde_json::Value::as_str) == Some("checkpoint")
        && result
            .payload
            .get("begin")
            .and_then(serde_json::Value::as_u64)
            == Some(begin.seq)
        && result
            .payload
            .get("begin_hash")
            .and_then(serde_json::Value::as_str)
            .and_then(Hash::from_hex)
            == Some(begin.hash)
        && result
            .payload
            .get("status")
            .and_then(serde_json::Value::as_str)
            == Some("ok")
        && result
            .payload
            .get("result")
            .and_then(serde_json::Value::as_object)
            .is_some_and(serde_json::Map::is_empty)
        && begin.at_ms == checkpoint.at_ms
        && checkpoint.at_ms == result.at_ms
        && state_before == Some(digest)
        && checkpoint_before == Some(digest)
        && checkpoint_after == Some(digest)
        && state_after == Some(digest);
    if !valid_shape {
        return Err(BundleError::invalid(
            "audit_bundle_incomplete",
            "外锚后的唯一事件不是由已锚 op_begin 唯一确定的 checkpoint 成功收口",
        ));
    }
    Ok(events.len())
}

fn require_clean_audit(repo: &Repo) -> Result<AuditReport, BundleError> {
    let report = audit::status(repo)?;
    if !report.ok || report.level != "L2" || report.open_ops != 0 {
        let issues = report
            .issues
            .iter()
            .map(|issue| format!("{}: {}", issue.kind, issue.detail))
            .collect::<Vec<_>>()
            .join("；");
        return Err(BundleError::invalid(
            "audit_bundle_incomplete",
            format!(
                "仓库未达到可封包条件（level={}, open_ops={}）：{issues}",
                report.level, report.open_ops
            ),
        ));
    }
    Ok(report)
}

fn state_pieces(repo: &Repo) -> Result<Vec<Piece>, BundleError> {
    let dir = repo.root().join(DIR);
    let mut pieces = Vec::new();
    for name in [
        "journal.jsonl",
        "HEAD",
        "index.json",
        "policy.json",
        "claims.json",
        "keys.json",
    ] {
        let path = dir.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_file() => {
                pieces.push(make_piece(name.to_string(), read_state_file(&path)?)?);
            }
            Ok(_) => {
                return Err(BundleError::invalid(
                    "audit_bundle_incomplete",
                    format!("仓库状态 {} 不是普通文件", path.display()),
                ));
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
    }
    let sparse = dir.join("sparse.json");
    match fs::symlink_metadata(&sparse) {
        Ok(_) => {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                format!(
                    "仓库存在未纳入历史状态摘要的 {}；TVAB v1 拒绝封包，请先全量检出或清除 sparse 索引",
                    sparse.display()
                ),
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    let refs = dir.join("refs");
    match fs::symlink_metadata(&refs) {
        Ok(metadata) if metadata.file_type().is_dir() => {
            for entry in fs::read_dir(refs)? {
                let entry = entry?;
                if !entry.file_type()?.is_file() {
                    return Err(BundleError::invalid(
                        "audit_bundle_incomplete",
                        format!("refs 下有非普通文件：{}", entry.path().display()),
                    ));
                }
                let name = entry.file_name().into_string().map_err(|_| {
                    BundleError::invalid("audit_bundle_incomplete", "ref 名不是合法 UTF-8")
                })?;
                Repo::validate_ref(&name)?;
                pieces.push(make_piece(
                    format!("refs/{name}"),
                    read_state_file(&entry.path())?,
                )?);
            }
        }
        Ok(_) => {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                format!("仓库状态 {} 不是普通目录", refs.display()),
            ));
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }
    if !pieces
        .iter()
        .any(|piece| piece.reference.name == "journal.jsonl")
    {
        return Err(BundleError::invalid(
            "audit_bundle_incomplete",
            "仓库缺 journal.jsonl，不能封包",
        ));
    }
    Ok(pieces)
}

fn read_state_file(path: &Path) -> Result<Vec<u8>, BundleError> {
    let file = open_regular_file(path)?;
    let mut bytes = Vec::new();
    file.take(MAX_PIECE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_PIECE_BYTES {
        return Err(BundleError::invalid(
            "audit_bundle_too_large",
            format!("{} 超过单部件上限", path.display()),
        ));
    }
    Ok(bytes)
}

fn make_piece(name: String, bytes: Vec<u8>) -> Result<Piece, BundleError> {
    if bytes.len() > MAX_PIECE_BYTES {
        return Err(BundleError::invalid(
            "audit_bundle_too_large",
            format!("部件 {name} 超过单件上限"),
        ));
    }
    let hash = Hash::of(&bytes);
    validate_piece_name(&name, &hash)?;
    Ok(Piece {
        reference: PieceRef {
            name,
            hash: hash.to_hex(),
            bytes: bytes.len() as u64,
        },
        bytes,
    })
}

fn restore(temp: &TempRepo, decoded: &Decoded) -> Result<(), BundleError> {
    let repo = Repo::init(temp.root())?;
    let dir = temp.root().join(DIR);
    for piece in &decoded.pieces {
        let name = &piece.reference.name;
        if let Some(id_hex) = name.strip_prefix(OBJECT_PREFIX) {
            let id = Hash::from_hex(id_hex)
                .ok_or_else(|| BundleError::invalid("audit_bundle_bad", "对象部件名含非法摘要"))?;
            let (actual, _) = repo.store().put_chunk(&piece.bytes)?;
            if actual != id {
                return Err(BundleError::invalid(
                    "audit_bundle_hash_mismatch",
                    format!("对象部件 {name} 重导入后摘要不符"),
                ));
            }
            continue;
        }
        let path = if let Some(ref_name) = name.strip_prefix("refs/") {
            Repo::validate_ref(ref_name)?;
            dir.join("refs").join(ref_name)
        } else {
            dir.join(name)
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        file.write_all(&piece.bytes)?;
        file.sync_all()?;
    }
    Ok(())
}

struct TempRepo {
    path: PathBuf,
    cleaned: bool,
}

impl TempRepo {
    fn new() -> Result<Self, BundleError> {
        for _ in 0..8 {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random)
                .map_err(|err| BundleError::invalid("audit_bundle_io", err.to_string()))?;
            let path = std::env::temp_dir().join(format!(
                "trit-vcs-tvab-{}-{}",
                std::process::id(),
                Hash::of(&random).to_hex()
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        cleaned: false,
                    });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => return Err(err.into()),
            }
        }
        Err(BundleError::invalid(
            "audit_bundle_io",
            "无法创建唯一临时目录",
        ))
    }

    fn root(&self) -> &Path {
        &self.path
    }

    fn cleanup(&mut self) -> Result<(), BundleError> {
        if self.cleaned {
            return Ok(());
        }
        fs::remove_dir_all(&self.path).map_err(|err| {
            BundleError::invalid(
                "audit_bundle_io",
                format!("清理临时仓库 {} 失败：{err}", self.path.display()),
            )
        })?;
        self.cleaned = true;
        Ok(())
    }
}

impl Drop for TempRepo {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup().map_err(|err| eprintln!("{err}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    fn completion(state: Value) -> (TempRepo, ExternalAnchor) {
        let temp = TempRepo::new().unwrap();
        let mut repo = Repo::init(temp.root()).unwrap();
        let begin = repo
            .journal_mut()
            .append(
                "op_begin",
                json!({"op": "checkpoint", "state_before": state}),
                1_000,
            )
            .unwrap();
        let checkpoint = repo
            .journal_mut()
            .append(
                "checkpoint",
                json!({
                    "state_before": begin.payload["state_before"],
                    "state_after": begin.payload["state_before"],
                }),
                1_000,
            )
            .unwrap();
        repo.journal_mut()
            .append(
                "op_result",
                json!({
                    "op": "checkpoint",
                    "begin": begin.seq,
                    "begin_hash": begin.hash.to_hex(),
                    "status": "ok",
                    "result": {},
                    "state_after": begin.payload["state_before"],
                }),
                1_000,
            )
            .unwrap();
        let anchor = ExternalAnchor {
            schema: external::SCHEMA.to_string(),
            checkpoint: checkpoint.hash,
            height: usize::try_from(checkpoint.seq).unwrap(),
            head: Some(begin.hash),
            merkle_root: Hash::of(b"root"),
            previous: None,
            key_id: "ed25519:test".to_string(),
            algorithm: external::ALGORITHM.to_string(),
            signature: "00".to_string(),
            signed_at_ms: 1_000,
        };
        (temp, anchor)
    }

    #[test]
    fn checkpoint_completion_requires_actual_state_digest() {
        for state in [
            json!(null),
            json!("not-a-hash"),
            json!(Hash::of(b"wrong-state").to_hex()),
        ] {
            let (temp, anchor) = completion(state);
            let repo = Repo::open(temp.root()).unwrap();
            let err = require_checkpoint_completion(&repo, &anchor).unwrap_err();
            assert_eq!(err.kind(), "audit_bundle_incomplete");
        }
    }

    #[test]
    fn checkpoint_completion_accepts_matching_state_digest() {
        let empty = TempRepo::new().unwrap();
        let repo = Repo::init(empty.root()).unwrap();
        let digest = repo.state_digest().unwrap().to_hex();
        drop(repo);
        let (temp, anchor) = completion(json!(digest));
        let repo = Repo::open(temp.root()).unwrap();
        assert_eq!(require_checkpoint_completion(&repo, &anchor).unwrap(), 3);
    }

    #[test]
    fn audit_error_kinds_remain_specific() {
        let io = BundleError::Audit(AuditError::Io(std::io::Error::other("read failed")));
        assert_eq!(io.kind(), "audit_bundle_io");
        let repo = BundleError::Audit(AuditError::Repo(RepoError::NotInitialized(
            "missing".to_string(),
        )));
        assert_eq!(repo.kind(), "audit_bundle_repo");
    }

    #[test]
    fn clean_audit_rejects_open_operations() {
        let temp = TempRepo::new().unwrap();
        let mut repo = Repo::init(temp.root()).unwrap();
        repo.journal_mut()
            .append("op_begin", json!({"op": "commit"}), 1_000)
            .unwrap();
        let repo = Repo::open(temp.root()).unwrap();
        let err = require_clean_audit(&repo).unwrap_err();
        assert_eq!(err.kind(), "audit_bundle_incomplete");
    }
}
