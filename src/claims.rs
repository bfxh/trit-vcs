//! 跨仓认领账本：认领写在**中央仓**里，多个工作树共享同一张表。
//!
//! 以前 `--claims FILE` 是各仓自己导一份快照：谁先导谁落后，冲突只能靠人对。
//! 这里把账放进中央仓（`.tritvcs/claims.json`），`claims add/release/list` 直接改它，
//! 每次改动追加进中央仓的哈希链（`claim_add` / `claim_release`），事后能复核。
//!
//! 并发口径：账本用 `claims.lock`（`create_new`）做单写者；抢不到就报 `claims_locked`，
//! 不静默覆盖。读（`list` / `export`）不加锁：写是先写临时文件再原子改名，
//! 读到旧版本最多是"晚一拍"，不会读到半截 JSON。

use std::fs::{self, OpenOptions};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::gate::ClaimSpec;
use crate::hash::Hash;
use crate::remediation::{Context, Remediable, VCS};
use crate::repo::{DIR, Repo};

pub(crate) mod signing;

pub const FILE: &str = "claims.json";
pub const LOCK: &str = "claims.lock";
pub const MIN_TTL_SECS: u64 = 1;
pub const MAX_TTL_SECS: u64 = 86_400;

/// 一次提交当时解析出来的认领快照（不可变对象，随提交进对象库）。
///
/// 账本本身会变、TTL 会过期；只存 claim id 的旧做法事后没法复核"当时到底授权了哪些路径"。
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClaimSet {
    pub schema: u32,
    pub ledger_digest: String,
    pub resolved_at: u64,
    pub claims: Vec<ClaimSpec>,
}

impl ClaimSet {
    pub const SCHEMA: u32 = 1;

    /// 按 id 排序后取账本摘要；同一组认领无论账本 JSON 顺序如何，快照一致。
    pub fn from_claims(claims: &[ClaimSpec], resolved_at: u64) -> Result<Self, serde_json::Error> {
        let mut sorted = claims.to_vec();
        sorted.sort_by(|a, b| a.id.cmp(&b.id));
        let ledger_digest = Hash::of(&serde_json::to_vec(&sorted)?).to_hex();
        Ok(Self {
            schema: Self::SCHEMA,
            ledger_digest,
            resolved_at,
            claims: sorted,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    pub fn id(&self) -> Result<Hash, serde_json::Error> {
        Ok(Hash::of(&self.encode()?))
    }

    pub fn find(&self, id: &str) -> Option<&ClaimSpec> {
        self.claims.iter().find(|claim| claim.id == id)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimsError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("认领表不是合法 JSON 数组：{0}")]
    Json(#[from] serde_json::Error),
    #[error("认领账本被另一个进程占着（锁文件 {0}）；等它跑完再重来")]
    Locked(String),
    #[error("认领 id {id} 已被 {owner} 占着：换一个 id，或等它到期")]
    IdTaken { id: String, owner: String },
    #[error("认领 {0} 不存在（或已过期被清理）")]
    UnknownId(String),
    #[error("认领 {id} 属于 {owner}，不是你能 release 的")]
    OwnerMismatch { id: String, owner: String },
    #[error("认领 id 不合法：{0:?}（1–64 位字母数字或 . _ - :）")]
    BadId(String),
    #[error("owner 不合法：{0:?}（1–64 位，不含空白）")]
    BadOwner(String),
    #[error("认领路径不合法：{0:?}（相对路径、不含 ..；反斜杠会归一成 /）")]
    BadPath(String),
    #[error("ttl 要在 {MIN_TTL_SECS}–{MAX_TTL_SECS} 秒之间：{0}")]
    BadTtl(u64),
    #[error("这些路径和 {others:?} 的在效认领相交：{paths:?}；先拆开触碰集或等它到期")]
    Conflict {
        others: Vec<String>,
        paths: Vec<String>,
    },
    #[error("中央仓策略要求认领操作带 --sign-key")]
    SignatureRequired,
    #[error("认领签名被拒绝：{0}")]
    Signature(String),
    #[error("中央仓: {0}")]
    Repo(#[from] crate::repo::RepoError),
    #[error("事件日志: {0}")]
    Journal(#[from] crate::journal::JournalError),
}

impl Remediable for ClaimsError {
    fn kind(&self) -> &'static str {
        match self {
            Self::Io(_) | Self::Repo(_) | Self::Journal(_) => "claims_io",
            Self::Json(_) => "claims_bad_ledger",
            Self::Locked(_) => "claims_locked",
            Self::IdTaken { .. } => "claims_id_taken",
            Self::UnknownId(_) => "claims_unknown_id",
            Self::OwnerMismatch { .. } => "claims_owner_mismatch",
            Self::BadId(_) | Self::BadOwner(_) | Self::BadPath(_) | Self::BadTtl(_) => {
                "claims_bad_request"
            }
            Self::Conflict { .. } => "claims_conflict",
            Self::SignatureRequired => "claims_signature_required",
            Self::Signature(_) => "claims_signature_rejected",
        }
    }

    fn commands(&self, ctx: Context<'_>) -> Vec<String> {
        let central = ctx.dir.display().to_string();
        match self {
            Self::Locked(_) => vec![
                "等持锁的进程结束；锁文件是它正在写的证据，别删".to_string(),
                format!("{VCS} claims list --central {central}"),
            ],
            Self::Conflict { others, .. } => {
                let mut out = vec![format!(
                    "{VCS} claims list --central {central} --json   # 看谁挡着、还剩多少秒"
                )];
                for other in others.iter().take(4) {
                    out.push(format!("等 {other} 的认领到期再重来（别替它 release）"));
                }
                out
            }
            Self::IdTaken { id, .. } => vec![
                format!("换一个 id：`{VCS} claims add --central {central} --id <新 id> …`"),
                format!("或等 {id} 到期：`{VCS} claims list --central {central} --json`"),
            ],
            Self::OwnerMismatch { id, .. } => vec![format!(
                "release 只能由持有者本人做：`{VCS} claims list --central {central} --json` 确认 {id} 的 owner"
            )],
            Self::UnknownId(id) => vec![format!(
                "{VCS} claims list --central {central} --all --json   # 确认 {id} 是否已过期/拼错"
            )],
            Self::BadId(_) | Self::BadOwner(_) | Self::BadPath(_) | Self::BadTtl(_) => {
                vec![format!(
                    "{VCS} claims add --central {central} --id c1 --owner <宿主:会话id> --path src/x.rs --ttl 900"
                )]
            }
            Self::SignatureRequired => vec![format!(
                "{VCS} claims add --central {central} --id c1 --owner <principal> --path src/x.rs --sign-key <私钥文件>"
            )],
            Self::Signature(_) => vec![
                format!("{VCS} key list --repo {central} --json"),
                format!(
                    "{VCS} claims add --central {central} --id c1 --owner <与 principal 相同> --path src/x.rs --sign-key <私钥文件>"
                ),
            ],
            Self::Io(_) | Self::Repo(_) | Self::Journal(_) => vec![
                format!("{VCS} claims list --central {central}"),
                "确认 --central 指向中央仓目录（不是客户端仓）".to_string(),
            ],
            Self::Json(_) => vec![format!(
                "{VCS} claims list --central {central}   # 账本坏了先看原文件；修复前不要继续 add"
            )],
        }
    }
}

/// 新认领请求（`add` 的入参）。
#[derive(Clone, Debug)]
pub struct NewClaim<'a> {
    pub id: &'a str,
    pub owner: &'a str,
    pub paths: Vec<String>,
    pub ttl_secs: u64,
}

pub fn ledger_path(central: &Path) -> PathBuf {
    central.join(DIR).join(FILE)
}

/// 读账本；文件不存在 = 空表（第一个认领不用先手工建文件）。
pub fn load(central: &Path) -> Result<Vec<ClaimSpec>, ClaimsError> {
    let path = ledger_path(central);
    if !path.is_file() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_str(&fs::read_to_string(path)?)?)
}

/// 只看在效认领；`all` 时连过期的一起给（审计/排错用）。
pub fn list(central: &Path, now: u64, all: bool) -> Result<Vec<ClaimSpec>, ClaimsError> {
    let mut claims = load(central)?;
    if !all {
        claims.retain(|claim| claim.expires_at > now);
    }
    claims.sort_by(|a, b| a.owner.cmp(&b.owner).then(a.id.cmp(&b.id)));
    Ok(claims)
}

/// 新增/续期。同一个 id + 同一个 owner 视为续期（路径整体替换、到期时间重算）。
pub fn add(central: &Path, request: NewClaim<'_>, now: u64) -> Result<ClaimSpec, ClaimsError> {
    add_inner(central, request, None, now)
}

pub fn add_signed(
    central: &Path,
    request: NewClaim<'_>,
    key_path: &Path,
    now: u64,
) -> Result<ClaimSpec, ClaimsError> {
    add_inner(central, request, Some(key_path), now)
}

fn add_inner(
    central: &Path,
    request: NewClaim<'_>,
    key_path: Option<&Path>,
    now: u64,
) -> Result<ClaimSpec, ClaimsError> {
    validate_id(request.id)?;
    validate_owner(request.owner)?;
    if !(MIN_TTL_SECS..=MAX_TTL_SECS).contains(&request.ttl_secs) {
        return Err(ClaimsError::BadTtl(request.ttl_secs));
    }
    let paths = normalize_paths(&request.paths)?;
    let expires_at = now
        .checked_add(request.ttl_secs)
        .ok_or(ClaimsError::BadTtl(request.ttl_secs))?;
    let _guard = lock(central)?;
    let mut claims = load(central)?;
    // 过期条目在写路径上清掉：否则同一个 id 的过期记录会和新的同 id 并存，
    // gate 看到重复 id 会整张表 fail-closed（历史仍在中央仓的哈希链里）。
    claims.retain(|claim| claim.expires_at > now);
    let mut renewed = false;
    let mut acquired_at = now;
    let mut others = Vec::new();
    for claim in &claims {
        if claim.expires_at <= now {
            continue;
        }
        if claim.id == request.id {
            if claim.owner != request.owner {
                return Err(ClaimsError::IdTaken {
                    id: claim.id.clone(),
                    owner: claim.owner.clone(),
                });
            }
            renewed = true;
            acquired_at = claim.acquired_at;
            continue;
        }
        if claim.owner == request.owner {
            continue;
        }
        if claim.paths.iter().any(|scope| {
            paths
                .iter()
                .any(|path| trit_orch::paths_overlap(scope, path))
        }) && !others.contains(&claim.owner)
        {
            others.push(claim.owner.clone());
        }
    }
    if !others.is_empty() {
        others.sort();
        return Err(ClaimsError::Conflict { others, paths });
    }
    let spec = ClaimSpec {
        id: request.id.to_string(),
        owner: request.owner.to_string(),
        paths,
        acquired_at,
        expires_at,
    };
    if renewed {
        claims.retain(|claim| claim.id != spec.id);
    }
    claims.push(spec.clone());
    let mut repo = Repo::init(central)?;
    let signer = prepare_signer(&repo, request.owner, key_path)?;
    let at_ms = claim_at_ms(now);
    let begin = repo.begin_operation_locked(
        "claim_add",
        json!({
            "id": spec.id.clone(),
            "owner": spec.owner.clone(),
            "paths": spec.paths.len(),
            "path_list": spec.paths.clone(),
            "expires_at": spec.expires_at,
        }),
        at_ms,
    )?;
    if let Err(err) = write_ledger(central, &claims) {
        let _ = repo.finish_operation_locked(
            &begin,
            "claim_add",
            "failed",
            json!({"error": err.to_string()}),
            at_ms,
        );
        return Err(err);
    }
    finish_claim(
        &mut repo,
        &begin,
        "claim_add",
        &spec,
        signer.as_ref(),
        at_ms,
    )?;
    Ok(spec)
}

/// 释放认领；只有 owner 本人能释放（替别人 release 是另一种"把工作甩掉"）。
pub fn release(central: &Path, id: &str, owner: &str, now: u64) -> Result<ClaimSpec, ClaimsError> {
    release_inner(central, id, owner, None, now)
}

pub fn release_signed(
    central: &Path,
    id: &str,
    owner: &str,
    key_path: &Path,
    now: u64,
) -> Result<ClaimSpec, ClaimsError> {
    release_inner(central, id, owner, Some(key_path), now)
}

fn release_inner(
    central: &Path,
    id: &str,
    owner: &str,
    key_path: Option<&Path>,
    now: u64,
) -> Result<ClaimSpec, ClaimsError> {
    validate_id(id)?;
    validate_owner(owner)?;
    let _guard = lock(central)?;
    let mut claims = load(central)?;
    let Some(index) = claims.iter().position(|claim| claim.id == id) else {
        return Err(ClaimsError::UnknownId(id.to_string()));
    };
    if claims[index].owner != owner {
        return Err(ClaimsError::OwnerMismatch {
            id: id.to_string(),
            owner: claims[index].owner.clone(),
        });
    }
    let spec = claims.remove(index);
    let mut repo = Repo::init(central)?;
    let signer = prepare_signer(&repo, owner, key_path)?;
    let at_ms = claim_at_ms(now);
    let begin = repo.begin_operation_locked(
        "claim_release",
        json!({
            "id": spec.id.clone(),
            "owner": spec.owner.clone(),
            "paths": spec.paths.len(),
            "path_list": spec.paths.clone(),
        }),
        at_ms,
    )?;
    if let Err(err) = write_ledger(central, &claims) {
        let _ = repo.finish_operation_locked(
            &begin,
            "claim_release",
            "failed",
            json!({"error": err.to_string()}),
            at_ms,
        );
        return Err(err);
    }
    finish_claim(
        &mut repo,
        &begin,
        "claim_release",
        &spec,
        signer.as_ref(),
        at_ms,
    )?;
    Ok(spec)
}

/// 导出一份快照给 `commit/preflight --claims FILE` 用（即同一个数组格式）。
pub fn export(central: &Path, out: &Path) -> Result<usize, ClaimsError> {
    let claims = load(central)?;
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out, serde_json::to_vec_pretty(&claims)?)?;
    Ok(claims.len())
}

fn validate_id(id: &str) -> Result<(), ClaimsError> {
    let ok = (1..=64).contains(&id.len())
        && id
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ':'));
    if ok {
        Ok(())
    } else {
        Err(ClaimsError::BadId(id.to_string()))
    }
}

fn validate_owner(owner: &str) -> Result<(), ClaimsError> {
    let ok = (1..=64).contains(&owner.len()) && !owner.chars().any(char::is_whitespace);
    if ok {
        Ok(())
    } else {
        Err(ClaimsError::BadOwner(owner.to_string()))
    }
}

fn normalize_paths(paths: &[String]) -> Result<Vec<String>, ClaimsError> {
    if paths.is_empty() || paths.len() > 256 {
        return Err(ClaimsError::BadPath(format!(
            "路径条数要在 1–256：{}",
            paths.len()
        )));
    }
    let mut out = Vec::new();
    for raw in paths {
        let normalized = raw.replace('\\', "/");
        let trimmed = normalized.trim_end_matches('/');
        let bad = trimmed.is_empty()
            || trimmed.starts_with('/')
            || trimmed
                .split('/')
                .any(|seg| seg.is_empty() || seg == "." || seg == "..");
        if bad {
            return Err(ClaimsError::BadPath(raw.clone()));
        }
        if !out.iter().any(|path| path == trimmed) {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

fn write_ledger(central: &Path, claims: &[ClaimSpec]) -> Result<(), ClaimsError> {
    let path = ledger_path(central);
    fs::create_dir_all(path.parent().expect("账本路径一定有父目录"))?;
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(claims)?)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

fn claim_at_ms(now: u64) -> u64 {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    wall.max(now.saturating_mul(1000))
}

fn prepare_signer(
    repo: &Repo,
    owner: &str,
    key_path: Option<&Path>,
) -> Result<Option<signing::Signer>, ClaimsError> {
    if repo.policy()?.require_signed_claims && key_path.is_none() {
        return Err(ClaimsError::SignatureRequired);
    }
    key_path
        .map(|path| signing::Signer::load(repo, path, owner))
        .transpose()
}

/// 认领动作的统一收口：先记 `claim_add/claim_release` 事件（带 state_after），再记
/// 可选签名与 `op_result`。签名不改变状态，也不改变账本 JSON 形状。
fn finish_claim(
    repo: &mut Repo,
    begin: &crate::journal::Event,
    kind: &str,
    spec: &ClaimSpec,
    signer: Option<&signing::Signer>,
    at_ms: u64,
) -> Result<(), ClaimsError> {
    let state_after = repo.state_digest()?;
    let state_after_hex = state_after.to_hex();
    let mut signature = match signer {
        Some(signer) => match signer.sign(kind, spec, begin, state_after, at_ms) {
            Ok(signature) => Some(signature),
            Err(err) => {
                let _ = repo.finish_operation_locked(
                    begin,
                    kind,
                    "failed",
                    json!({"error": err.to_string()}),
                    at_ms,
                );
                return Err(err);
            }
        },
        None => None,
    };
    let claim_event = repo.journal_mut().append(
        kind,
        json!({
            "operation": begin.hash.to_hex(),
            "id": spec.id.clone(),
            "owner": spec.owner.clone(),
            "paths": spec.paths.len(),
            "path_list": spec.paths.clone(),
            "acquired_at": spec.acquired_at,
            "expires_at": spec.expires_at,
            "claim": spec,
            "signed": signer.is_some(),
            "state_after": state_after_hex,
        }),
        at_ms,
    )?;
    if let Some(signature) = &mut signature {
        signature["claim_event"] = json!(claim_event.hash.to_hex());
        repo.journal_mut()
            .append(signing::EVENT_KIND, signature.clone(), at_ms)?;
    }
    repo.finish_operation_locked(begin, kind, "ok", json!({}), at_ms)?;
    Ok(())
}

pub(crate) struct LockGuard {
    path: PathBuf,
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn lock(central: &Path) -> Result<LockGuard, ClaimsError> {
    let path = central.join(DIR).join(LOCK);
    fs::create_dir_all(path.parent().expect("锁路径一定有父目录"))?;
    match OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(_) => Ok(LockGuard { path }),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Err(ClaimsError::Locked(path.display().to_string()))
        }
        Err(err) => Err(ClaimsError::Io(err)),
    }
}

/// 账本内容摘要：给 `claims list` 的读数行用（不是哈希链，只是让人一眼看出变没变）。
pub fn digest(claims: &[ClaimSpec]) -> String {
    let mut ids: Vec<String> = claims
        .iter()
        .map(|claim| format!("{}:{}:{}", claim.id, claim.owner, claim.expires_at))
        .collect();
    ids.sort();
    Hash::of(ids.join("\n").as_bytes()).short()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::KeyFile;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trit-vcs-claims-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn add_one<'a>(
        central: &Path,
        id: &'a str,
        owner: &'a str,
        path: &str,
        now: u64,
    ) -> Result<ClaimSpec, ClaimsError> {
        add(
            central,
            NewClaim {
                id,
                owner,
                paths: vec![path.to_string()],
                ttl_secs: 900,
            },
            now,
        )
    }

    #[test]
    fn add_list_release_roundtrip() {
        let central = temp("roundtrip");
        let spec = add_one(&central, "c1", "qoder:s1", "src", 100).unwrap();
        assert_eq!(spec.expires_at, 1_000);
        let claims = list(&central, 200, false).unwrap();
        assert_eq!(claims, vec![spec.clone()]);
        let released = release(&central, "c1", "qoder:s1", 300).unwrap();
        assert_eq!(released.id, "c1");
        assert!(list(&central, 300, false).unwrap().is_empty());
    }

    #[test]
    fn overlapping_other_owner_is_rejected_and_named() {
        let central = temp("conflict");
        add_one(&central, "c1", "zcode:z", "src/lib.rs", 100).unwrap();
        let err = add_one(&central, "c2", "qoder:s1", "src", 100).unwrap_err();
        assert!(
            matches!(err, ClaimsError::Conflict { ref others, .. } if others == &vec!["zcode:z".to_string()]),
            "{err}"
        );
    }

    #[test]
    fn same_owner_can_renew_and_expired_claims_do_not_block() {
        let central = temp("renew");
        add_one(&central, "c1", "qoder:s1", "src", 100).unwrap();
        let renewed = add_one(&central, "c1", "qoder:s1", "src", 500).unwrap();
        assert_eq!(renewed.expires_at, 1_400, "同一 owner + 同一 id 是续期");
        let other = add_one(&central, "c2", "zcode:z", "src", 1_500).unwrap();
        assert_eq!(other.owner, "zcode:z", "过期认领不该继续挡路");
    }

    #[test]
    fn duplicate_id_from_another_owner_is_rejected() {
        let central = temp("id");
        add_one(&central, "c1", "qoder:s1", "a.rs", 100).unwrap();
        let err = add_one(&central, "c1", "zcode:z", "b.rs", 100).unwrap_err();
        assert!(matches!(err, ClaimsError::IdTaken { .. }), "{err}");
    }

    #[test]
    fn release_by_another_owner_is_rejected() {
        let central = temp("release");
        add_one(&central, "c1", "qoder:s1", "a.rs", 100).unwrap();
        let err = release(&central, "c1", "zcode:z", 200).unwrap_err();
        assert!(matches!(err, ClaimsError::OwnerMismatch { .. }), "{err}");
    }

    #[test]
    fn bad_paths_and_ids_fail_closed() {
        let central = temp("bad");
        for path in ["/abs", "a/../b", "a//b", ""] {
            assert!(
                matches!(
                    add_one(&central, "c1", "qoder:s1", path, 100),
                    Err(ClaimsError::BadPath(_))
                ),
                "{path}"
            );
        }
        let windows_style = add_one(&central, "c1", "qoder:s1", "src\\lib.rs", 100).unwrap();
        assert_eq!(
            windows_style.paths,
            vec!["src/lib.rs".to_string()],
            "反斜杠要归一成 /，不是另一套路径口径"
        );
        assert!(matches!(
            add_one(&central, "bad/id", "qoder:s1", "a", 100),
            Err(ClaimsError::BadId(_))
        ));
        assert!(matches!(
            add_one(&central, "c2", "two words", "a", 100),
            Err(ClaimsError::BadOwner(_))
        ));
        assert_eq!(
            list(&central, 100, false).unwrap().len(),
            1,
            "只有归一后的那条路径能写进账本"
        );
    }

    #[test]
    fn lock_is_single_writer_and_recovers_on_drop() {
        let central = temp("lock");
        let guard = lock(&central).unwrap();
        assert!(matches!(
            add_one(&central, "c1", "qoder:s1", "a", 100),
            Err(ClaimsError::Locked(_))
        ));
        drop(guard);
        assert!(add_one(&central, "c1", "qoder:s1", "a", 100).is_ok());

        let mut repo = Repo::open(&central).unwrap();
        let guard = lock(&central).unwrap();
        let commit = Hash::of(b"locked-commit");
        let tree = Hash::of(b"locked-tree");
        let files = std::collections::BTreeMap::from([("a.rs".to_string(), b"a".to_vec())]);
        assert!(matches!(
            repo.stage(&files, 2_000),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.set_ref("main", &commit),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.adopt(&commit, &tree, &["a.rs".to_string()]),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.commit(crate::repo::CommitRequest {
                allow_unclaimed: true,
                now_secs: 2,
                ..Default::default()
            }),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        assert!(matches!(
            crate::merge::merge_audited(&mut repo, &commit, &commit, None),
            Err(crate::merge::MergeError::Repo(
                crate::repo::RepoError::StateLocked(_)
            ))
        ));
        let receipt = crate::accept::AcceptReceipt {
            schema: crate::accept::AcceptReceipt::SCHEMA,
            tree,
            base: None,
            session: "qoder:lock".to_string(),
            claim_ids: Vec::new(),
            outcomes: Vec::new(),
            passed: true,
            at_secs: 2,
        };
        assert!(matches!(
            repo.record_accept(&receipt),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        let policy = crate::repo::Policy {
            require_signed_claims: true,
            ..Default::default()
        };
        assert!(matches!(
            repo.set_policy(&policy, "qoder:admin", 1_000),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        drop(guard);
        repo.set_policy(&policy, "qoder:admin", 1_000).unwrap();

        let old = KeyFile::generate().unwrap();
        let new = KeyFile::generate().unwrap();
        let entry = crate::keys::TrustEntry {
            key_id: old.key_id.clone(),
            principal: "qoder:lock".to_string(),
            role: "author".to_string(),
            added_at_ms: 1_001,
            public_key: Some(old.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        };
        let missing_key = central.join("missing.key");
        let guard = lock(&central).unwrap();
        assert!(matches!(
            repo.add_key(entry.clone(), "qoder:lock", 1_001),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.revoke_key(&old.key_id, "test", "qoder:lock", 1_002),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.rotate_key(&old, &new, "test", "qoder:lock", 1_002),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.sign_commit(&Hash::of(b"locked"), &missing_key, "qoder:lock", 1_002),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.checkpoint(&missing_key, "qoder:lock", 1_002),
            Err(crate::repo::RepoError::StateLocked(_))
        ));
        drop(guard);
        repo.add_key(entry, "qoder:lock", 1_001).unwrap();
    }
}
