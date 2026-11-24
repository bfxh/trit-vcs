//! 受审计的信任表：`keys.json` 记录 key_id、principal、角色和吊销状态。
//!
//! 信任表本身不生成私钥，也不签提交；它记录“谁被信任”。私钥生成、提交签名与
//! 验签在 `signing`。每次 add/revoke/rotate 都有写前状态、写后状态和操作结果；带公钥的
//! 记录还要求 key_id 是公钥的 BLAKE3 指纹。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hash::Hash;
use crate::repo::{DIR, Repo, RepoError};
use crate::signing::KeyFile;

pub const FILE: &str = "keys.json";

/// 公钥指纹：`ed25519:` + BLAKE3(32 字节公钥) 的 hex。
pub fn public_key_id(public: &[u8; 32]) -> String {
    format!("ed25519:{}", Hash::of(public).to_hex())
}

/// 信任表里的一条 key。`revoked_at_ms` 有值即吊销，不删除历史。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustEntry {
    pub key_id: String,
    pub principal: String,
    pub role: String,
    pub added_at_ms: u64,
    /// Ed25519 公钥（32 字节 hex）；旧的纯 key_id 记录可以为空。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// 如果这条记录是 `key rotate` 产生的，指向它替换掉的旧 key_id。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoke_reason: Option<String>,
}

impl TrustEntry {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at_ms.is_some()
    }
}

/// 整份信任表。用 BTreeMap 保证 JSON 输出顺序稳定，状态摘要才不会因插入顺序漂。
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustStore {
    #[serde(default)]
    pub keys: BTreeMap<String, TrustEntry>,
}

impl TrustStore {
    pub fn path(root: &Path) -> PathBuf {
        root.join(DIR).join(FILE)
    }

    pub fn load(root: &Path) -> Result<Self, RepoError> {
        let path = Self::path(root);
        if !path.is_file() {
            return Ok(Self::default());
        }
        let text = fs::read_to_string(&path)?;
        serde_json::from_str(&text)
            .map_err(|err| RepoError::BadHead(format!("keys.json: {err}")))
    }

    pub fn save(&self, root: &Path) -> Result<Hash, RepoError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|err| RepoError::BadHead(format!("keys.json 编码失败：{err}")))?;
        fs::write(Self::path(root), &bytes)?;
        Ok(Hash::of(&bytes))
    }

    pub fn active(&self) -> impl Iterator<Item = &TrustEntry> {
        self.keys.values().filter(|entry| !entry.is_revoked())
    }
}

/// key_id 先做形状校验；带 `public_key` 时，`add_key` 还要求它与公钥指纹一致。
fn validate_key_id(key_id: &str) -> Result<(), RepoError> {
    let bad = key_id.len() < 8
        || key_id.len() > 256
        || key_id.chars().any(|c| c.is_whitespace() || c.is_control());
    if bad {
        return Err(RepoError::BadHead(
            "key_id 必须是 8..256 字节、无空白的指纹".to_string(),
        ));
    }
    Ok(())
}

fn validate_text(field: &str, value: &str) -> Result<(), RepoError> {
    if value.trim().is_empty() || value.chars().any(char::is_control) {
        return Err(RepoError::BadHead(format!("{field} 不能为空")));
    }
    Ok(())
}

fn validate_role(role: &str) -> Result<(), RepoError> {
    const ROLES: [&str; 4] = ["author", "auditor", "release", "reader"];
    if !ROLES.contains(&role) {
        return Err(RepoError::BadHead(format!(
            "role 必须是 {} 之一",
            ROLES.join("/")
        )));
    }
    Ok(())
}

impl Repo {
    pub fn keys(&self) -> Result<TrustStore, RepoError> {
        TrustStore::load(self.root())
    }

    /// 新增一条信任记录；重复 key_id 直接拒绝，不做静默覆盖。
    pub fn add_key(
        &mut self,
        mut entry: TrustEntry,
        session: &str,
        at_ms: u64,
    ) -> Result<Hash, RepoError> {
        validate_key_id(&entry.key_id)?;
        validate_text("principal", &entry.principal)?;
        validate_role(&entry.role)?;
        validate_text("session", session)?;
        if let Some(public) = entry.public_key.as_mut() {
            *public = public.to_ascii_lowercase();
            let bytes = crate::signing::public_key_bytes(public)?;
            if public_key_id(&bytes) != entry.key_id {
                return Err(RepoError::BadHead(
                    "key_id 与 Ed25519 公钥指纹不匹配".to_string(),
                ));
            }
        }
        let mut store = self.keys()?;
        if store.keys.contains_key(&entry.key_id) {
            return Err(RepoError::BadHead(format!(
                "key {} 已存在；吊销后请新建 key，不静默覆盖",
                entry.key_id
            )));
        }
        store.keys.insert(entry.key_id.clone(), entry.clone());
        let key_id = entry.key_id.clone();
        let principal = entry.principal.clone();
        let role = entry.role.clone();
        let session_owned = session.to_string();
        self.with_operation(
            "key",
            json!({
                "action": "add",
                "key_id": key_id.clone(),
                "principal": principal.clone(),
                "role": role.clone(),
                "session": session_owned,
            }),
            at_ms,
            move |repo| {
                let before = repo.state_digest()?.to_hex();
                let keystore_hash = store.save(repo.root())?;
                let after = repo.state_digest()?.to_hex();
                repo.journal_mut().append(
                    "key",
                    json!({
                        "action": "add",
                        "key_id": key_id,
                        "principal": principal,
                        "role": role,
                        "session": session,
                        "keystore_hash": keystore_hash.to_hex(),
                        "state_before": before,
                        "state_after": after,
                    }),
                    at_ms,
                )?;
                Ok(keystore_hash)
            },
        )
    }

    /// 吊销一条已存在的 key；不物理删除，保留 add/revoke 的完整历史。
    pub fn revoke_key(
        &mut self,
        key_id: &str,
        reason: &str,
        session: &str,
        at_ms: u64,
    ) -> Result<Hash, RepoError> {
        validate_key_id(key_id)?;
        validate_text("reason", reason)?;
        validate_text("session", session)?;
        let mut store = self.keys()?;
        let Some(entry) = store.keys.get_mut(key_id) else {
            return Err(RepoError::BadHead(format!("key {key_id} 不在信任表")));
        };
        if entry.is_revoked() {
            return Err(RepoError::BadHead(format!("key {key_id} 已经吊销")));
        }
        validate_text("principal", &entry.principal)?;
        validate_role(&entry.role)?;
        entry.revoked_at_ms = Some(at_ms);
        entry.revoke_reason = Some(reason.to_string());
        let key_id_owned = key_id.to_string();
        let principal = entry.principal.clone();
        let role = entry.role.clone();
        let reason_owned = reason.to_string();
        let session_owned = session.to_string();
        self.with_operation(
            "key",
            json!({
                "action": "revoke",
                "key_id": key_id_owned.clone(),
                "principal": principal.clone(),
                "role": role.clone(),
                "session": session_owned,
                "reason": reason_owned.clone(),
            }),
            at_ms,
            move |repo| {
                let before = repo.state_digest()?.to_hex();
                let keystore_hash = store.save(repo.root())?;
                let after = repo.state_digest()?.to_hex();
                repo.journal_mut().append(
                    "key",
                    json!({
                        "action": "revoke",
                        "key_id": key_id_owned,
                        "principal": principal,
                        "role": role,
                        "session": session,
                        "reason": reason_owned,
                        "keystore_hash": keystore_hash.to_hex(),
                        "state_before": before,
                        "state_after": after,
                    }),
                    at_ms,
                )?;
                Ok(keystore_hash)
            },
        )
    }

    /// 密钥轮换：旧钥和新钥都签同一份轮换声明，旧记录吊销、新记录继承 principal/role。
    ///
    /// 两个签名分别证明“旧钥持有者同意换”和“新钥持有者知道这条轮换”。这不等于
    /// 信任表自身可信（写仓库的人仍可手改 keys.json），但轮换事件本身不能被无钥伪造。
    pub fn rotate_key(
        &mut self,
        old_key: &KeyFile,
        new_key: &KeyFile,
        reason: &str,
        session: &str,
        at_ms: u64,
    ) -> Result<Hash, RepoError> {
        old_key.validate()?;
        new_key.validate()?;
        validate_text("reason", reason)?;
        validate_text("session", session)?;
        if old_key.key_id == new_key.key_id {
            return Err(RepoError::BadHead(
                "旧钥和新钥的 key_id 相同，不能轮换".to_string(),
            ));
        }
        let mut store = self.keys()?;
        let Some(old_entry) = store.keys.get(&old_key.key_id) else {
            return Err(RepoError::BadHead(format!(
                "旧 key {} 不在信任表",
                old_key.key_id
            )));
        };
        if old_entry.is_revoked() {
            return Err(RepoError::BadHead(format!(
                "旧 key {} 已吊销",
                old_key.key_id
            )));
        }
        if old_entry
            .public_key
            .as_deref()
            .is_none_or(|public| !public.eq_ignore_ascii_case(&old_key.public))
        {
            return Err(RepoError::BadHead(format!(
                "旧 key {} 的公钥与信任表不一致",
                old_key.key_id
            )));
        }
        if store.keys.contains_key(&new_key.key_id) {
            return Err(RepoError::BadHead(format!(
                "新 key {} 已存在；轮换要求一个全新的 key",
                new_key.key_id
            )));
        }
        validate_text("principal", &old_entry.principal)?;
        validate_role(&old_entry.role)?;

        let old_key_id = old_key.key_id.clone();
        let new_key_id = new_key.key_id.clone();
        let principal = old_entry.principal.clone();
        let role = old_entry.role.clone();
        let statement = rotation_statement(&old_key_id, &new_key_id, &principal, &role, at_ms);
        let old_signature = old_key.sign_hex(&statement)?;
        let new_signature = new_key.sign_hex(&statement)?;
        let old_public = old_key.public.clone();
        let new_public = new_key.public.clone();

        if let Some(old_entry) = store.keys.get_mut(&old_key_id) {
            old_entry.revoked_at_ms = Some(at_ms);
            old_entry.revoke_reason = Some(format!("rotated to {new_key_id}"));
        }
        store.keys.insert(
            new_key_id.clone(),
            TrustEntry {
                key_id: new_key_id.clone(),
                principal: principal.clone(),
                role: role.clone(),
                added_at_ms: at_ms,
                public_key: Some(new_public.clone()),
                rotated_from: Some(old_key_id.clone()),
                revoked_at_ms: None,
                revoke_reason: None,
            },
        );

        let reason_owned = reason.to_string();
        let session_owned = session.to_string();
        self.with_operation(
            "key",
            json!({
                "action": "rotate",
                "old_key_id": old_key_id.clone(),
                "key_id": new_key_id.clone(),
                "principal": principal.clone(),
                "role": role.clone(),
                "session": session_owned,
                "reason": reason_owned.clone(),
            }),
            at_ms,
            move |repo| {
                let before = repo.state_digest()?.to_hex();
                let keystore_hash = store.save(repo.root())?;
                let after = repo.state_digest()?.to_hex();
                repo.journal_mut().append(
                    "key",
                    json!({
                        "action": "rotate",
                        "old_key_id": old_key_id,
                        "key_id": new_key_id,
                        "principal": principal,
                        "role": role,
                        "session": session,
                        "reason": reason_owned,
                        "rotated_at_ms": at_ms,
                        "old_public": old_public,
                        "new_public": new_public,
                        "old_signature": old_signature,
                        "new_signature": new_signature,
                        "keystore_hash": keystore_hash.to_hex(),
                        "state_before": before,
                        "state_after": after,
                    }),
                    at_ms,
                )?;
                Ok(keystore_hash)
            },
        )
    }
}

/// 轮换声明的 canonical 字节；旧钥和新钥都对它签名。
pub fn rotation_statement(
    old_key_id: &str,
    new_key_id: &str,
    principal: &str,
    role: &str,
    at_ms: u64,
) -> Vec<u8> {
    format!("trit-key-rotate-v1\n{old_key_id}\n{new_key_id}\n{principal}\n{role}\n{at_ms}\n")
        .into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn store_roundtrips_and_orders_keys() {
        let root = std::env::temp_dir().join(format!(
            "trit-vcs-keys-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Repo::init(&root).unwrap();
        let mut store = TrustStore::default();
        for id in ["ed25519:bbbb", "ed25519:aaaa"] {
            store.keys.insert(
                id.to_string(),
                TrustEntry {
                    key_id: id.to_string(),
                    principal: "qoder:test".to_string(),
                    role: "author".to_string(),
                    added_at_ms: 1,
                    public_key: None,
                    rotated_from: None,
                    revoked_at_ms: None,
                    revoke_reason: None,
                },
            );
        }
        store.save(&root).unwrap();
        let loaded = TrustStore::load(&root).unwrap();
        assert_eq!(loaded.keys.len(), 2);
        let first = loaded.keys.keys().next().unwrap();
        assert_eq!(first, "ed25519:aaaa");
    }

    #[test]
    fn role_and_id_are_validated() {
        assert!(validate_role("author").is_ok());
        assert!(validate_role("root").is_err());
        assert!(validate_key_id("short").is_err());
        assert!(validate_key_id("ed25519:aaaaaaaa").is_ok());
    }

    fn rotation_repo(name: &str) -> (std::path::PathBuf, Repo, KeyFile, KeyFile) {
        let root = std::env::temp_dir().join(format!(
            "trit-vcs-rotate-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&root);
        Repo::init(&root).unwrap();
        let mut repo = Repo::open(&root).unwrap();
        let old = KeyFile::generate().unwrap();
        let new = KeyFile::generate().unwrap();
        repo.add_key(
            TrustEntry {
                key_id: old.key_id.clone(),
                principal: "qoder:rotate".to_string(),
                role: "author".to_string(),
                added_at_ms: 1_001,
                public_key: Some(old.public.clone()),
                rotated_from: None,
                revoked_at_ms: None,
                revoke_reason: None,
            },
            "qoder:rotate",
            1_001,
        )
        .unwrap();
        repo.rotate_key(&old, &new, "年度轮换", "qoder:rotate", 1_002)
            .unwrap();
        (root, repo, old, new)
    }

    #[test]
    fn rotate_event_is_checked_against_trust_lineage() {
        let (root, repo, old, new) = rotation_repo("lineage");
        let report = crate::audit::status(&repo).unwrap();
        assert!(report.ok, "轮换后审计应绿：{:?}", report.issues);

        let mut store = TrustStore::load(&root).unwrap();
        store.keys.get_mut(&new.key_id).unwrap().rotated_from = None;
        store.save(&root).unwrap();
        let report = crate::audit::status(&repo).unwrap();
        assert!(!report.ok, "抹掉轮换谱系必须判红");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "key_rotation_mismatch"),
            "应报 key_rotation_mismatch：{:?}",
            report.issues
        );
        assert_eq!(store.keys[&old.key_id].revoked_at_ms, Some(1_002));
    }

    #[test]
    fn later_rotation_does_not_retroactively_red_original() {
        let (_root, mut repo, _old, new) = rotation_repo("chain");
        let third = KeyFile::generate().unwrap();
        repo.rotate_key(&new, &third, "第二次轮换", "qoder:rotate", 1_003)
            .unwrap();
        let report = crate::audit::status(&repo).unwrap();
        assert!(
            report.ok,
            "新钥后来被轮换吊销，不应把上一次 rotate 判红：{:?}",
            report.issues
        );
        let store = repo.keys().unwrap();
        assert_eq!(store.keys[&new.key_id].revoked_at_ms, Some(1_003));
        assert!(store.keys[&third.key_id].rotated_from.as_deref() == Some(new.key_id.as_str()));
    }

    #[test]
    fn rotate_event_with_bad_signer_is_red() {
        let (_root, mut repo, old, new) = rotation_repo("bad-signature");
        let before = repo.state_digest().unwrap().to_hex();
        let payload = json!({
            "action": "rotate",
            "old_key_id": old.key_id,
            "key_id": new.key_id,
            "principal": "qoder:rotate",
            "role": "author",
            "session": "qoder:rotate",
            "reason": "年度轮换",
            "rotated_at_ms": 1_002,
            "old_public": old.public,
            "new_public": new.public,
            "old_signature": "00".repeat(64),
            "new_signature": "00".repeat(64),
            "keystore_hash": TrustStore::load(repo.root()).unwrap().save(repo.root()).unwrap().to_hex(),
            "state_before": before,
            "state_after": before,
        });
        repo.journal_mut().append("key", payload, 1_002).unwrap();
        let report = crate::audit::status(&repo).unwrap();
        assert!(!report.ok, "坏签名的 rotate 事件必须判红");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "key_rotation_mismatch"),
            "应报 key_rotation_mismatch：{:?}",
            report.issues
        );
    }
}
