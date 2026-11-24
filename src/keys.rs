//! 受审计的信任表：`keys.json` 记录 key_id、principal、角色和吊销状态。
//!
//! 这里刻意不生成也不验证签名：它是 L3 之前的“谁被信任”账本，先保证每次
//! add/revoke 都有写前状态、写后状态和操作结果。未来接入 Ed25519 验签时，
//! key_id 仍是公钥指纹，事件格式不用推翻，只是多一条验签判据。

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hash::Hash;
use crate::repo::{DIR, Repo, RepoError};

pub const FILE: &str = "keys.json";

/// 信任表里的一条 key。`revoked_at_ms` 有值即吊销，不删除历史。
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustEntry {
    pub key_id: String,
    pub principal: String,
    pub role: String,
    pub added_at_ms: u64,
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

/// key_id 是外部提供的公钥指纹；当前只做形状校验，不做密码学验证。
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
        entry: TrustEntry,
        session: &str,
        at_ms: u64,
    ) -> Result<Hash, RepoError> {
        validate_key_id(&entry.key_id)?;
        validate_text("principal", &entry.principal)?;
        validate_role(&entry.role)?;
        validate_text("session", session)?;
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
}
