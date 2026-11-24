//! 认领操作的 Ed25519 sidecar：签 op_begin、完整 ClaimSpec 与操作前后状态。

use std::path::Path;

use serde::Serialize;
use serde_json::{Value, json};

use super::ClaimsError;
use crate::gate::ClaimSpec;
use crate::hash::Hash;
use crate::journal::Event;
use crate::keys::public_key_id;
use crate::repo::{Repo, RepoError};
use crate::signing::{KeyFile, public_key_bytes};

pub(crate) const SCHEMA: &str = "trit-claim-sign-v1";
pub(crate) const EVENT_KIND: &str = "claim_signature";

#[derive(Clone, Debug)]
pub(crate) struct Signer {
    key: KeyFile,
    principal: String,
}

impl Signer {
    pub(crate) fn load(repo: &Repo, key_path: &Path, owner: &str) -> Result<Self, ClaimsError> {
        let rejected = |detail: String| ClaimsError::Signature(detail);
        let key =
            KeyFile::load(key_path).map_err(|err| rejected(format!("私钥文件不可用：{err}")))?;
        let entry = repo
            .keys()
            .map_err(|err| rejected(format!("读不到中央仓信任表：{err}")))?
            .keys
            .get(&key.key_id)
            .cloned()
            .ok_or_else(|| rejected(format!("key {} 不在中央仓信任表", key.key_id)))?;
        let public = entry
            .public_key
            .as_deref()
            .ok_or_else(|| rejected(format!("key {} 没有公钥", key.key_id)))?;
        let public_bytes = public_key_bytes(public)
            .map_err(|err| rejected(format!("key {} 的公钥不合法：{err}", key.key_id)))?;
        if public_key_id(&public_bytes) != key.key_id
            || public_bytes
                != key
                    .public_bytes()
                    .map_err(|err| rejected(err.to_string()))?
        {
            return Err(rejected(format!(
                "key {} 的公钥或指纹与私钥/信任表不一致",
                key.key_id
            )));
        }
        if entry.principal != owner {
            return Err(rejected(format!(
                "签名 principal {} 与认领 owner {owner} 不一致",
                entry.principal
            )));
        }
        if entry.role != "author" {
            return Err(rejected(format!(
                "key {} 的角色 {} 不能操作认领（需要 author）",
                key.key_id, entry.role
            )));
        }
        if entry.is_revoked() {
            return Err(rejected(format!("key {} 已吊销", key.key_id)));
        }
        Ok(Self {
            key,
            principal: entry.principal,
        })
    }

    pub(crate) fn sign(
        &self,
        action: &str,
        claim: &ClaimSpec,
        begin: &Event,
        state_after: Hash,
        at_ms: u64,
    ) -> Result<Value, ClaimsError> {
        let state_before = begin
            .payload
            .get("state_before")
            .and_then(Value::as_str)
            .and_then(Hash::from_hex)
            .ok_or_else(|| ClaimsError::Signature("op_begin 缺合法 state_before".to_string()))?;
        let statement = ClaimStatement {
            schema: SCHEMA,
            action,
            operation: begin.hash.to_hex(),
            claim,
            state_before: state_before.to_hex(),
            state_after: state_after.to_hex(),
            key_id: &self.key.key_id,
            principal: &self.principal,
            owner: &claim.owner,
            signed_at_ms: at_ms,
        }
        .to_bytes()
        .map_err(|err| ClaimsError::Signature(format!("认领声明编码失败：{err}")))?;
        let signature = self
            .key
            .sign_hex(&statement)
            .map_err(|err| ClaimsError::Signature(format!("认领签名失败：{err}")))?;
        Ok(json!({
            "schema": SCHEMA,
            "operation": begin.hash.to_hex(),
            "action": action,
            "key_id": self.key.key_id,
            "principal": self.principal,
            "owner": claim.owner,
            "algorithm": "ed25519",
            "signature": signature,
            "signed_at_ms": at_ms,
            "state_before": state_before.to_hex(),
            "state_after": state_after.to_hex(),
        }))
    }
}

#[derive(Serialize)]
pub(crate) struct ClaimStatement<'a> {
    pub(crate) schema: &'static str,
    pub(crate) action: &'a str,
    pub(crate) operation: String,
    pub(crate) claim: &'a ClaimSpec,
    pub(crate) state_before: String,
    pub(crate) state_after: String,
    pub(crate) key_id: &'a str,
    pub(crate) principal: &'a str,
    pub(crate) owner: &'a str,
    pub(crate) signed_at_ms: u64,
}

impl ClaimStatement<'_> {
    pub(crate) fn to_bytes(&self) -> Result<Vec<u8>, RepoError> {
        serde_json::to_vec(self)
            .map_err(|err| RepoError::BadHead(format!("认领声明编码失败：{err}")))
    }
}
