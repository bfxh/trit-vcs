//! 仓库策略的受审计变更：改 `policy.json` 前后都进同一套写前/写后协议。
//!
//! 策略本身只有门禁开关，但它是“谁能提交什么”的依据；手工改文件虽然会被
//! `state_digest` 漂移抓到，却没有一条能说明“谁在什么时候把哪一项打开了”的事件。
//! 这里补上 `policy` 事件，并让 `policy_hash` 与 `state_digest` 使用同一套字节哈希。
//!
//! 可选 Ed25519 签名把“改策略的人”绑到事件：`policy set --sign-key` 会签
//! 旧/新策略摘要、五个开关、session、时间和 key id；`require_signed_policy`
//! 打开后，后续策略变更必须带有效签名，否则审计判红。

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hash::Hash;
use crate::repo::{DIR, Repo, RepoError};
use crate::signing::KeyFile;

pub(crate) const POLICY_SCHEMA: &str = "trit-policy-v1";

/// 仓库策略（`.tritvcs/policy.json`）。默认全关：不影响别项目，成熟后逐项目 opt-in。
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub require_witness: bool,
    #[serde(default)]
    pub require_intent: bool,
    #[serde(default)]
    pub require_signed_claims: bool,
    #[serde(default)]
    pub require_signed_witness: bool,
    /// 打开后，后续 `policy` 事件必须有 Ed25519 签名；开启这条的策略变更自身也必须签名。
    #[serde(default)]
    pub require_signed_policy: bool,
}

/// 策略签名覆盖的规范字节。字段顺序固定，签名和审计必须用同一份形状。
#[derive(Serialize)]
struct PolicyStatement<'a> {
    schema: &'static str,
    action: &'static str,
    session: &'a str,
    require_witness: bool,
    require_intent: bool,
    require_signed_claims: bool,
    require_signed_witness: bool,
    require_signed_policy: bool,
    previous_policy_hash: Option<&'a str>,
    policy_hash: &'a str,
    signed_at_ms: u64,
    key_id: &'a str,
}

pub(crate) fn policy_statement_bytes(
    session: &str,
    policy: &Policy,
    previous_policy_hash: Option<&str>,
    policy_hash: &str,
    signed_at_ms: u64,
    key_id: &str,
) -> Result<Vec<u8>, RepoError> {
    serde_json::to_vec(&PolicyStatement {
        schema: POLICY_SCHEMA,
        action: "set",
        session,
        require_witness: policy.require_witness,
        require_intent: policy.require_intent,
        require_signed_claims: policy.require_signed_claims,
        require_signed_witness: policy.require_signed_witness,
        require_signed_policy: policy.require_signed_policy,
        previous_policy_hash,
        policy_hash,
        signed_at_ms,
        key_id,
    })
    .map_err(|err| RepoError::BadHead(format!("策略签名载荷编码失败：{err}")))
}

fn policy_file_hash(path: &Path) -> Result<Option<Hash>, RepoError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(Hash::of(&bytes))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(RepoError::Io(err)),
    }
}

fn ensure_trusted_signer(repo: &Repo, key: &KeyFile) -> Result<(), RepoError> {
    let keys = repo.keys()?;
    let Some(entry) = keys.keys.get(&key.key_id) else {
        return Err(RepoError::BadHead(format!(
            "key {} 不在信任表；先 key add",
            key.key_id
        )));
    };
    if entry.public_key.as_deref() != Some(key.public.as_str()) {
        return Err(RepoError::BadHead(format!(
            "key {} 的公钥与信任表不一致",
            key.key_id
        )));
    }
    if entry.is_revoked() {
        return Err(RepoError::BadHead(format!("key {} 已吊销", key.key_id)));
    }
    Ok(())
}

impl Repo {
    /// 写入整份策略，并记录 `policy` 事件。参数是“完整策略”，不是增量：
    /// 调用方必须明确本次要打开/关闭哪些开关，避免旧的 true 被悄悄带过去。
    pub fn set_policy(
        &mut self,
        policy: &Policy,
        session: &str,
        at_ms: u64,
    ) -> Result<Hash, RepoError> {
        self.set_policy_with_signer(policy, session, at_ms, None)
    }

    /// 与 `set_policy` 相同，但可用 Ed25519 私钥给本次策略变更签名。
    ///
    /// 当前策略或新策略打开 `require_signed_policy` 时，`signer` 不能为空；
    /// 签名覆盖旧/新摘要与完整开关，事件本身仍不改 `policy.json` 的形状。
    pub fn set_policy_with_signer(
        &mut self,
        policy: &Policy,
        session: &str,
        at_ms: u64,
        signer: Option<&Path>,
    ) -> Result<Hash, RepoError> {
        let _guard = self.lock_state()?;
        let key = match signer {
            Some(path) => Some(KeyFile::load(path)?),
            None => None,
        };
        if let Some(key) = key.as_ref() {
            ensure_trusted_signer(self, key)?;
        }
        let current = self.policy()?;
        if (current.require_signed_policy || policy.require_signed_policy) && key.is_none() {
            return Err(RepoError::BadHead(
                "策略要求签名；policy set 需要 --sign-key <私钥文件>".to_string(),
            ));
        }

        let path = self.root().join(DIR).join("policy.json");
        let policy_owned = policy.clone();
        let key_owned = key;
        let key_id = key_owned.as_ref().map(|key| key.key_id.clone());
        let session_owned = session.to_string();
        let args = json!({
            "session": session_owned,
            "require_witness": policy.require_witness,
            "require_intent": policy.require_intent,
            "require_signed_claims": policy.require_signed_claims,
            "require_signed_witness": policy.require_signed_witness,
            "require_signed_policy": policy.require_signed_policy,
            "signed": key_owned.is_some(),
            "key_id": key_id,
        });
        self.with_operation("policy", args, at_ms, move |repo| {
            let before = repo.state_digest()?.to_hex();
            let previous = policy_file_hash(&path)?;
            let bytes = serde_json::to_vec_pretty(&policy_owned)
                .map_err(|err| RepoError::BadHead(format!("policy 编码失败：{err}")))?;
            let policy_hash = Hash::of(&bytes);
            let policy_hash_hex = policy_hash.to_hex();
            let previous_hex = previous.map(|hash| hash.to_hex());
            let signature = key_owned
                .as_ref()
                .map(|key| {
                    let statement = policy_statement_bytes(
                        session,
                        &policy_owned,
                        previous_hex.as_deref(),
                        &policy_hash_hex,
                        at_ms,
                        &key.key_id,
                    )?;
                    Ok::<_, RepoError>((key.key_id.clone(), key.sign_hex(&statement)?))
                })
                .transpose()?;

            fs::write(&path, &bytes)?;
            let after = repo.state_digest()?.to_hex();
            let mut payload = json!({
                "schema": POLICY_SCHEMA,
                "session": session,
                "require_witness": policy_owned.require_witness,
                "require_intent": policy_owned.require_intent,
                "require_signed_claims": policy_owned.require_signed_claims,
                "require_signed_witness": policy_owned.require_signed_witness,
                "require_signed_policy": policy_owned.require_signed_policy,
                "previous_policy_hash": previous_hex,
                "policy_hash": policy_hash_hex,
                "state_before": before,
                "state_after": after,
            });
            if let Some((key_id, signature)) = signature {
                payload["action"] = json!("set");
                payload["algorithm"] = json!("ed25519");
                payload["key_id"] = json!(key_id);
                payload["signature"] = json!(signature);
                payload["signed_at_ms"] = json!(at_ms);
            }
            repo.journal_mut().append("policy", payload, at_ms)?;
            Ok(policy_hash)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::TrustEntry;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trit-vcs-policy-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn signed_setup(name: &str) -> (std::path::PathBuf, Repo, KeyFile, std::path::PathBuf) {
        let root = temp(name);
        let mut repo = Repo::init(&root).unwrap();
        let key = KeyFile::generate().unwrap();
        let key_path = root.join("policy.key");
        key.save_new(&key_path).unwrap();
        repo.add_key(
            TrustEntry {
                key_id: key.key_id.clone(),
                principal: "qoder:policy".to_string(),
                role: "auditor".to_string(),
                added_at_ms: 1_000,
                public_key: Some(key.public.clone()),
                rotated_from: None,
                revoked_at_ms: None,
                revoke_reason: None,
            },
            "qoder:admin",
            1_000,
        )
        .unwrap();
        (root, repo, key, key_path)
    }

    #[test]
    fn signed_policy_change_is_audited_and_attributes_the_key() {
        let (root, mut repo, key, key_path) = signed_setup("signed");
        let policy = Policy {
            require_signed_policy: true,
            ..Default::default()
        };
        repo.set_policy_with_signer(&policy, "qoder:policy", 2_000, Some(&key_path))
            .unwrap();
        let report = crate::audit::status(&repo).unwrap();
        assert!(report.ok, "{:?}", report.issues);

        let event = repo
            .journal()
            .events()
            .iter()
            .rev()
            .find(|event| event.kind == "policy")
            .unwrap();
        assert_eq!(event.payload["require_signed_policy"], true);
        assert_eq!(event.payload["algorithm"], "ed25519");
        assert_eq!(event.payload["key_id"], key.key_id);
        assert!(event.payload["previous_policy_hash"].is_null());
        assert!(event.payload["signature"].as_str().is_some_and(|value| {
            value.len() == 128 && value.chars().all(|ch| ch.is_ascii_hexdigit())
        }));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn strict_policy_refuses_unsigned_policy_change() {
        let (root, mut repo, _key, key_path) = signed_setup("refuse");
        let policy = Policy {
            require_signed_policy: true,
            ..Default::default()
        };
        repo.set_policy_with_signer(&policy, "qoder:policy", 2_000, Some(&key_path))
            .unwrap();
        let err = repo
            .set_policy_with_signer(&Policy::default(), "qoder:policy", 3_000, None)
            .unwrap_err();
        assert!(err.to_string().contains("需要 --sign-key"), "{err}");
        let _ = fs::remove_dir_all(&root);
    }
}
