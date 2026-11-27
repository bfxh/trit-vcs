//! 仓库策略的受审计变更：改 `policy.json` 前后都进同一套写前/写后协议。
//!
//! 策略本身只有门禁开关，但它是“谁能提交什么”的依据；手工改文件虽然会被
//! `state_digest` 漂移抓到，却没有一条能说明“谁在什么时候把哪一项打开了”的事件。
//! 这里补上 `policy` 事件，并让 `policy_hash` 与 `state_digest` 使用同一套字节哈希。
//!
//! 可选 Ed25519 签名把“改策略的人”绑到事件：`policy set --sign-key` 会签
//! 旧/新策略摘要、五个开关、阈值、session、时间和 key id；`require_signed_policy`
//! 打开后，后续策略变更必须带足够数量的 `auditor` 签名，否则审计判红。

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hash::Hash;
use crate::repo::{DIR, Repo, RepoError};
use crate::signing::KeyFile;

pub(crate) const POLICY_SCHEMA: &str = "trit-policy-v1";
pub(crate) const POLICY_SCHEMA_V2: &str = "trit-policy-v2";
pub const MAX_POLICY_THRESHOLD: u8 = 16;

fn default_policy_threshold() -> u8 {
    1
}

/// 仓库策略（`.tritvcs/policy.json`）。默认全关：不影响别项目，成熟后逐项目 opt-in。
#[derive(Clone, Debug, Serialize, Deserialize)]
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
    /// 严格策略需要多少个不同的 `auditor` 签名。`0` 视为非法配置。
    #[serde(default = "default_policy_threshold")]
    pub policy_threshold: u8,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_witness: false,
            require_intent: false,
            require_signed_claims: false,
            require_signed_witness: false,
            require_signed_policy: false,
            policy_threshold: 1,
        }
    }
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

/// 多签策略的规范字节。每个签名者各签一份，`key_id` 与 `signed_at_ms` 是
/// 该签名者自己的值；其余字段必须完全一致，尤其是 `policy_threshold`。
#[derive(Serialize)]
struct PolicyStatementV2<'a> {
    schema: &'static str,
    action: &'static str,
    session: &'a str,
    require_witness: bool,
    require_intent: bool,
    require_signed_claims: bool,
    require_signed_witness: bool,
    require_signed_policy: bool,
    policy_threshold: u8,
    previous_policy_hash: Option<&'a str>,
    policy_hash: &'a str,
    signed_at_ms: u64,
    key_id: &'a str,
}

pub(crate) fn policy_statement_v2_bytes(
    session: &str,
    policy: &Policy,
    previous_policy_hash: Option<&str>,
    policy_hash: &str,
    signed_at_ms: u64,
    key_id: &str,
) -> Result<Vec<u8>, RepoError> {
    serde_json::to_vec(&PolicyStatementV2 {
        schema: POLICY_SCHEMA_V2,
        action: "set",
        session,
        require_witness: policy.require_witness,
        require_intent: policy.require_intent,
        require_signed_claims: policy.require_signed_claims,
        require_signed_witness: policy.require_signed_witness,
        require_signed_policy: policy.require_signed_policy,
        policy_threshold: policy.policy_threshold,
        previous_policy_hash,
        policy_hash,
        signed_at_ms,
        key_id,
    })
    .map_err(|err| RepoError::BadHead(format!("策略签名载荷编码失败：{err}")))
}

/// 本次变更必须收集的签名数：当前严格阈值与新严格阈值取较大者。
/// 调低阈值也必须先满足旧阈值，避免用单钥把 3-of-N 降成 1-of-N。
pub(crate) fn policy_quorum(
    current_require: bool,
    current_threshold: u8,
    next_require: bool,
    next_threshold: u8,
) -> usize {
    if !current_require && !next_require {
        return 0;
    }
    let current = if current_require {
        usize::from(current_threshold.max(1))
    } else {
        1
    };
    let next = if next_require {
        usize::from(next_threshold.max(1))
    } else {
        1
    };
    current.max(next)
}

fn ensure_policy_threshold(policy: &Policy) -> Result<(), RepoError> {
    if !(1..=MAX_POLICY_THRESHOLD).contains(&policy.policy_threshold) {
        return Err(RepoError::BadHead(format!(
            "policy_threshold 必须在 1..={MAX_POLICY_THRESHOLD}；收到 {}",
            policy.policy_threshold
        )));
    }
    Ok(())
}

fn policy_file_hash(path: &Path) -> Result<Option<Hash>, RepoError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(Hash::of(&bytes))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(RepoError::Io(err)),
    }
}

fn ensure_trusted_signer(
    repo: &Repo,
    key: &KeyFile,
    require_auditor: bool,
) -> Result<(), RepoError> {
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
    if require_auditor && entry.role != "auditor" {
        return Err(RepoError::BadHead(format!(
            "策略签名要求 auditor 角色；key {} 的角色是 {}",
            key.key_id, entry.role
        )));
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

    /// 与 `set_policy` 相同，但可用一组 Ed25519 私钥给本次策略变更签名。
    ///
    /// 当前策略或新策略打开 `require_signed_policy` 时，签名数必须达到
    /// 两边阈值的较大者，且每把 key 都必须是信任表里 `auditor` 角色的
    /// 不同 key；签名覆盖旧/新摘要、完整开关、阈值、session 与各自 key id。
    pub fn set_policy_with_signers(
        &mut self,
        policy: &Policy,
        session: &str,
        at_ms: u64,
        signers: &[&Path],
    ) -> Result<Hash, RepoError> {
        let _guard = self.lock_state()?;
        ensure_policy_threshold(policy)?;
        let current = self.policy()?;
        ensure_policy_threshold(&current)?;
        let required = policy_quorum(
            current.require_signed_policy,
            current.policy_threshold,
            policy.require_signed_policy,
            policy.policy_threshold,
        );
        let keys = signers
            .iter()
            .map(|path| KeyFile::load(path))
            .collect::<Result<Vec<_>, _>>()?;
        if required > 0 && keys.is_empty() {
            return Err(RepoError::BadHead(format!(
                "策略要求 {required} 个 auditor 签名；policy set 需要 --sign-key <私钥文件>"
            )));
        }
        if required > 0 && keys.len() < required {
            return Err(RepoError::BadHead(format!(
                "策略要求至少 {required} 个不同 auditor 签名；只收到 {} 个 --sign-key",
                keys.len()
            )));
        }
        let mut seen = HashSet::new();
        for key in &keys {
            if !seen.insert(key.key_id.clone()) {
                return Err(RepoError::BadHead(format!(
                    "policy set 收到重复的签名 key：{}",
                    key.key_id
                )));
            }
            ensure_trusted_signer(self, key, required > 0)?;
        }

        let path = self.root().join(DIR).join("policy.json");
        let policy_owned = policy.clone();
        let key_ids = keys
            .iter()
            .map(|key| key.key_id.clone())
            .collect::<Vec<_>>();
        let session_owned = session.to_string();
        let args = json!({
            "session": session_owned,
            "require_witness": policy.require_witness,
            "require_intent": policy.require_intent,
            "require_signed_claims": policy.require_signed_claims,
            "require_signed_witness": policy.require_signed_witness,
            "require_signed_policy": policy.require_signed_policy,
            "policy_threshold": policy.policy_threshold,
            "signed": !key_ids.is_empty(),
            "key_ids": key_ids,
        });
        self.with_operation("policy", args, at_ms, move |repo| {
            let before = repo.state_digest()?.to_hex();
            let previous = policy_file_hash(&path)?;
            let bytes = serde_json::to_vec_pretty(&policy_owned)
                .map_err(|err| RepoError::BadHead(format!("policy 编码失败：{err}")))?;
            let policy_hash = Hash::of(&bytes);
            let policy_hash_hex = policy_hash.to_hex();
            let previous_hex = previous.map(|hash| hash.to_hex());
            let signatures = keys
                .iter()
                .map(|key| {
                    let statement = policy_statement_v2_bytes(
                        session,
                        &policy_owned,
                        previous_hex.as_deref(),
                        &policy_hash_hex,
                        at_ms,
                        &key.key_id,
                    )?;
                    Ok::<_, RepoError>(json!({
                        "key_id": key.key_id.clone(),
                        "signature": key.sign_hex(&statement)?,
                        "signed_at_ms": at_ms,
                    }))
                })
                .collect::<Result<Vec<_>, _>>()?;

            fs::write(&path, &bytes)?;
            let after = repo.state_digest()?.to_hex();
            let mut payload = json!({
                "schema": POLICY_SCHEMA_V2,
                "session": session,
                "require_witness": policy_owned.require_witness,
                "require_intent": policy_owned.require_intent,
                "require_signed_claims": policy_owned.require_signed_claims,
                "require_signed_witness": policy_owned.require_signed_witness,
                "require_signed_policy": policy_owned.require_signed_policy,
                "policy_threshold": policy_owned.policy_threshold,
                "previous_policy_hash": previous_hex,
                "policy_hash": policy_hash_hex,
                "state_before": before,
                "state_after": after,
            });
            if !signatures.is_empty() {
                payload["action"] = json!("set");
                payload["algorithm"] = json!("ed25519");
                payload["signatures"] = json!(signatures);
            }
            repo.journal_mut().append("policy", payload, at_ms)?;
            Ok(policy_hash)
        })
    }

    /// 单钥便捷入口；语义与 `set_policy_with_signers` 完全一致。
    pub fn set_policy_with_signer(
        &mut self,
        policy: &Policy,
        session: &str,
        at_ms: u64,
        signer: Option<&Path>,
    ) -> Result<Hash, RepoError> {
        let signers = signer.into_iter().collect::<Vec<_>>();
        self.set_policy_with_signers(policy, session, at_ms, &signers)
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
        assert_eq!(event.payload["policy_threshold"], 1);
        assert_eq!(event.payload["algorithm"], "ed25519");
        assert_eq!(event.payload["schema"], POLICY_SCHEMA_V2);
        assert_eq!(event.payload["signatures"][0]["key_id"], key.key_id);
        assert!(event.payload["previous_policy_hash"].is_null());
        assert!(
            event.payload["signatures"][0]["signature"]
                .as_str()
                .is_some_and(|value| {
                    value.len() == 128 && value.chars().all(|ch| ch.is_ascii_hexdigit())
                })
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn policy_quorum_requires_multiple_auditor_signatures_and_blocks_threshold_downgrade() {
        let (root, mut repo, key, key_path) = signed_setup("quorum");
        let second = KeyFile::generate().unwrap();
        let second_path = root.join("policy-second.key");
        second.save_new(&second_path).unwrap();
        repo.add_key(
            TrustEntry {
                key_id: second.key_id.clone(),
                principal: "qoder:policy-second".to_string(),
                role: "auditor".to_string(),
                added_at_ms: 1_500,
                public_key: Some(second.public.clone()),
                rotated_from: None,
                revoked_at_ms: None,
                revoke_reason: None,
            },
            "qoder:admin",
            1_500,
        )
        .unwrap();

        let strict_two = Policy {
            require_signed_policy: true,
            policy_threshold: 2,
            ..Default::default()
        };
        let err = repo
            .set_policy_with_signers(&strict_two, "qoder:policy", 2_000, &[&key_path])
            .unwrap_err();
        assert!(err.to_string().contains("至少 2"), "{err}");
        repo.set_policy_with_signers(
            &strict_two,
            "qoder:policy",
            2_000,
            &[&key_path, &second_path],
        )
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
        assert_eq!(event.payload["policy_threshold"], 2);
        assert_eq!(event.payload["signatures"].as_array().unwrap().len(), 2);
        assert_eq!(event.payload["signatures"][0]["key_id"], key.key_id);

        let lower = Policy {
            policy_threshold: 1,
            ..Default::default()
        };
        let err = repo
            .set_policy_with_signers(&lower, "qoder:policy", 3_000, &[&key_path])
            .unwrap_err();
        assert!(
            err.to_string().contains("至少 2"),
            "调低阈值也必须先满足旧阈值：{err}"
        );
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
