//! 仓库策略的受审计变更：改 `policy.json` 前后都进同一套写前/写后协议。
//!
//! 策略本身只有门禁开关，但它是“谁能提交什么”的依据；手工改文件虽然会被
//! `state_digest` 漂移抓到，却没有一条能说明“谁在什么时候把哪一项打开了”的事件。
//! 这里补上 `policy` 事件，并让 `policy_hash` 与 `state_digest` 使用同一套字节哈希。

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hash::Hash;
use crate::repo::{DIR, Repo, RepoError};

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
        let _guard = self.lock_state()?;
        let path = self.root().join(DIR).join("policy.json");
        let session_owned = session.to_string();
        let args = json!({
            "session": session_owned,
            "require_witness": policy.require_witness,
            "require_intent": policy.require_intent,
            "require_signed_claims": policy.require_signed_claims,
            "require_signed_witness": policy.require_signed_witness,
        });
        self.with_operation("policy", args, at_ms, move |repo| {
            let before = repo.state_digest()?.to_hex();
            let bytes = serde_json::to_vec_pretty(policy)
                .map_err(|err| RepoError::BadHead(format!("policy 编码失败：{err}")))?;
            std::fs::write(&path, &bytes)?;
            let policy_hash = Hash::of(&bytes);
            let after = repo.state_digest()?.to_hex();
            repo.journal_mut().append(
                "policy",
                json!({
                    "schema": "trit-policy-v1",
                    "session": session,
                    "require_witness": policy.require_witness,
                    "require_intent": policy.require_intent,
                    "require_signed_claims": policy.require_signed_claims,
                    "require_signed_witness": policy.require_signed_witness,
                    "policy_hash": policy_hash.to_hex(),
                    "state_before": before,
                    "state_after": after,
                }),
                at_ms,
            )?;
            Ok(policy_hash)
        })
    }
}
