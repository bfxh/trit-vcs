//! 状态摘要：把 HEAD、refs、index、策略、认领账本和信任表压成一个可对账摘要。

use std::collections::BTreeMap;
use std::path::Path;

use serde_json::json;

use crate::hash::Hash;

use super::{Repo, RepoError};

impl Repo {
    /// 当前状态的可复算摘要：HEAD + refs + index + policy 字节 + claims 字节。
    ///
    /// 不把 journal 自己算进去——审计要问的是"日志是否解释了这份状态"，不能循环自证。
    /// 文件用原始字节哈希而不是解析后的结构：格式/空白变化也算状态变化，审计宁可多报。
    pub fn state_digest(&self) -> Result<Hash, RepoError> {
        let head = self.head()?.map(|id| id.to_hex());
        let refs: BTreeMap<String, String> = self
            .list_refs()?
            .into_iter()
            .map(|(name, id)| (name, id.to_hex()))
            .collect();
        let index = self.index()?;
        let policy = file_digest(&Self::dir(&self.root).join("policy.json"))?;
        let claims = file_digest(&Self::dir(&self.root).join("claims.json"))?;
        let keys_path = Self::dir(&self.root).join("keys.json");
        let keyset = if keys_path.is_file() {
            Some(file_digest(&keys_path)?)
        } else {
            None
        };
        let mut state = json!({
            "head": head,
            "refs": refs,
            "index": index,
            "policy": policy,
            "claims": claims,
        });
        // 旧仓没有 keys.json；此时不加入该字段，避免在没有信任表的仓里
        // 平白改变历史事件的状态摘要口径。第一次 key add 会显式进入。
        if let Some(keyset) = keyset {
            state["keyset"] = json!(keyset);
        }
        let bytes = serde_json::to_vec(&state).map_err(|e| RepoError::BadHead(e.to_string()))?;
        Ok(Hash::of(&bytes))
    }
}

fn file_digest(path: &Path) -> Result<Option<String>, RepoError> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(Hash::of(&bytes).to_hex())),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(RepoError::Io(err)),
    }
}
