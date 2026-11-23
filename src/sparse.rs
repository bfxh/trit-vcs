//! 持久 sparse index：记住"这个工作树只检出了哪个前缀、对应哪棵树"。
//!
//! 没有它的时候，前缀 `pull` 之后再跑 `status` 只能拿 HEAD 比：HEAD 还没落（也不该落），
//! 范围外的文件会被算成新增；范围外的改动又会混进 `status`。这里把**范围**和**基准树**
//! 一起写进 `.tritvcs/sparse.json`，`status` 就能只扫范围内、只跟这棵树比。
//!
//! 文件本身是普通 JSON（不是第二个二进制格式）：范围/树/提交三个字段、坏了就整份丢弃，
//! 判定的正确性仍然由对象库里的树保证——索引丢了只是退化成全量扫描，不会给出错误结论。

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::hash::Hash;
use crate::repo::DIR;

pub const FILE: &str = "sparse.json";
pub const SCHEMA: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum SparseError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("sparse 索引不是合法 JSON：{0}")]
    Json(#[from] serde_json::Error),
    #[error("sparse 索引的 prefix 不合法：{0}")]
    BadPrefix(String),
    #[error("sparse 索引里的树 id 不合法：{0}")]
    BadTree(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SparseIndex {
    #[serde(default = "default_schema")]
    pub schema: u32,
    /// 只检出这个前缀（路径段匹配，`gen` 覆盖 `gen/...`）。
    pub prefix: String,
    /// 工作树内容对应的树 id。
    pub tree: String,
    /// 这棵树来自哪个提交（只是给人看的，判定不用它）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commit: Option<String>,
}

fn default_schema() -> u32 {
    SCHEMA
}

impl SparseIndex {
    pub fn new(prefix: &str, tree: Hash, commit: Option<Hash>) -> Result<Self, SparseError> {
        let prefix = normalize_prefix(prefix)?;
        Ok(Self {
            schema: SCHEMA,
            prefix,
            tree: tree.to_hex(),
            commit: commit.map(|id| id.to_hex()),
        })
    }

    pub fn path(root: &Path) -> PathBuf {
        root.join(DIR).join(FILE)
    }

    /// 读不出来就当成"没有 sparse 索引"（坏文件不阻塞 status，只是这次全量扫）。
    pub fn load(root: &Path) -> Option<Self> {
        let text = fs::read_to_string(Self::path(root)).ok()?;
        let index: Self = serde_json::from_str(&text).ok()?;
        (index.schema == SCHEMA && normalize_prefix(&index.prefix).ok()? == index.prefix)
            .then_some(index)
    }

    /// 先写临时文件再改名：半截索引不会覆盖好索引。
    pub fn save(&self, root: &Path) -> Result<(), SparseError> {
        let path = Self::path(root);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// 全量检出/全量 pull 之后清掉：范围已经不是"稀疏"了。
    pub fn clear(root: &Path) -> Result<(), SparseError> {
        let path = Self::path(root);
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    pub fn tree_id(&self) -> Option<Hash> {
        Hash::from_hex(&self.tree)
    }

    /// 校验并返回树 id；索引里的树必须能解析，否则当坏索引。
    pub fn expect_tree(&self) -> Result<Hash, SparseError> {
        self.tree_id()
            .ok_or_else(|| SparseError::BadTree(self.tree.clone()))
    }
}

/// 前缀归一：去掉末尾 `/`；拒绝空、绝对路径、`..`、反斜杠（跨平台路径要同一口径）。
pub fn normalize_prefix(raw: &str) -> Result<String, SparseError> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(SparseError::BadPrefix(raw.to_string()));
    }
    if trimmed.starts_with('/') || trimmed.starts_with('\\') || trimmed.contains('\\') {
        return Err(SparseError::BadPrefix(raw.to_string()));
    }
    if trimmed.split('/').any(|seg| seg == ".." || seg.is_empty()) {
        return Err(SparseError::BadPrefix(raw.to_string()));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trit-vcs-sparse-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(DIR)).unwrap();
        dir
    }

    #[test]
    fn index_roundtrips_and_clears() {
        let root = temp("roundtrip");
        let index =
            SparseIndex::new("gen/d00/", Hash::of(b"tree"), Some(Hash::of(b"commit"))).unwrap();
        assert_eq!(index.prefix, "gen/d00");
        index.save(&root).unwrap();
        assert_eq!(SparseIndex::load(&root).unwrap(), index);
        SparseIndex::clear(&root).unwrap();
        assert!(SparseIndex::load(&root).is_none());
    }

    #[test]
    fn bad_prefixes_are_rejected() {
        for bad in ["", "/abs", "a/../b", "a//b", "a\\b"] {
            assert!(normalize_prefix(bad).is_err(), "{bad}");
        }
        assert_eq!(normalize_prefix("gen/d00/").unwrap(), "gen/d00");
        assert_eq!(normalize_prefix("top.txt").unwrap(), "top.txt");
    }

    #[test]
    fn corrupt_index_is_ignored_instead_of_failing() {
        let root = temp("corrupt");
        fs::write(SparseIndex::path(&root), b"not json").unwrap();
        assert!(SparseIndex::load(&root).is_none());
        fs::write(
            SparseIndex::path(&root),
            br#"{"schema":99,"prefix":"a","tree":"00"}"#,
        )
        .unwrap();
        assert!(SparseIndex::load(&root).is_none());
    }
}
