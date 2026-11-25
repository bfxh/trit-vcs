//! 由已验签事件与仓库状态独立推导证据闭包，检查缺失对象而不依赖包内清单。

use std::collections::BTreeSet;

use serde_json::Value;

use crate::accept::AcceptReceipt;
use crate::attestation::Attestation;
use crate::hash::Hash;
use crate::model::Commit;
use crate::repo::Repo;
use crate::store::Store;

use super::BundleError;

pub(super) fn validate(repo: &Repo) -> Result<BTreeSet<Hash>, BundleError> {
    let mut check = Closure::new(repo.store());
    for event in repo.journal().events() {
        let payload = &event.payload;
        match event.kind.as_str() {
            "stage" => {
                if let Some(tree) = hash(payload, "tree") {
                    check.tree(tree, format!("第 {} 条 stage", event.seq))?;
                }
            }
            "commit" => {
                if let Some(commit) = hash(payload, "id") {
                    check.commit(commit, format!("第 {} 条 commit", event.seq))?;
                }
            }
            "adopt" | "ref" | "pull" | "publish" | "signature" => {
                if let Some(commit) = hash(payload, "commit") {
                    check.commit(commit, format!("第 {} 条 {}", event.seq, event.kind))?;
                }
            }
            "merge" => {
                for key in ["ours", "theirs", "base"] {
                    if let Some(commit) = hash(payload, key) {
                        check.commit(commit, format!("第 {} 条 merge.{key}", event.seq))?;
                    }
                }
                if let Some(tree) = hash(payload, "tree") {
                    check.tree(tree, format!("第 {} 条 merge", event.seq))?;
                }
            }
            "accept" => {
                if let Some(receipt) = hash(payload, "receipt") {
                    check.receipt(receipt, format!("第 {} 条 accept", event.seq))?;
                }
            }
            "attestation" => {
                if let Some(attestation) = hash(payload, "attestation") {
                    check.attestation(attestation, format!("第 {} 条 attestation", event.seq))?;
                }
            }
            _ => {}
        }
    }
    if let Some(head) = repo.head()? {
        check.commit(head, "HEAD".to_string())?;
    }
    for (name, commit) in repo.list_refs()? {
        check.commit(commit, format!("ref {name}"))?;
    }
    if let Some(index) = repo.index()?
        && let Some(tree) = Hash::from_hex(&index.tree)
    {
        check.tree(tree, "index.json".to_string())?;
    }
    Ok(check.seen)
}

struct Closure<'a> {
    store: &'a Store,
    seen: BTreeSet<Hash>,
    expanded_trees: BTreeSet<Hash>,
}

impl<'a> Closure<'a> {
    fn new(store: &'a Store) -> Self {
        Self {
            store,
            seen: BTreeSet::new(),
            expanded_trees: BTreeSet::new(),
        }
    }

    fn object(&mut self, id: Hash, source: &str) -> Result<(), BundleError> {
        if self.seen.insert(id) {
            self.store.get_chunk(&id).map_err(|err| {
                BundleError::invalid(
                    "audit_bundle_incomplete",
                    format!("{source} 需要对象 {}，但对象缺失或损坏：{err}", id.short()),
                )
            })?;
        }
        Ok(())
    }

    fn tree(&mut self, id: Hash, source: String) -> Result<(), BundleError> {
        if !self.expanded_trees.insert(id) {
            return Ok(());
        }
        self.object(id, &source)?;
        let entries = self.store.tree_entries(&id)?;
        for (path, file) in entries {
            if !safe_path(&path) {
                return Err(BundleError::invalid(
                    "audit_bundle_incomplete",
                    format!("树 {id} 含不安全路径 {path:?}"),
                ));
            }
            self.file(file, format!("{source} 的路径 {path}"))?;
        }
        Ok(())
    }

    fn file(&mut self, id: Hash, source: String) -> Result<(), BundleError> {
        self.object(id, &source)?;
        let map = self.store.file_map(&id)?;
        let mut expected_size = 0u64;
        for chunk in &map.chunks {
            let bytes = self.store.get_chunk(chunk).map_err(|err| {
                BundleError::invalid(
                    "audit_bundle_incomplete",
                    format!("{source} 需要块 {chunk}，但块缺失或损坏：{err}"),
                )
            })?;
            self.seen.insert(*chunk);
            expected_size = expected_size
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| {
                    BundleError::invalid(
                        "audit_bundle_incomplete",
                        format!("{source} 的文件长度溢出"),
                    )
                })?;
        }
        if expected_size != map.size {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                format!("{source} 的文件映射长度与块内容不符"),
            ));
        }
        Ok(())
    }

    fn commit(&mut self, id: Hash, source: String) -> Result<(), BundleError> {
        let is_new = self.seen.insert(id);
        if !is_new {
            return Ok(());
        }
        let bytes = self.store.get_chunk(&id).map_err(|err| {
            BundleError::invalid(
                "audit_bundle_incomplete",
                format!("{source} 需要提交 {}，但提交缺失或损坏：{err}", id.short()),
            )
        })?;
        let commit: Commit = serde_json::from_slice(&bytes)?;
        if commit.id()? != id {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                format!("{source} 的提交摘要与对象名不符"),
            ));
        }
        self.tree(commit.tree, source.clone())?;
        for parent in &commit.parents {
            self.commit(*parent, format!("{source} 的父提交"))?;
        }
        if let Some(witness) = commit.witness {
            self.object(witness, &source)?;
        }
        if let Some(claim_set) = commit.claim_set {
            self.object(claim_set, &source)?;
        }
        if let Some(base) = commit.intent.as_ref().and_then(|intent| intent.base) {
            self.tree(base, format!("{source} 的意图父树"))?;
        }
        Ok(())
    }

    fn receipt(&mut self, id: Hash, source: String) -> Result<(), BundleError> {
        let is_new = self.seen.insert(id);
        if !is_new {
            return Ok(());
        }
        let bytes = self.store.get_chunk(&id)?;
        let receipt: AcceptReceipt = serde_json::from_slice(&bytes)?;
        if receipt.id()? != id {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                format!("{source} 的回执摘要与对象名不符"),
            ));
        }
        self.tree(receipt.tree, source.clone())?;
        if let Some(base) = receipt.base {
            self.tree(base, format!("{source} 的回执父树"))?;
        }
        Ok(())
    }

    fn attestation(&mut self, id: Hash, source: String) -> Result<(), BundleError> {
        let is_new = self.seen.insert(id);
        if !is_new {
            return Ok(());
        }
        let bytes = self.store.get_chunk(&id)?;
        if Hash::of(&bytes) != id {
            return Err(BundleError::invalid(
                "audit_bundle_incomplete",
                format!("{source} 的证明摘要与对象名不符"),
            ));
        }
        let attestation: Attestation = serde_json::from_slice(&bytes)?;
        self.commit(attestation.commit, source.clone())?;
        self.object(attestation.witness, &source)?;
        self.tree(attestation.tree, source.clone())?;
        if let Some(base) = attestation.base {
            self.tree(base, format!("{source} 的证明父树"))?;
        }
        Ok(())
    }
}

fn hash(payload: &Value, key: &str) -> Option<Hash> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .and_then(Hash::from_hex)
}

fn safe_path(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.starts_with('\\')
        && !path.contains('\\')
        && !path
            .split('/')
            .any(|segment| segment.is_empty() || segment == ".." || segment == ".")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::model::{Commit, Hlc, Intent};
    use crate::store::FileMap;
    use serde_json::json;

    fn temp_repo() -> (std::path::PathBuf, Repo) {
        for _ in 0..8 {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random).unwrap();
            let path =
                std::env::temp_dir().join(format!("trit-vcs-tvab-evidence-{}", Hash::of(&random)));
            match std::fs::create_dir(&path) {
                Ok(()) => {
                    let repo = Repo::init(&path).unwrap();
                    return (path, repo);
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => panic!("创建测试目录失败：{err}"),
            }
        }
        panic!("无法创建唯一测试目录");
    }

    #[test]
    fn missing_tree_child_is_rejected_independently_of_manifest() {
        let (path, repo) = temp_repo();
        let file = Hash::of(b"missing-file-map");
        let mut entries = BTreeMap::new();
        entries.insert("a.txt".to_string(), file);
        let tree = repo
            .store()
            .put_chunk(&serde_json::to_vec(&entries).unwrap())
            .unwrap()
            .0;
        let err = Closure::new(repo.store())
            .tree(tree, "test".to_string())
            .unwrap_err();
        assert_eq!(err.kind(), "audit_bundle_incomplete");
        assert!(err.to_string().contains("a.txt"));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn missing_parent_commit_is_rejected() {
        let (path, repo) = temp_repo();
        let tree = repo.store().put_chunk(b"{}").unwrap().0;
        let parent = Hash::of(b"missing-parent");
        let commit = Commit::new(tree, "test:session", "child", Hlc::zero()).with_parent(parent);
        let bytes = commit.encode().unwrap();
        let id = repo.store().put_chunk(&bytes).unwrap().0;
        let err = Closure::new(repo.store())
            .commit(id, "test".to_string())
            .unwrap_err();
        assert_eq!(err.kind(), "audit_bundle_incomplete");
        assert!(err.to_string().contains("父提交"));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn merge_event_contributes_its_tree_and_file_closure() {
        let (path, mut repo) = temp_repo();
        let chunk = repo.store().put_chunk(b"merged").unwrap().0;
        let map = FileMap {
            size: 6,
            chunks: vec![chunk],
        };
        let file = repo
            .store()
            .put_chunk(&serde_json::to_vec(&map).unwrap())
            .unwrap()
            .0;
        let mut entries = BTreeMap::new();
        entries.insert("merged.txt".to_string(), file);
        let tree = repo
            .store()
            .put_chunk(&serde_json::to_vec(&entries).unwrap())
            .unwrap()
            .0;
        repo.journal_mut()
            .append("merge", json!({"tree": tree.to_hex()}), 1)
            .unwrap();
        let required = validate(&repo).unwrap();
        assert!(required.contains(&tree));
        assert!(required.contains(&file));
        assert!(required.contains(&chunk));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn tree_bases_in_commit_receipt_and_attestation_are_expanded() {
        let (path, repo) = temp_repo();
        let tree = repo.store().put_chunk(b"{}").unwrap().0;
        let base_tree = repo.store().put_chunk(b"{ }").unwrap().0;
        let commit = Commit::new(tree, "test:session", "tree bases", Hlc::zero()).with_intent(
            Intent::new("verify tree bases", vec!["cargo test".to_string()]).with_base(base_tree),
        );
        let commit_id = repo.store().put_chunk(&commit.encode().unwrap()).unwrap().0;
        let plain_commit = Commit::new(tree, "test:session", "plain", Hlc::zero());
        let plain_commit_id = repo
            .store()
            .put_chunk(&plain_commit.encode().unwrap())
            .unwrap()
            .0;
        let witness = repo.store().put_chunk(b"witness").unwrap().0;
        let receipt = AcceptReceipt {
            schema: AcceptReceipt::SCHEMA,
            tree,
            base: Some(base_tree),
            session: "test:session".to_string(),
            claim_ids: Vec::new(),
            outcomes: Vec::new(),
            passed: true,
            at_secs: 0,
        };
        let receipt_id = repo
            .store()
            .put_chunk(&receipt.encode().unwrap())
            .unwrap()
            .0;
        let attestation = Attestation {
            schema: "trit-attestation-v1".to_string(),
            commit: plain_commit_id,
            witness,
            tree,
            base: Some(base_tree),
            key_id: "ed25519:test".to_string(),
            algorithm: "ed25519".to_string(),
            signature: "00".to_string(),
            signed_at_ms: 0,
            session: "test:session".to_string(),
        };
        let attestation_id = repo
            .store()
            .put_chunk(&serde_json::to_vec(&attestation).unwrap())
            .unwrap()
            .0;

        let mut commit_closure = Closure::new(repo.store());
        commit_closure
            .commit(commit_id, "test commit".to_string())
            .unwrap();
        assert!(commit_closure.seen.contains(&base_tree));

        let mut receipt_closure = Closure::new(repo.store());
        receipt_closure
            .receipt(receipt_id, "test receipt".to_string())
            .unwrap();
        assert!(receipt_closure.seen.contains(&base_tree));

        let mut attestation_closure = Closure::new(repo.store());
        attestation_closure
            .attestation(attestation_id, "test attestation".to_string())
            .unwrap();
        assert!(attestation_closure.seen.contains(&base_tree));
        std::fs::remove_dir_all(path).unwrap();
    }

    #[test]
    fn file_map_size_must_match_chunk_bytes() {
        let (path, repo) = temp_repo();
        let chunk = repo.store().put_chunk(b"abc").unwrap().0;
        let map = FileMap {
            size: 4,
            chunks: vec![chunk],
        };
        let file = repo
            .store()
            .put_chunk(&serde_json::to_vec(&map).unwrap())
            .unwrap()
            .0;
        let err = Closure::new(repo.store())
            .file(file, "test".to_string())
            .unwrap_err();
        assert_eq!(err.kind(), "audit_bundle_incomplete");
        assert!(err.to_string().contains("长度"));
        std::fs::remove_dir_all(path).unwrap();
    }
}
