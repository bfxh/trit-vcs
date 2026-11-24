//! 签名检查点 v0：对“检查点事件之前的所有事件哈希”做 Merkle 根，旧/新检查点用前一条哈希串起来。
//!
//! 这不是仓外锚：检查点仍在本仓 journal 里，删掉整条尾巴的人可以连检查点一起删。它要解决的是
//! “事件前缀能否被签名钉住、后来的检查点能否接上前一条”，而不是替代外部时间戳/透明日志。

use std::path::Path;

use serde::Serialize;
use serde_json::json;

use crate::hash::Hash;
use crate::keys::public_key_id;
use crate::repo::{Repo, RepoError};
use crate::signing::{KeyFile, public_key_bytes};

pub mod anchor;
pub mod consistency;
pub mod external;

/// 一次 checkpoint 的摘要，给 CLI 和测试用。
#[derive(Clone, Debug, Serialize)]
pub struct CheckpointOutcome {
    pub event: Hash,
    pub height: usize,
    pub head: Option<Hash>,
    pub merkle_root: Hash,
    pub previous: Option<Hash>,
    pub key_id: String,
    pub signature: String,
}

impl Repo {
    /// 对当前 journal 前缀做签名检查点。允许的角色是 auditor/release：检查点不是提交作者自证。
    pub fn checkpoint(
        &mut self,
        key_path: &Path,
        session: &str,
        at_ms: u64,
    ) -> Result<CheckpointOutcome, RepoError> {
        if session.trim().is_empty() || session.chars().any(char::is_control) {
            return Err(RepoError::BadHead("session 不能为空".to_string()));
        }
        let _guard = self.lock_state()?;
        let key = KeyFile::load(key_path)?;
        let store = self.keys()?;
        let Some(entry) = store.keys.get(&key.key_id) else {
            return Err(RepoError::BadHead(format!(
                "key {} 不在信任表；先 key add",
                key.key_id
            )));
        };
        if entry
            .public_key
            .as_deref()
            .is_none_or(|public| !public.eq_ignore_ascii_case(&key.public))
        {
            return Err(RepoError::BadHead(format!(
                "key {} 的公钥与信任表不一致",
                key.key_id
            )));
        }
        if entry.is_revoked() {
            return Err(RepoError::BadHead(format!("key {} 已吊销", key.key_id)));
        }
        if !matches!(entry.role.as_str(), "auditor" | "release") {
            return Err(RepoError::BadHead(format!(
                "key {} 的角色是 {}；检查点只允许 auditor/release 签",
                key.key_id, entry.role
            )));
        }

        let key_id = key.key_id.clone();
        let session_owned = session.to_string();
        self.with_operation(
            "checkpoint",
            json!({"key_id": key_id.clone(), "session": session_owned}),
            at_ms,
            move |repo| {
                // 这里包含本次 op_begin；checkpoint 事件本身不在根里。
                let events = repo.journal().events();
                let height = events.len();
                let head = events.last().map(|event| event.hash);
                let previous = events
                    .iter()
                    .rev()
                    .find(|event| event.kind == "checkpoint")
                    .map(|event| event.hash);
                let root = merkle_root(&events.iter().map(|event| event.hash).collect::<Vec<_>>());
                let statement = checkpoint_statement(height, head, root, previous, at_ms, &key_id);
                let signature = key.sign_hex(&statement)?;
                let before = repo.state_digest()?.to_hex();
                let after = repo.state_digest()?.to_hex();
                let event = repo.journal_mut().append(
                    "checkpoint",
                    json!({
                        "height": height,
                        "head": head.map(|hash| hash.to_hex()),
                        "merkle_root": root.to_hex(),
                        "previous": previous.map(|hash| hash.to_hex()),
                        "key_id": key_id,
                        "algorithm": "ed25519",
                        "signature": signature,
                        "signed_at_ms": at_ms,
                        "session": session,
                        "state_before": before,
                        "state_after": after,
                    }),
                    at_ms,
                )?;
                Ok(CheckpointOutcome {
                    event: event.hash,
                    height,
                    head,
                    merkle_root: root,
                    previous,
                    key_id,
                    signature,
                })
            },
        )
    }
}

/// 检查点签名覆盖的 canonical 字节；审计端按同样格式重建，不信任事件里的字段顺序。
pub fn checkpoint_statement(
    height: usize,
    head: Option<Hash>,
    merkle_root: Hash,
    previous: Option<Hash>,
    signed_at_ms: u64,
    key_id: &str,
) -> Vec<u8> {
    format!(
        "trit-checkpoint-v1\n{height}\n{}\n{}\n{}\n{signed_at_ms}\n{key_id}\n",
        head.map(|hash| hash.to_hex())
            .unwrap_or_else(|| "-".to_string()),
        merkle_root.to_hex(),
        previous
            .map(|hash| hash.to_hex())
            .unwrap_or_else(|| "-".to_string()),
    )
    .into_bytes()
}

/// 事件哈希的 Merkle 根；奇数层复制最后一个，空前缀用固定域分隔哈希。
pub fn merkle_root(leaves: &[Hash]) -> Hash {
    if leaves.is_empty() {
        return Hash::of(b"trit-checkpoint-empty-v1");
    }
    let mut level: Vec<Hash> = leaves.iter().copied().map(leaf_hash).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(node_hash(left, right));
        }
        level = next;
    }
    level[0]
}

/// 某个事件在检查点前缀里的 inclusion proof（兄弟哈希路径）。
pub fn merkle_proof(leaves: &[Hash], index: usize) -> Option<Vec<Hash>> {
    if index >= leaves.len() {
        return None;
    }
    let mut level: Vec<Hash> = leaves.iter().copied().map(leaf_hash).collect();
    let mut current = index;
    let mut proof = Vec::new();
    while level.len() > 1 {
        let sibling_index = current ^ 1;
        let sibling = level.get(sibling_index).copied().unwrap_or(level[current]);
        proof.push(sibling);
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pair in level.chunks(2) {
            let left = pair[0];
            let right = pair.get(1).copied().unwrap_or(left);
            next.push(node_hash(left, right));
        }
        level = next;
        current /= 2;
    }
    Some(proof)
}

/// 用 inclusion proof 复算某个事件是否落在 root 下。
pub fn verify_merkle_proof(
    event_hash: Hash,
    index: usize,
    proof: &[Hash],
    root: Hash,
    leaf_count: usize,
) -> bool {
    if leaf_count == 0 || index >= leaf_count || proof.len() != tree_levels(leaf_count) {
        return false;
    }
    let mut current = leaf_hash(event_hash);
    let mut position = index;
    for (level, sibling) in proof.iter().enumerate() {
        if position >= leaf_count.div_ceil(1usize << level) {
            return false;
        }
        current = if position.is_multiple_of(2) {
            node_hash(current, *sibling)
        } else {
            node_hash(*sibling, current)
        };
        position /= 2;
    }
    current == root
}

fn tree_levels(size: usize) -> usize {
    if size <= 1 {
        0
    } else {
        (usize::BITS - (size - 1).leading_zeros()) as usize
    }
}

fn leaf_hash(hash: Hash) -> Hash {
    Hash::of(format!("trit-checkpoint-leaf-v1:{}", hash.to_hex()).as_bytes())
}

fn node_hash(left: Hash, right: Hash) -> Hash {
    let mut bytes = Vec::with_capacity(65);
    bytes.push(1u8);
    bytes.extend_from_slice(left.as_bytes());
    bytes.extend_from_slice(right.as_bytes());
    Hash::of(&bytes)
}

/// 校验 key_id 与公钥指纹一致；checkpoint 命令/审计共用。
pub fn key_matches_public(key_id: &str, public_hex: &str) -> Result<(), RepoError> {
    let public = public_key_bytes(public_hex)?;
    if public_key_id(&public) != key_id {
        return Err(RepoError::BadHead("key_id 与公钥指纹不一致".to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::TrustEntry;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trit-vcs-checkpoint-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Repo::init(&dir).unwrap();
        dir
    }

    fn setup(name: &str) -> (std::path::PathBuf, Repo, KeyFile, std::path::PathBuf) {
        let root = temp(name);
        let mut repo = Repo::open(&root).unwrap();
        let key = KeyFile::generate().unwrap();
        let key_path = root.join("auditor.key");
        key.save_new(&key_path).unwrap();
        repo.add_key(
            TrustEntry {
                key_id: key.key_id.clone(),
                principal: "qoder:auditor".to_string(),
                role: "auditor".to_string(),
                added_at_ms: 1_001,
                public_key: Some(key.public.clone()),
                rotated_from: None,
                revoked_at_ms: None,
                revoke_reason: None,
            },
            "qoder:auditor",
            1_001,
        )
        .unwrap();
        (root, repo, key, key_path)
    }

    fn append_fake(
        repo: &mut Repo,
        key: &KeyFile,
        signature: String,
        root: Hash,
        previous_override: Option<Hash>,
        at_ms: u64,
    ) {
        let events = repo.journal().events();
        let height = events.len();
        let head = events.last().map(|event| event.hash);
        let previous = previous_override.or_else(|| {
            events
                .iter()
                .rev()
                .find(|event| event.kind == "checkpoint")
                .map(|event| event.hash)
        });
        let before = repo.state_digest().unwrap().to_hex();
        let event = repo
            .journal_mut()
            .append(
                "checkpoint",
                json!({
                    "height": height,
                    "head": head.map(|hash| hash.to_hex()),
                    "merkle_root": root.to_hex(),
                    "previous": previous.map(|hash| hash.to_hex()),
                    "key_id": key.key_id,
                    "algorithm": "ed25519",
                    "signature": signature,
                    "signed_at_ms": at_ms,
                    "session": "qoder:auditor",
                    "state_before": before,
                    "state_after": before,
                }),
                at_ms,
            )
            .unwrap();
        assert_eq!(event.seq as usize, height);
    }

    #[test]
    fn checkpoints_chain_and_audit_verifies_prefix() {
        let (_root, mut repo, _key, key_path) = setup("chain");
        let first = repo.checkpoint(&key_path, "qoder:auditor", 1_002).unwrap();
        let first_report = crate::audit::status(&repo).unwrap();
        assert!(
            first_report.ok,
            "首个检查点后审计应绿：{:?}",
            first_report.issues
        );

        let second = repo.checkpoint(&key_path, "qoder:auditor", 1_003).unwrap();
        assert_eq!(second.previous, Some(first.event));
        assert!(second.height > first.height);
        let report = crate::audit::status(&repo).unwrap();
        assert!(report.ok, "第二个检查点应接上前一条：{:?}", report.issues);
    }

    #[test]
    fn checkpoint_bad_signature_is_red() {
        let (_root, mut repo, key, key_path) = setup("bad-signature");
        repo.checkpoint(&key_path, "qoder:auditor", 1_002).unwrap();
        let events = repo.journal().events();
        let root = merkle_root(&events.iter().map(|event| event.hash).collect::<Vec<_>>());
        append_fake(&mut repo, &key, "00".repeat(64), root, None, 1_004);
        let report = crate::audit::status(&repo).unwrap();
        assert!(!report.ok, "坏签名 checkpoint 必须判红");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "checkpoint_signature_invalid"),
            "应报 checkpoint_signature_invalid：{:?}",
            report.issues
        );
    }

    #[test]
    fn checkpoint_wrong_root_is_red_even_if_signature_is_valid() {
        let (_root, mut repo, key, key_path) = setup("wrong-root");
        repo.checkpoint(&key_path, "qoder:auditor", 1_002).unwrap();
        let events = repo.journal().events();
        let height = events.len();
        let head = events.last().map(|event| event.hash);
        let previous = events
            .iter()
            .rev()
            .find(|event| event.kind == "checkpoint")
            .map(|event| event.hash);
        let expected_root = merkle_root(&events.iter().map(|event| event.hash).collect::<Vec<_>>());
        let statement =
            checkpoint_statement(height, head, expected_root, previous, 1_004, &key.key_id);
        let signature = key.sign_hex(&statement).unwrap();
        append_fake(
            &mut repo,
            &key,
            signature,
            Hash::of(b"wrong-root"),
            None,
            1_004,
        );
        let report = crate::audit::status(&repo).unwrap();
        assert!(!report.ok, "置换 Merkle 根必须判红");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "checkpoint_merkle_mismatch"),
            "应报 checkpoint_merkle_mismatch：{:?}",
            report.issues
        );
    }

    #[test]
    fn checkpoint_wrong_previous_is_red_even_if_signature_is_valid() {
        let (_root, mut repo, key, key_path) = setup("wrong-previous");
        repo.checkpoint(&key_path, "qoder:auditor", 1_002).unwrap();
        let events = repo.journal().events();
        let height = events.len();
        let head = events.last().map(|event| event.hash);
        let previous = events
            .iter()
            .rev()
            .find(|event| event.kind == "checkpoint")
            .map(|event| event.hash);
        let expected_root = merkle_root(&events.iter().map(|event| event.hash).collect::<Vec<_>>());
        let statement =
            checkpoint_statement(height, head, expected_root, previous, 1_004, &key.key_id);
        let signature = key.sign_hex(&statement).unwrap();
        append_fake(
            &mut repo,
            &key,
            signature,
            expected_root,
            Some(Hash::of(b"wrong-previous")),
            1_004,
        );
        let report = crate::audit::status(&repo).unwrap();
        assert!(!report.ok, "置换 previous 必须判红");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "checkpoint_chain_mismatch"),
            "应报 checkpoint_chain_mismatch：{:?}",
            report.issues
        );
    }

    #[test]
    fn checkpoint_without_operation_is_red() {
        let (_root, mut repo, key, key_path) = setup("no-op");
        repo.checkpoint(&key_path, "qoder:auditor", 1_002).unwrap();
        let events = repo.journal().events();
        let height = events.len();
        let head = events.last().map(|event| event.hash);
        let previous = events
            .iter()
            .rev()
            .find(|event| event.kind == "checkpoint")
            .map(|event| event.hash);
        let root = merkle_root(&events.iter().map(|event| event.hash).collect::<Vec<_>>());
        let statement = checkpoint_statement(height, head, root, previous, 1_004, &key.key_id);
        let signature = key.sign_hex(&statement).unwrap();
        append_fake(&mut repo, &key, signature, root, None, 1_004);
        let report = crate::audit::status(&repo).unwrap();
        assert!(!report.ok, "没有 op_begin/op_result 的检查点必须判红");
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "checkpoint_bad"),
            "应报 checkpoint_bad：{:?}",
            report.issues
        );
    }

    #[test]
    fn merkle_inclusion_proofs_verify_and_reject_tampering() {
        let leaves = [Hash::of(b"a"), Hash::of(b"b"), Hash::of(b"c")];
        let root = merkle_root(&leaves);
        for (index, leaf) in leaves.iter().enumerate() {
            let proof = merkle_proof(&leaves, index).unwrap();
            assert!(
                verify_merkle_proof(*leaf, index, &proof, root, leaves.len()),
                "第 {index} 个叶子应能证明"
            );
            if let Some(sibling) = proof.first() {
                let mut bad = proof.clone();
                bad[0] = Hash::of(sibling.as_bytes());
                assert!(!verify_merkle_proof(*leaf, index, &bad, root, leaves.len()));
            }
            if index + 1 < leaves.len() {
                assert!(!verify_merkle_proof(
                    *leaf,
                    index + 1,
                    &proof,
                    root,
                    leaves.len()
                ));
            }
        }
        let proof = merkle_proof(&leaves, 2).unwrap();
        assert!(!verify_merkle_proof(
            leaves[2],
            3,
            &proof,
            root,
            leaves.len()
        ));
        assert!(!verify_merkle_proof(leaves[2], 2, &proof, root, 2));
        assert!(!verify_merkle_proof(
            leaves[2],
            2,
            &proof[..1],
            root,
            leaves.len()
        ));
        assert!(merkle_proof(&leaves, 3).is_none());
    }

    #[test]
    fn merkle_root_is_order_sensitive_and_handles_odd_leaves() {
        let a = Hash::of(b"a");
        let b = Hash::of(b"b");
        let c = Hash::of(b"c");
        let d = Hash::of(b"d");
        assert_ne!(merkle_root(&[a, b]), merkle_root(&[b, a]));
        assert_eq!(merkle_root(&[a]), merkle_root(&[a]));
        assert_ne!(merkle_root(&[a]), merkle_root(&[a, b]));
        assert_ne!(merkle_root(&[a, b, c]), merkle_root(&[a, b, c, d]));
    }
}
