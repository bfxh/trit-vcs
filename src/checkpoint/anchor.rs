//! 仓外文件锚：把已签检查点复制到仓库外，并复核当前日志仍是它的扩展。

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::consistency::{consistency_proof, verify_consistency};
use super::{checkpoint_statement, key_matches_public, merkle_root};
use crate::hash::Hash;
use crate::journal::{Event, event_hash};
use crate::repo::{Repo, RepoError};
use crate::signing::verify_signature;

pub const SCHEMA: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditAnchor {
    pub schema: u32,
    pub event: Event,
}

#[derive(Clone, Debug, Serialize)]
pub struct AnchorOutcome {
    pub ok: bool,
    pub checkpoint: u64,
    pub height: usize,
    pub head: Option<String>,
    pub merkle_root: String,
    pub previous: Option<String>,
    pub key_id: String,
    pub signed_at_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum AnchorError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("锚文件不是合法 JSON：{0}")]
    Json(#[from] serde_json::Error),
    #[error("仓库: {0}")]
    Repo(#[from] RepoError),
    #[error("{kind}: {detail}")]
    Invalid { kind: &'static str, detail: String },
}

impl AnchorError {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Io(_) | Self::Json(_) => "anchor_bad",
            Self::Repo(_) => "anchor_untrusted",
            Self::Invalid { kind, .. } => kind,
        }
    }
}

#[derive(Clone, Debug)]
struct CheckpointData {
    height: usize,
    head: Option<Hash>,
    root: Hash,
    previous: Option<Hash>,
    key_id: String,
    signature: String,
    signed_at_ms: u64,
}

pub fn from_repo(repo: &Repo, checkpoint_seq: usize) -> Result<AuditAnchor, AnchorError> {
    let event = repo
        .journal()
        .events()
        .get(checkpoint_seq)
        .ok_or_else(|| AnchorError::invalid("anchor_missing", "检查点事件不存在"))?;
    if event.kind != "checkpoint" {
        return Err(AnchorError::invalid(
            "anchor_bad",
            format!("事件 #{checkpoint_seq} 不是 checkpoint"),
        ));
    }
    let data = parse_checkpoint(event)?;
    if data.height != checkpoint_seq {
        return Err(AnchorError::invalid(
            "anchor_bad",
            "检查点 height 必须等于自己的事件序号",
        ));
    }
    Ok(AuditAnchor {
        schema: SCHEMA,
        event: event.clone(),
    })
}

pub fn verify(repo: &Repo, anchor: &AuditAnchor) -> Result<AnchorOutcome, AnchorError> {
    if anchor.schema != SCHEMA {
        return Err(AnchorError::invalid(
            "anchor_bad",
            format!("schema 应为 {SCHEMA}，实际是 {}", anchor.schema),
        ));
    }
    let event = &anchor.event;
    if event.kind != "checkpoint" {
        return Err(AnchorError::invalid(
            "anchor_bad",
            "锚里的事件不是 checkpoint",
        ));
    }
    let expected_hash = event_hash(
        event.seq,
        event.at_ms,
        &event.kind,
        &event.payload,
        event.prev.as_ref(),
    );
    if expected_hash != event.hash {
        return Err(AnchorError::invalid(
            "anchor_bad",
            "锚里的事件哈希与内容不符",
        ));
    }
    let data = parse_checkpoint(event)?;
    if data.height != event.seq as usize {
        return Err(AnchorError::invalid(
            "anchor_bad",
            "检查点 height 必须等于自己的事件序号",
        ));
    }
    let statement = checkpoint_statement(
        data.height,
        data.head,
        data.root,
        data.previous,
        data.signed_at_ms,
        &data.key_id,
    );
    let store = repo.keys()?;
    let entry = store.keys.get(&data.key_id).ok_or_else(|| {
        AnchorError::invalid(
            "anchor_untrusted",
            format!("签者 {} 不在信任表", data.key_id),
        )
    })?;
    let public = entry
        .public_key
        .as_deref()
        .ok_or_else(|| AnchorError::invalid("anchor_untrusted", "签者在信任表里没有公钥"))?;
    key_matches_public(&data.key_id, public)
        .map_err(|err| AnchorError::invalid("anchor_untrusted", err.to_string()))?;
    if !matches!(entry.role.as_str(), "auditor" | "release") {
        return Err(AnchorError::invalid(
            "anchor_untrusted",
            format!("签者角色 {} 不是 auditor/release", entry.role),
        ));
    }
    if entry
        .revoked_at_ms
        .is_some_and(|revoked_at| data.signed_at_ms > revoked_at)
    {
        return Err(AnchorError::invalid(
            "anchor_revoked",
            format!("签者 {} 在签名时已吊销", data.key_id),
        ));
    }
    verify_signature(public, &data.signature, &statement).map_err(|err| {
        AnchorError::invalid(
            "anchor_signature_invalid",
            format!("检查点签名验不过：{err}"),
        )
    })?;
    Ok(outcome(event.seq, &data))
}

pub fn verify_against_repo(
    repo: &Repo,
    anchor: &AuditAnchor,
) -> Result<AnchorOutcome, AnchorError> {
    let outcome = verify(repo, anchor)?;
    let events = repo.journal().events();
    let anchored = events.get(outcome.height).ok_or_else(|| {
        AnchorError::invalid(
            "anchor_ahead",
            format!(
                "锚指向 {} 条事件，当前日志只有 {} 条",
                outcome.height + 1,
                events.len()
            ),
        )
    })?;
    if anchored.hash != anchor.event.hash {
        return Err(AnchorError::invalid(
            "anchor_mismatch",
            format!(
                "事件 #{} 不是锚住的检查点：锚是 {}，当前是 {}",
                outcome.height,
                anchor.event.hash.to_hex(),
                anchored.hash.to_hex()
            ),
        ));
    }
    let prefix = &events[..outcome.height];
    let expected_head = prefix.last().map(|event| event.hash);
    let expected_previous = prefix
        .iter()
        .rev()
        .find(|event| event.kind == "checkpoint")
        .map(|event| event.hash);
    let expected_root = merkle_root(&prefix.iter().map(|event| event.hash).collect::<Vec<_>>());
    if outcome.head != expected_head.map(|hash| hash.to_hex())
        || outcome.previous != expected_previous.map(|hash| hash.to_hex())
        || outcome.merkle_root != expected_root.to_hex()
    {
        return Err(AnchorError::invalid(
            "anchor_mismatch",
            "锚住的检查点与当前事件前缀的 head/root/previous 不符",
        ));
    }

    let Some(latest) = events
        .iter()
        .skip(outcome.height + 1)
        .rev()
        .find(|event| event.kind == "checkpoint")
    else {
        return Ok(outcome);
    };
    let latest_data = parse_checkpoint(latest)?;
    if latest_data.height != latest.seq as usize || latest_data.height <= outcome.height {
        return Err(AnchorError::invalid(
            "anchor_consistency_failed",
            "较新检查点的 height 与事件序号不匹配",
        ));
    }
    let leaves = events[..latest_data.height]
        .iter()
        .map(|event| event.hash)
        .collect::<Vec<_>>();
    let proof = consistency_proof(&leaves, outcome.height)
        .map_err(|err| AnchorError::invalid("anchor_consistency_failed", err.to_string()))?;
    let valid = verify_consistency(&proof)
        .map_err(|err| AnchorError::invalid("anchor_consistency_failed", err.to_string()))?;
    if !valid
        || proof.old_root.to_hex() != outcome.merkle_root
        || proof.new_root != latest_data.root
    {
        return Err(AnchorError::invalid(
            "anchor_consistency_failed",
            "旧锚与较新检查点之间不能构成一致前缀",
        ));
    }
    Ok(outcome)
}

pub fn load(path: &Path) -> Result<AuditAnchor, AnchorError> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(AnchorError::from)
}

fn parse_checkpoint(event: &Event) -> Result<CheckpointData, AnchorError> {
    let payload = &event.payload;
    let height = payload
        .get("height")
        .and_then(Value::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or_else(|| AnchorError::invalid("anchor_bad", "检查点缺合法 height"))?;
    let root = parse_hash(payload.get("merkle_root"))
        .ok_or_else(|| AnchorError::invalid("anchor_bad", "检查点缺合法 merkle_root"))?;
    let key_id = payload
        .get("key_id")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AnchorError::invalid("anchor_bad", "检查点缺 key_id"))?
        .to_string();
    let signature = payload
        .get("signature")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| AnchorError::invalid("anchor_bad", "检查点缺 signature"))?
        .to_string();
    let signed_at_ms = payload
        .get("signed_at_ms")
        .and_then(Value::as_u64)
        .ok_or_else(|| AnchorError::invalid("anchor_bad", "检查点缺 signed_at_ms"))?;
    if payload.get("algorithm").and_then(Value::as_str) != Some("ed25519") {
        return Err(AnchorError::invalid(
            "anchor_bad",
            "检查点 algorithm 不是 ed25519",
        ));
    }
    let before = parse_hash(payload.get("state_before"));
    let after = parse_hash(payload.get("state_after"));
    if before.is_none() || before != after {
        return Err(AnchorError::invalid(
            "anchor_bad",
            "检查点缺 state_before/state_after 或状态摘要不一致",
        ));
    }
    Ok(CheckpointData {
        height,
        head: parse_hash(payload.get("head")),
        root,
        previous: parse_hash(payload.get("previous")),
        key_id,
        signature,
        signed_at_ms,
    })
}

fn parse_hash(value: Option<&Value>) -> Option<Hash> {
    value.and_then(Value::as_str).and_then(Hash::from_hex)
}

fn outcome(seq: u64, data: &CheckpointData) -> AnchorOutcome {
    AnchorOutcome {
        ok: true,
        checkpoint: seq,
        height: data.height,
        head: data.head.map(|hash| hash.to_hex()),
        merkle_root: data.root.to_hex(),
        previous: data.previous.map(|hash| hash.to_hex()),
        key_id: data.key_id.clone(),
        signed_at_ms: data.signed_at_ms,
    }
}

impl AnchorError {
    fn invalid(kind: &'static str, detail: impl Into<String>) -> Self {
        Self::Invalid {
            kind,
            detail: detail.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::TrustEntry;
    use crate::signing::KeyFile;
    use serde_json::json;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trit-vcs-anchor-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn trust_entry(key: &KeyFile) -> TrustEntry {
        TrustEntry {
            key_id: key.key_id.clone(),
            principal: "qoder:auditor".to_string(),
            role: "auditor".to_string(),
            added_at_ms: 1_001,
            public_key: Some(key.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        }
    }

    fn setup(name: &str) -> (std::path::PathBuf, Repo, KeyFile, std::path::PathBuf) {
        let root = temp(name);
        Repo::init(&root).unwrap();
        let key = KeyFile::generate().unwrap();
        let key_path = root.join("auditor.key");
        key.save_new(&key_path).unwrap();
        let mut repo = Repo::open(&root).unwrap();
        repo.add_key(trust_entry(&key), "qoder:auditor", 1_001)
            .unwrap();
        (root, repo, key, key_path)
    }

    fn anchor(repo: &mut Repo, key_path: &Path) -> AuditAnchor {
        let outcome = repo.checkpoint(key_path, "qoder:auditor", 1_002).unwrap();
        from_repo(repo, outcome.height).unwrap()
    }

    fn rewrite_event(root: &Path, replacement: Event) {
        let journal = root.join(".tritvcs/journal.jsonl");
        let mut events: Vec<Event> = std::fs::read_to_string(&journal)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let index = replacement.seq as usize;
        events[index] = replacement;
        for next in index + 1..events.len() {
            let previous = events[next - 1].hash;
            let event = &mut events[next];
            event.prev = Some(previous);
            event.hash = event_hash(
                event.seq,
                event.at_ms,
                &event.kind,
                &event.payload,
                event.prev.as_ref(),
            );
        }
        let rewritten = events
            .iter()
            .map(|event| serde_json::to_string(event).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(journal, format!("{rewritten}\n")).unwrap();
    }

    fn edit_trust(repo: &Repo, key: &KeyFile, edit: impl FnOnce(&mut TrustEntry)) {
        let mut store = repo.keys().unwrap();
        edit(store.keys.get_mut(&key.key_id).unwrap());
        store.save(repo.root()).unwrap();
    }

    #[test]
    fn anchor_checks_event_hash_and_signature_separately() {
        let (_root, mut repo, _key, key_path) = setup("signature");
        let value = anchor(&mut repo, &key_path);
        assert!(verify(&repo, &value).unwrap().ok);

        let mut bad_signature = value.clone();
        bad_signature.event.payload["signature"] = json!("00".repeat(64));
        bad_signature.event.hash = event_hash(
            bad_signature.event.seq,
            bad_signature.event.at_ms,
            &bad_signature.event.kind,
            &bad_signature.event.payload,
            bad_signature.event.prev.as_ref(),
        );
        let err = verify(&repo, &bad_signature).unwrap_err();
        assert_eq!(err.kind(), "anchor_signature_invalid");

        let mut bad_hash = value;
        bad_hash.event.payload["merkle_root"] = json!("00".repeat(32));
        let err = verify(&repo, &bad_hash).unwrap_err();
        assert_eq!(err.kind(), "anchor_bad");
    }

    #[test]
    fn anchor_rejects_untrusted_signer() {
        let (root, mut repo, key, key_path) = setup("untrusted");
        let value = anchor(&mut repo, &key_path);
        let foreign = KeyFile::generate().unwrap();
        let mut store = repo.keys().unwrap();
        store.keys.remove(&key.key_id);
        store
            .keys
            .insert(foreign.key_id.clone(), trust_entry(&foreign));
        store.save(&root).unwrap();

        let err = verify(&repo, &value).unwrap_err();
        assert_eq!(err.kind(), "anchor_untrusted");
        assert!(err.to_string().contains("不在信任表"), "{err}");
    }

    #[test]
    fn anchor_rejects_signer_without_public_key() {
        let (_root, mut repo, key, key_path) = setup("no-public-key");
        let value = anchor(&mut repo, &key_path);
        edit_trust(&repo, &key, |entry| entry.public_key = None);

        let err = verify(&repo, &value).unwrap_err();
        assert_eq!(err.kind(), "anchor_untrusted");
        assert!(err.to_string().contains("没有公钥"), "{err}");
    }

    #[test]
    fn anchor_rejects_public_key_fingerprint_mismatch() {
        let (_root, mut repo, key, key_path) = setup("fingerprint");
        let value = anchor(&mut repo, &key_path);
        let foreign = KeyFile::generate().unwrap();
        edit_trust(&repo, &key, |entry| {
            entry.public_key = Some(foreign.public.clone());
        });

        let err = verify(&repo, &value).unwrap_err();
        assert_eq!(err.kind(), "anchor_untrusted");
        assert!(err.to_string().contains("指纹"), "{err}");
    }

    #[test]
    fn anchor_rejects_non_auditor_role() {
        let (_root, mut repo, key, key_path) = setup("wrong-role");
        let value = anchor(&mut repo, &key_path);
        edit_trust(&repo, &key, |entry| entry.role = "author".to_string());

        let err = verify(&repo, &value).unwrap_err();
        assert_eq!(err.kind(), "anchor_untrusted");
        assert!(err.to_string().contains("不是 auditor/release"), "{err}");
    }

    #[test]
    fn anchor_checks_revocation_at_signature_time() {
        let (_root, mut repo, key, key_path) = setup("revoked");
        let value = anchor(&mut repo, &key_path);
        let signed_at_ms = value.event.payload["signed_at_ms"].as_u64().unwrap();
        edit_trust(&repo, &key, |entry| {
            entry.revoked_at_ms = Some(signed_at_ms - 1);
            entry.revoke_reason = Some("compromised".to_string());
        });

        let err = verify(&repo, &value).unwrap_err();
        assert_eq!(err.kind(), "anchor_revoked");
        assert!(err.to_string().contains("在签名时已吊销"), "{err}");

        edit_trust(&repo, &key, |entry| {
            entry.revoked_at_ms = Some(signed_at_ms)
        });
        assert!(verify(&repo, &value).is_ok(), "同毫秒吊销不追溯旧签名");
    }

    #[test]
    fn anchor_rejects_validly_signed_wrong_prefix_summary() {
        let (root, mut repo, key, key_path) = setup("wrong-prefix");
        let value = anchor(&mut repo, &key_path);
        let journal = root.join(".tritvcs/journal.jsonl");
        let original = std::fs::read_to_string(&journal).unwrap();
        let resign = |event: &mut Event| {
            let data = parse_checkpoint(event).unwrap();
            let statement = checkpoint_statement(
                data.height,
                data.head,
                data.root,
                data.previous,
                data.signed_at_ms,
                &data.key_id,
            );
            event.payload["signature"] = json!(key.sign_hex(&statement).unwrap());
            event.hash = event_hash(
                event.seq,
                event.at_ms,
                &event.kind,
                &event.payload,
                event.prev.as_ref(),
            );
        };
        for (field, replacement) in [
            ("merkle_root", json!(Hash::of(b"wrong-root").to_hex())),
            ("head", json!(Hash::of(b"wrong-head").to_hex())),
            ("previous", json!(Hash::of(b"wrong-previous").to_hex())),
        ] {
            std::fs::write(&journal, &original).unwrap();
            let mut bad = value.clone();
            bad.event.payload[field] = replacement;
            resign(&mut bad.event);
            assert!(verify(&repo, &bad).is_ok(), "重签后内部签名应有效");
            rewrite_event(&root, bad.event.clone());
            let reopened = Repo::open(&root).unwrap();
            assert!(verify(&reopened, &bad).is_ok(), "重写后链与签名应有效");
            let err = verify_against_repo(&reopened, &bad).unwrap_err();
            assert_eq!(
                err.kind(),
                "anchor_mismatch",
                "字段 {field} 应被前缀核对拒绝"
            );
        }
    }

    #[test]
    fn anchor_rejects_same_summary_checkpoint_with_different_event_hash() {
        let (_root_a, mut repo_a, key, key_path_a) = setup("same-summary-a");
        let root_b = temp("same-summary-b");
        Repo::init(&root_b).unwrap();
        let key_path_b = root_b.join("auditor.key");
        key.save_new(&key_path_b).unwrap();
        let mut repo_b = Repo::open(&root_b).unwrap();
        repo_b
            .add_key(trust_entry(&key), "qoder:auditor", 1_001)
            .unwrap();
        let first = repo_a
            .checkpoint(&key_path_a, "qoder:auditor", 1_002)
            .unwrap();
        let second = repo_b
            .checkpoint(&key_path_b, "qoder:auditor", 1_002)
            .unwrap();
        assert_eq!(first.height, second.height);
        assert_eq!(first.head, second.head);
        assert_eq!(first.merkle_root, second.merkle_root);
        assert_eq!(first.previous, second.previous);
        assert_eq!(first.event, second.event);

        let mut different = from_repo(&repo_b, second.height).unwrap();
        let data = parse_checkpoint(&different.event).unwrap();
        different.event.payload["signed_at_ms"] = json!(1_003);
        let statement = checkpoint_statement(
            data.height,
            data.head,
            data.root,
            data.previous,
            1_003,
            &data.key_id,
        );
        different.event.payload["signature"] = json!(key.sign_hex(&statement).unwrap());
        different.event.hash = event_hash(
            different.event.seq,
            different.event.at_ms,
            &different.event.kind,
            &different.event.payload,
            different.event.prev.as_ref(),
        );
        assert_ne!(first.event, different.event.hash);
        rewrite_event(&root_b, different.event.clone());
        let reopened = Repo::open(&root_b).unwrap();
        assert!(verify(&reopened, &different).is_ok());

        let value = from_repo(&repo_a, first.height).unwrap();
        let err = verify_against_repo(&reopened, &value).unwrap_err();
        assert_eq!(err.kind(), "anchor_mismatch");
    }

    #[test]
    fn anchor_rejects_foreign_history_at_the_same_height() {
        let (_root_a, mut repo_a, key, key_path_a) = setup("foreign-a");
        let root_b = temp("foreign-b");
        Repo::init(&root_b).unwrap();
        let key_path_b = root_b.join("auditor.key");
        key.save_new(&key_path_b).unwrap();
        let mut repo_b = Repo::open(&root_b).unwrap();
        repo_b
            .add_key(trust_entry(&key), "qoder:auditor", 1_001)
            .unwrap();
        repo_a
            .journal_mut()
            .append("note", json!({"repo": "a"}), 1_001)
            .unwrap();
        repo_b
            .journal_mut()
            .append("note", json!({"repo": "b"}), 1_001)
            .unwrap();
        let value = anchor(&mut repo_a, &key_path_a);
        repo_b
            .checkpoint(&key_path_b, "qoder:auditor", 1_002)
            .unwrap();
        let err = verify_against_repo(&repo_b, &value).unwrap_err();
        assert_eq!(err.kind(), "anchor_mismatch");
    }

    #[test]
    fn anchor_rejects_forged_newer_checkpoint_root() {
        let (_root, mut repo, key, key_path) = setup("forged-newer");
        let value = anchor(&mut repo, &key_path);
        let events = repo.journal().events();
        let height = events.len();
        let head = events.last().map(|event| event.hash);
        let previous = Some(value.event.hash);
        let root = Hash::of(b"forged-root");
        let statement = checkpoint_statement(height, head, root, previous, 1_003, &key.key_id);
        let signature = key.sign_hex(&statement).unwrap();
        let before = repo.state_digest().unwrap().to_hex();
        repo.journal_mut()
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
                    "signed_at_ms": 1_003,
                    "session": "qoder:auditor",
                    "state_before": before,
                    "state_after": before,
                }),
                1_003,
            )
            .unwrap();
        let err = verify_against_repo(&repo, &value).unwrap_err();
        assert_eq!(err.kind(), "anchor_consistency_failed");
    }
}
