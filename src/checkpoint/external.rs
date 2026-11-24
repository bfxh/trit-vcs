//! 独立公钥锚：外部签者钉住检查点事件与前缀摘要，验锚不读仓内信任表。

use std::path::Path;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::anchor::{self, AnchorError, AnchorOutcome};
use crate::hash::Hash;
use crate::journal::event_hash;
use crate::keys::public_key_id;
use crate::repo::Repo;
use crate::signing::{KeyFile, public_key_bytes, verify_signature};

pub const SCHEMA: &str = "trit-external-anchor-v1";
pub const ALGORITHM: &str = "ed25519";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalAnchor {
    pub schema: String,
    #[serde(with = "hash_hex")]
    pub checkpoint: Hash,
    pub height: usize,
    #[serde(with = "option_hash_hex")]
    pub head: Option<Hash>,
    #[serde(with = "hash_hex")]
    pub merkle_root: Hash,
    #[serde(with = "option_hash_hex")]
    pub previous: Option<Hash>,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
    pub signed_at_ms: u64,
}

impl ExternalAnchor {
    pub fn statement(&self) -> Vec<u8> {
        format!(
            "trit-external-anchor-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.checkpoint.to_hex(),
            self.height,
            self.head
                .map(|hash| hash.to_hex())
                .unwrap_or_else(|| "-".to_string()),
            self.merkle_root.to_hex(),
            self.previous
                .map(|hash| hash.to_hex())
                .unwrap_or_else(|| "-".to_string()),
            self.signed_at_ms,
            self.key_id,
        )
        .into_bytes()
    }

    pub fn verify_with_key(&self, pinned_public: &str) -> Result<(), AnchorError> {
        if self.schema != SCHEMA || self.algorithm != ALGORITHM {
            return Err(AnchorError::invalid(
                "anchor_bad",
                "外部锚 schema 或 algorithm 不受支持",
            ));
        }
        let public = public_key_bytes(pinned_public)?;
        if public_key_id(&public) != self.key_id {
            return Err(AnchorError::invalid(
                "anchor_untrusted",
                "外部锚 key_id 与调用方钉住的公钥指纹不一致",
            ));
        }
        verify_signature(pinned_public, &self.signature, &self.statement()).map_err(|err| {
            AnchorError::invalid(
                "anchor_signature_invalid",
                format!("外部锚签名验不过：{err}"),
            )
        })
    }
}

pub fn from_checkpoint(
    repo: &Repo,
    checkpoint_seq: usize,
    key_path: &Path,
    pinned_public: &str,
    at_ms: u64,
) -> Result<ExternalAnchor, AnchorError> {
    let pinned = public_key_bytes(pinned_public)?;
    let key = KeyFile::load(key_path)?;
    if key.public_bytes()? != pinned {
        return Err(AnchorError::invalid(
            "anchor_untrusted",
            "外部锚私钥与钉住的公钥不是同一把",
        ));
    }
    let local = anchor::from_repo(repo, checkpoint_seq)?;
    let expected_hash = event_hash(
        local.event.seq,
        local.event.at_ms,
        &local.event.kind,
        &local.event.payload,
        local.event.prev.as_ref(),
    );
    if expected_hash != local.event.hash {
        return Err(AnchorError::invalid(
            "anchor_bad",
            "检查点事件哈希与内容不符",
        ));
    }
    let data = anchor::parse_checkpoint(&local.event)?;
    if at_ms < data.signed_at_ms {
        return Err(AnchorError::invalid(
            "anchor_bad",
            "外部锚签名时间早于被锚检查点",
        ));
    }
    anchor::verify_repo_prefix(
        repo,
        local.event.hash,
        data.height,
        data.head,
        data.root,
        data.previous,
    )?;
    let mut value = ExternalAnchor {
        schema: SCHEMA.to_string(),
        checkpoint: local.event.hash,
        height: data.height,
        head: data.head,
        merkle_root: data.root,
        previous: data.previous,
        key_id: key.key_id.clone(),
        algorithm: ALGORITHM.to_string(),
        signature: String::new(),
        signed_at_ms: at_ms,
    };
    value.signature = key.sign_hex(&value.statement())?;
    Ok(value)
}

pub fn verify_against_repo(
    repo: &Repo,
    value: &ExternalAnchor,
    pinned_public: &str,
) -> Result<AnchorOutcome, AnchorError> {
    value.verify_with_key(pinned_public)?;
    let events = repo.journal().events();
    let event = events.get(value.height).ok_or_else(|| {
        AnchorError::invalid(
            "anchor_ahead",
            format!(
                "外部锚指向 {} 条事件，当前日志只有 {} 条",
                value.height.saturating_add(1),
                events.len()
            ),
        )
    })?;
    if event.hash != value.checkpoint {
        return Err(AnchorError::invalid(
            "anchor_mismatch",
            "外部锚钉住的检查点事件与当前日志不符",
        ));
    }
    if event.kind != "checkpoint" {
        return Err(AnchorError::invalid(
            "anchor_bad",
            "外部锚指向的事件不是 checkpoint",
        ));
    }
    let data = anchor::parse_checkpoint(event)?;
    if data.height != value.height
        || data.head != value.head
        || data.root != value.merkle_root
        || data.previous != value.previous
    {
        return Err(AnchorError::invalid(
            "anchor_mismatch",
            "外部锚摘要与检查点事件不一致",
        ));
    }
    anchor::verify_repo_prefix(
        repo,
        value.checkpoint,
        value.height,
        value.head,
        value.merkle_root,
        value.previous,
    )?;
    Ok(AnchorOutcome {
        ok: true,
        checkpoint: event.seq,
        height: value.height,
        head: value.head.map(|hash| hash.to_hex()),
        merkle_root: value.merkle_root.to_hex(),
        previous: value.previous.map(|hash| hash.to_hex()),
        key_id: value.key_id.clone(),
        signed_at_ms: value.signed_at_ms,
    })
}

pub fn load(path: &Path) -> Result<ExternalAnchor, AnchorError> {
    let bytes = std::fs::read(path)?;
    serde_json::from_slice(&bytes).map_err(AnchorError::from)
}

mod hash_hex {
    use super::{Deserialize, Deserializer, Hash, Serializer};

    pub fn serialize<S: Serializer>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hash.to_hex())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Hash, D::Error> {
        let text = String::deserialize(deserializer)?;
        Hash::from_hex(&text).ok_or_else(|| serde::de::Error::custom("哈希必须是 64 位十六进制"))
    }
}

mod option_hash_hex {
    use super::{Deserialize, Deserializer, Hash, Serializer};

    pub fn serialize<S: Serializer>(hash: &Option<Hash>, serializer: S) -> Result<S::Ok, S::Error> {
        match hash {
            Some(hash) => serializer.serialize_str(&hash.to_hex()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<Hash>, D::Error> {
        Option::<String>::deserialize(deserializer).and_then(|value| {
            value
                .map(|text| {
                    Hash::from_hex(&text)
                        .ok_or_else(|| serde::de::Error::custom("哈希必须是 64 位十六进制"))
                })
                .transpose()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{checkpoint_statement, merkle_root};
    use crate::journal::{Event, event_hash};
    use crate::keys::{TrustEntry, TrustStore};
    use serde_json::json;

    fn resign(value: &mut ExternalAnchor, key: &KeyFile) {
        value.signature = key.sign_hex(&value.statement()).unwrap();
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trit-vcs-external-anchor-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
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

    fn setup(
        name: &str,
    ) -> (
        std::path::PathBuf,
        Repo,
        KeyFile,
        std::path::PathBuf,
        KeyFile,
    ) {
        let root = temp(name);
        Repo::init(&root).unwrap();
        let auditor = KeyFile::generate().unwrap();
        let auditor_path = root.join("auditor.key");
        auditor.save_new(&auditor_path).unwrap();
        let mut repo = Repo::open(&root).unwrap();
        repo.add_key(trust_entry(&auditor), "qoder:auditor", 1_001)
            .unwrap();
        let external = KeyFile::generate().unwrap();
        (root, repo, auditor, auditor_path, external)
    }

    fn sign(repo: &mut Repo, auditor: &Path, external: &KeyFile) -> ExternalAnchor {
        let checkpoint = repo_checkpoint(repo, auditor);
        from_checkpoint(
            repo,
            checkpoint.height,
            &external_path(repo, external),
            &external.public,
            2_000,
        )
        .unwrap()
    }

    fn repo_checkpoint(repo: &mut Repo, auditor: &Path) -> crate::checkpoint::CheckpointOutcome {
        repo.checkpoint(auditor, "qoder:auditor", 1_500).unwrap()
    }

    fn external_path(repo: &Repo, external: &KeyFile) -> std::path::PathBuf {
        let path = repo.root().join("external.key");
        if !path.exists() {
            external.save_new(&path).unwrap();
        }
        path
    }

    fn rewrite_event(root: &std::path::Path, replacement: Event) {
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

    #[test]
    fn verification_uses_only_the_pinned_external_key() {
        let (root, mut repo, _auditor, auditor_path, external) = setup("independent");
        let checkpoint = repo_checkpoint(&mut repo, &auditor_path);
        let value = from_checkpoint(
            &repo,
            checkpoint.height,
            &external_path(&repo, &external),
            &external.public,
            2_000,
        )
        .unwrap();
        TrustStore::default().save(&root).unwrap();
        let reopened = Repo::open_for_audit(&root).unwrap();
        let outcome = verify_against_repo(&reopened, &value, &external.public).unwrap();
        assert!(outcome.ok);
        assert_eq!(outcome.height, checkpoint.height);
        assert!(repo.keys().unwrap().keys.is_empty());
    }

    #[test]
    fn wrong_key_and_bad_signature_are_rejected() {
        let (_root, mut repo, _auditor, auditor_path, external) = setup("signature");
        let value = sign(&mut repo, &auditor_path, &external);
        let foreign = KeyFile::generate().unwrap();
        let err = verify_against_repo(&repo, &value, &foreign.public).unwrap_err();
        assert_eq!(err.kind(), "anchor_untrusted");

        let mut bad = value;
        bad.signature = "00".repeat(64);
        let err = verify_against_repo(&repo, &bad, &external.public).unwrap_err();
        assert_eq!(err.kind(), "anchor_signature_invalid");
    }

    #[test]
    fn validly_signed_wrong_summary_and_checkpoint_are_rejected() {
        let (_root, mut repo, _auditor, auditor_path, external) = setup("summary");
        let value = sign(&mut repo, &auditor_path, &external);
        type Mutation = (fn(&mut ExternalAnchor), &'static str, &'static str);
        let mutations: [Mutation; 2] = [
            (
                |bad| bad.merkle_root = Hash::of(b"wrong-root"),
                "anchor_mismatch",
                "外部锚摘要与检查点事件不一致",
            ),
            (
                |bad| bad.checkpoint = Hash::of(b"wrong-checkpoint"),
                "anchor_mismatch",
                "外部锚钉住的检查点事件与当前日志不符",
            ),
        ];
        for (mutate, kind, detail) in mutations {
            let mut bad = value.clone();
            mutate(&mut bad);
            resign(&mut bad, &external);
            let err = verify_against_repo(&repo, &bad, &external.public).unwrap_err();
            assert_eq!(err.kind(), kind);
            assert!(err.to_string().contains(detail), "{err}");
        }
    }

    #[test]
    fn anchor_ahead_of_truncated_repo_is_rejected() {
        let (_root, mut repo, _auditor, auditor_path, external) = setup("truncated");
        let value = sign(&mut repo, &auditor_path, &external);
        let root = temp("empty-target");
        Repo::init(&root).unwrap();
        let empty = Repo::open_for_audit(&root).unwrap();
        let err = verify_against_repo(&empty, &value, &external.public).unwrap_err();
        assert_eq!(err.kind(), "anchor_ahead");

        let mut extreme = value.clone();
        extreme.height = usize::MAX;
        resign(&mut extreme, &external);
        let err = verify_against_repo(&empty, &extreme, &external.public).unwrap_err();
        assert_eq!(err.kind(), "anchor_ahead");
    }

    #[test]
    fn divergent_newer_checkpoint_breaks_consistency() {
        let (root, mut repo, auditor, auditor_path, external) = setup("consistency");
        let first = repo_checkpoint(&mut repo, &auditor_path);
        let value = from_checkpoint(
            &repo,
            first.height,
            &external_path(&repo, &external),
            &external.public,
            2_000,
        )
        .unwrap();
        let second = repo_checkpoint(&mut repo, &auditor_path);
        let mut bad = repo.journal().events()[second.height].clone();
        let data = anchor::parse_checkpoint(&bad).unwrap();
        bad.payload["merkle_root"] = json!(Hash::of(b"wrong-new-root").to_hex());
        let statement = checkpoint_statement(
            data.height,
            data.head,
            Hash::of(b"wrong-new-root"),
            data.previous,
            data.signed_at_ms,
            &data.key_id,
        );
        bad.payload["signature"] = json!(auditor.sign_hex(&statement).unwrap());
        bad.hash = event_hash(
            bad.seq,
            bad.at_ms,
            &bad.kind,
            &bad.payload,
            bad.prev.as_ref(),
        );
        rewrite_event(&root, bad);
        let reopened = Repo::open_for_audit(&root).unwrap();
        let leaves = reopened.journal().events()[..second.height]
            .iter()
            .map(|event| event.hash)
            .collect::<Vec<_>>();
        assert_ne!(merkle_root(&leaves), Hash::of(b"wrong-new-root"));
        let err = verify_against_repo(&reopened, &value, &external.public).unwrap_err();
        assert_eq!(err.kind(), "anchor_consistency_failed");
    }

    #[test]
    fn anchor_file_round_trips_with_hex_hashes() {
        let (_root, mut repo, _auditor, auditor_path, external) = setup("roundtrip");
        let value = sign(&mut repo, &auditor_path, &external);
        let path = temp("anchor.json").join("external.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded, value);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains(&value.checkpoint.to_hex()));
    }
}
