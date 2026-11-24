//! Witness 签名：提交、树、父树、原始见证与签者绑在同一个 Ed25519 声明里。

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::hash::Hash;
use crate::keys::{TrustEntry, public_key_id};
use crate::model::Commit;
use crate::repo::{Repo, RepoError};
use crate::signing::{KeyFile, verify_signature};
use crate::witness::{self, Witness};

pub const SCHEMA: &str = "trit-attestation-v1";
pub const EVENT_KIND: &str = "attestation";
pub const ALGORITHM: &str = "ed25519";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attestation {
    pub schema: String,
    pub commit: Hash,
    pub witness: Hash,
    pub tree: Hash,
    pub base: Option<Hash>,
    pub key_id: String,
    pub algorithm: String,
    pub signature: String,
    pub signed_at_ms: u64,
    pub session: String,
}

impl Attestation {
    fn statement(&self) -> Vec<u8> {
        format!(
            "trit-attestation-v1\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.commit.to_hex(),
            self.witness.to_hex(),
            self.tree.to_hex(),
            self.base
                .map(|base| base.to_hex())
                .unwrap_or_else(|| "-".to_string()),
            self.key_id,
            self.signed_at_ms,
            self.session,
        )
        .into_bytes()
    }

    pub fn verify(
        &self,
        public: &str,
        id: &Hash,
        commit: &Commit,
        base: Option<Hash>,
        witness_bytes: &[u8],
    ) -> Result<Witness, RepoError> {
        if self.schema != SCHEMA || self.algorithm != ALGORITHM {
            return Err(RepoError::AttestationInvalid(
                "schema 或 algorithm 不受支持".to_string(),
            ));
        }
        if self.commit != *id || self.tree != commit.tree || self.base != base {
            return Err(RepoError::AttestationInvalid(
                "attestation 与提交/父树不一致".to_string(),
            ));
        }
        let recorded = commit
            .witness
            .ok_or_else(|| RepoError::Unwitnessed(self.commit.short().to_string()))?;
        if self.witness != recorded || Hash::of(witness_bytes) != recorded {
            return Err(RepoError::AttestationInvalid(
                "attestation witness 摘要与提交不一致".to_string(),
            ));
        }
        verify_signature(public, &self.signature, &self.statement())
            .map_err(|err| RepoError::AttestationInvalid(format!("签名不通过：{err}")))?;
        let parsed = witness::verify(witness_bytes, commit.tree)?;
        parsed.check_base(base)?;
        crate::repo::require_passing(&parsed)?;
        Ok(parsed)
    }
}

#[derive(Clone, Debug)]
pub struct Admission {
    pub event: Hash,
    pub attestation: Hash,
    pub witness: Witness,
}

impl Repo {
    pub fn attest_witness(
        &mut self,
        commit: &Hash,
        witness_bytes: &[u8],
        key_path: &Path,
        session: &str,
        at_ms: u64,
    ) -> Result<Hash, RepoError> {
        if session.trim().is_empty() || session.chars().any(char::is_control) {
            return Err(RepoError::BadHead("session 不能为空".to_string()));
        }
        let _guard = self.lock_state()?;
        let commit_data = self.commit_at(commit)?;
        let parsed = witness::verify(witness_bytes, commit_data.tree)?;
        witness::check_file(
            commit_data
                .witness
                .ok_or_else(|| RepoError::Unwitnessed(commit.short().to_string()))?,
            witness_bytes,
        )?;
        crate::repo::require_passing(&parsed)?;
        let key = KeyFile::load(key_path)?;
        let keys = self.keys()?;
        let entry = keys.keys.get(&key.key_id).ok_or_else(|| {
            RepoError::BadHead(format!("key {} 不在信任表；先 key add", key.key_id))
        })?;
        trusted_key(entry, &key, at_ms)?;
        let base = match commit_data.parents.first() {
            Some(parent) => Some(self.commit_at(parent)?.tree),
            None => None,
        };
        parsed.check_base(base)?;
        if self.journal().events().iter().any(|event| {
            event.kind == EVENT_KIND
                && event.payload.get("commit").and_then(|value| value.as_str())
                    == Some(commit.to_hex().as_str())
        }) {
            return Err(RepoError::BadHead(format!(
                "提交 {} 已有 attestation",
                commit.short()
            )));
        }
        let attestation = Attestation {
            schema: SCHEMA.to_string(),
            commit: *commit,
            witness: Hash::of(witness_bytes),
            tree: commit_data.tree,
            base,
            key_id: key.key_id.clone(),
            algorithm: ALGORITHM.to_string(),
            signature: String::new(),
            signed_at_ms: at_ms,
            session: session.to_string(),
        };
        let signature = key.sign_hex(&attestation.statement())?;
        let attestation = Attestation {
            signature,
            ..attestation
        };
        let bytes = serde_json::to_vec_pretty(&attestation)
            .map_err(|err| RepoError::BadHead(format!("attestation 编码失败：{err}")))?;
        let (digest, _) = self.store.put_chunk(&bytes)?;
        let key_id = attestation.key_id;
        let signature = attestation.signature;
        let witness = attestation.witness;
        let tree = attestation.tree;
        let base = attestation.base;
        self.with_operation(
            "attest",
            json!({"commit": commit.to_hex(), "witness": witness.to_hex(), "key_id": key_id, "session": session}),
            at_ms,
            move |repo| {
                let before = repo.state_digest()?.to_hex();
                let after = repo.state_digest()?.to_hex();
                let operation = repo
                    .journal()
                    .events()
                    .last()
                    .map(|event| event.hash.to_hex())
                    .unwrap_or_default();
                repo.journal_mut().append(
                    EVENT_KIND,
                    json!({
                        "schema": SCHEMA,
                        "attestation": digest.to_hex(),
                        "operation": operation,
                        "commit": commit.to_hex(),
                        "witness": witness.to_hex(),
                        "tree": tree.to_hex(),
                        "base": base.map(|base| base.to_hex()),
                        "key_id": key_id,
                        "algorithm": ALGORITHM,
                        "signature": signature,
                        "signed_at_ms": at_ms,
                        "session": session,
                        "state_before": before,
                        "state_after": after,
                    }),
                    at_ms,
                )?;
                Ok(digest)
            },
        )
    }

    pub fn verify_attestation(
        &self,
        id: &Hash,
        witness_bytes: &[u8],
    ) -> Result<Admission, RepoError> {
        let commit = self.commit_at(id)?;
        let event = self
            .journal()
            .events()
            .iter()
            .rev()
            .find(|event| {
                event.kind == EVENT_KIND
                    && event.payload.get("commit").and_then(|value| value.as_str())
                        == Some(id.to_hex().as_str())
            })
            .ok_or_else(|| RepoError::AttestationRequired(id.short().to_string()))?;
        if event.payload.get("schema").and_then(Value::as_str) != Some(SCHEMA)
            || event.payload.get("algorithm").and_then(Value::as_str) != Some(ALGORITHM)
        {
            return Err(RepoError::AttestationInvalid(
                "attestation 事件 schema 或 algorithm 不受支持".to_string(),
            ));
        }
        if self
            .journal()
            .events()
            .iter()
            .filter(|candidate| {
                candidate.kind == EVENT_KIND
                    && candidate
                        .payload
                        .get("commit")
                        .and_then(|value| value.as_str())
                        == Some(id.to_hex().as_str())
            })
            .count()
            > 1
        {
            return Err(RepoError::AttestationInvalid(
                "同一提交存在重复 attestation".to_string(),
            ));
        }
        let digest = Hash::from_hex(
            event
                .payload
                .get("attestation")
                .and_then(|value| value.as_str())
                .unwrap_or_default(),
        )
        .ok_or_else(|| RepoError::AttestationInvalid("attestation 事件缺对象摘要".to_string()))?;
        let bytes = self.store.get_chunk(&digest)?;
        let attestation: Attestation = serde_json::from_slice(&bytes)
            .map_err(|err| RepoError::AttestationInvalid(format!("attestation 解不开：{err}")))?;
        if Hash::of(&bytes) != digest {
            return Err(RepoError::AttestationInvalid(
                "attestation 对象摘要不符".to_string(),
            ));
        }
        let operation = parse_operation(event)?;
        let begin = self
            .journal()
            .events()
            .iter()
            .find(|candidate| candidate.hash == operation && candidate.seq < event.seq)
            .ok_or_else(|| {
                RepoError::AttestationInvalid("attestation operation 不存在".to_string())
            })?;
        if begin.kind != "op_begin"
            || begin.payload.get("op").and_then(|value| value.as_str()) != Some("attest")
            || begin
                .payload
                .get("args")
                .and_then(|args| args.get("commit"))
                .and_then(Value::as_str)
                != Some(id.to_hex().as_str())
            || begin
                .payload
                .get("args")
                .and_then(|args| args.get("witness"))
                .and_then(Value::as_str)
                != event.payload.get("witness").and_then(Value::as_str)
            || begin
                .payload
                .get("args")
                .and_then(|args| args.get("key_id"))
                .and_then(Value::as_str)
                != event.payload.get("key_id").and_then(Value::as_str)
            || begin
                .payload
                .get("args")
                .and_then(|args| args.get("session"))
                .and_then(Value::as_str)
                != event.payload.get("session").and_then(Value::as_str)
        {
            return Err(RepoError::AttestationInvalid(
                "attestation operation 与提交不一致".to_string(),
            ));
        }
        let result = self
            .journal()
            .events()
            .iter()
            .skip((event.seq + 1) as usize)
            .find(|candidate| {
                candidate.kind == "op_result"
                    && candidate
                        .payload
                        .get("begin_hash")
                        .and_then(|value| value.as_str())
                        == Some(operation.to_hex().as_str())
            })
            .ok_or_else(|| RepoError::AttestationInvalid("attestation 操作没有收口".to_string()))?;
        if result.payload.get("op").and_then(|value| value.as_str()) != Some("attest")
            || result
                .payload
                .get("status")
                .and_then(|value| value.as_str())
                != Some("ok")
        {
            return Err(RepoError::AttestationInvalid(
                "attestation 操作未成功收口".to_string(),
            ));
        }
        crate::audit::attestation_event::operation_states_match(event, begin, result)
            .map_err(RepoError::AttestationInvalid)?;
        let payload_matches = event.payload.get("witness").and_then(Value::as_str)
            == Some(attestation.witness.to_hex().as_str())
            && parse_hash(event.payload.get("tree")) == Some(attestation.tree)
            && parse_hash(event.payload.get("base")) == attestation.base
            && event.payload.get("key_id").and_then(Value::as_str)
                == Some(attestation.key_id.as_str())
            && event.payload.get("signature").and_then(Value::as_str)
                == Some(attestation.signature.as_str())
            && event.payload.get("signed_at_ms").and_then(Value::as_u64)
                == Some(attestation.signed_at_ms)
            && event.payload.get("session").and_then(Value::as_str)
                == Some(attestation.session.as_str());
        if !payload_matches {
            return Err(RepoError::AttestationInvalid(
                "attestation 事件与对象不一致".to_string(),
            ));
        }
        let base = match commit.parents.first() {
            Some(parent) => Some(self.commit_at(parent)?.tree),
            None => None,
        };
        let keys = self.keys()?;
        let entry = keys
            .keys
            .get(&attestation.key_id)
            .ok_or_else(|| RepoError::AttestationUntrusted(attestation.key_id.clone()))?;
        let public = entry
            .public_key
            .as_deref()
            .ok_or_else(|| RepoError::AttestationUntrusted(attestation.key_id.clone()))?;
        verify_signer(entry, public, &attestation)?;
        let witness = attestation.verify(public, id, &commit, base, witness_bytes)?;
        Ok(Admission {
            event: event.hash,
            attestation: digest,
            witness,
        })
    }

    pub fn admit_signed(&self, id: &Hash, witness_bytes: &[u8]) -> Result<Admission, RepoError> {
        self.verify_attestation(id, witness_bytes)
    }
}

fn trusted_key(entry: &TrustEntry, key: &KeyFile, at_ms: u64) -> Result<(), RepoError> {
    if at_ms < entry.added_at_ms {
        return Err(RepoError::BadHead(format!(
            "签名时间早于 key {} 加入信任表的时间",
            key.key_id
        )));
    }
    if entry.public_key.as_deref() != Some(key.public.as_str()) {
        return Err(RepoError::BadHead(format!(
            "key {} 的公钥与信任表不一致",
            key.key_id
        )));
    }
    if entry.revoked_at_ms.is_some_and(|at| at_ms > at) {
        return Err(RepoError::BadHead(format!("key {} 已吊销", key.key_id)));
    }
    if !matches!(entry.role.as_str(), "author" | "auditor" | "release") {
        return Err(RepoError::BadHead(format!(
            "key {} 的角色不能签见证",
            key.key_id
        )));
    }
    Ok(())
}

fn verify_signer(
    entry: &TrustEntry,
    public: &str,
    attestation: &Attestation,
) -> Result<(), RepoError> {
    let bytes = crate::signing::public_key_bytes(public)?;
    if public_key_id(&bytes) != attestation.key_id {
        return Err(RepoError::AttestationUntrusted(attestation.key_id.clone()));
    }
    if attestation.signed_at_ms < entry.added_at_ms {
        return Err(RepoError::AttestationUntrusted(attestation.key_id.clone()));
    }
    if !matches!(entry.role.as_str(), "author" | "auditor" | "release") {
        return Err(RepoError::AttestationUntrusted(attestation.key_id.clone()));
    }
    if entry
        .revoked_at_ms
        .is_some_and(|at| attestation.signed_at_ms > at)
    {
        return Err(RepoError::AttestationRevoked(attestation.key_id.clone()));
    }
    Ok(())
}

fn parse_operation(event: &crate::journal::Event) -> Result<Hash, RepoError> {
    Hash::from_hex(
        event
            .payload
            .get("operation")
            .and_then(Value::as_str)
            .unwrap_or_default(),
    )
    .ok_or_else(|| RepoError::AttestationInvalid("attestation 缺 operation".to_string()))
}

fn parse_hash(value: Option<&Value>) -> Option<Hash> {
    value.and_then(Value::as_str).and_then(Hash::from_hex)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate::ClaimSpec;
    use crate::repo::CommitRequest;
    use std::collections::BTreeMap;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "trit-vcs-attestation-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn request(witness: Option<Vec<u8>>) -> CommitRequest {
        CommitRequest {
            message: "signed witness".to_string(),
            session: "qoder:test".to_string(),
            claims: Vec::<ClaimSpec>::new(),
            evidence: Vec::new(),
            tags: Vec::new(),
            allow_unclaimed: true,
            witness,
            intent: None,
            parent_override: None,
            now_secs: 1_000,
        }
    }

    fn seed(
        name: &str,
    ) -> (
        std::path::PathBuf,
        Repo,
        Hash,
        Vec<u8>,
        KeyFile,
        std::path::PathBuf,
    ) {
        let root = temp(name);
        let mut repo = Repo::init(&root).unwrap();
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_string(), b"alpha\n".to_vec());
        let (tree, _) = repo.stage(&files, 1_000).unwrap();
        let witness = Witness::from_run(
            tree,
            None,
            vec!["cargo".into(), "test".into()],
            crate::witness::RunOutput::new(0, b"ok\n".to_vec(), Vec::new(), 1_000, 5),
        )
        .encode();
        let id = repo.commit(request(Some(witness.clone()))).unwrap().id;
        let key = KeyFile::generate().unwrap();
        let path = root.join("author.key");
        key.save_new(&path).unwrap();
        repo.add_key(
            TrustEntry {
                key_id: key.key_id.clone(),
                principal: "qoder:test".to_string(),
                role: "author".to_string(),
                added_at_ms: 1_001,
                public_key: Some(key.public.clone()),
                rotated_from: None,
                revoked_at_ms: None,
                revoke_reason: None,
            },
            "qoder:test",
            1_001,
        )
        .unwrap();
        (root, repo, id, witness, key, path)
    }

    fn attestation(repo: &Repo, id: &Hash) -> Attestation {
        let event = repo
            .journal()
            .events()
            .iter()
            .rev()
            .find(|event| {
                event.kind == EVENT_KIND
                    && event.payload.get("commit").and_then(Value::as_str)
                        == Some(id.to_hex().as_str())
            })
            .unwrap();
        let digest = Hash::from_hex(event.payload["attestation"].as_str().unwrap()).unwrap();
        serde_json::from_slice(&repo.store().get_chunk(&digest).unwrap()).unwrap()
    }

    #[test]
    fn signed_witness_verifies_without_changing_commit_id() {
        let (_root, mut repo, id, witness, _key, path) = seed("roundtrip");
        let before = id;
        let digest = repo
            .attest_witness(&id, &witness, &path, "qoder:test", 2_000)
            .unwrap();
        let admission = repo.admit_signed(&id, &witness).unwrap();
        assert_eq!(admission.attestation, digest);
        assert_eq!(repo.head().unwrap(), Some(before));
        assert!(crate::audit::status(&repo).unwrap().ok);
    }

    #[test]
    fn tampered_witness_and_duplicate_sidecar_are_rejected() {
        let (_root, mut repo, id, witness, _key, path) = seed("tamper");
        repo.attest_witness(&id, &witness, &path, "qoder:test", 2_000)
            .unwrap();
        assert!(matches!(
            repo.admit_signed(&id, b"{}"),
            Err(RepoError::AttestationInvalid(_))
        ));
        let commit = repo.commit_at(&id).unwrap();
        let alternate = Witness::from_run(
            commit.tree,
            None,
            vec!["cargo".into(), "test".into()],
            crate::witness::RunOutput::new(0, b"different\n".to_vec(), Vec::new(), 1_000, 6),
        )
        .encode();
        assert!(matches!(
            repo.admit_signed(&id, &alternate),
            Err(RepoError::AttestationInvalid(_))
        ));
        assert!(
            repo.attest_witness(&id, &witness, &path, "qoder:test", 2_001)
                .is_err()
        );
    }

    #[test]
    fn strict_policy_requires_attestation_and_revocation_is_checked() {
        let (_root, mut repo, id, witness, key, path) = seed("strict");
        repo.set_policy(
            &crate::repo::Policy {
                require_signed_witness: true,
                ..Default::default()
            },
            "qoder:test",
            1_500,
        )
        .unwrap();
        assert!(matches!(
            repo.admit(&id, &witness),
            Err(RepoError::AttestationRequired(_))
        ));
        repo.attest_witness(&id, &witness, &path, "qoder:test", 2_000)
            .unwrap();
        repo.revoke_key(&key.key_id, "compromised", "qoder:test", 3_000)
            .unwrap();
        assert!(repo.admit_signed(&id, &witness).is_ok());
        let mut keys = repo.keys().unwrap();
        keys.keys.get_mut(&key.key_id).unwrap().revoked_at_ms = Some(1_999);
        keys.save(repo.root()).unwrap();
        assert!(matches!(
            repo.admit_signed(&id, &witness),
            Err(RepoError::AttestationRevoked(_))
        ));
    }

    #[test]
    fn legacy_unsigned_admission_remains_compatible() {
        let (_root, mut repo, id, witness, _key, path) = seed("legacy");
        assert!(repo.admit(&id, &witness).is_ok());
        repo.set_policy(
            &crate::repo::Policy {
                require_signed_witness: true,
                ..Default::default()
            },
            "qoder:test",
            1_500,
        )
        .unwrap();
        assert!(matches!(
            repo.admit(&id, &witness),
            Err(RepoError::AttestationRequired(_))
        ));
        repo.attest_witness(&id, &witness, &path, "qoder:test", 2_000)
            .unwrap();
        assert!(repo.admit(&id, &witness).is_ok());
    }

    #[test]
    fn signer_trust_role_and_public_key_are_checked() {
        let (root, mut repo, id, witness, key, path) = seed("signer");
        repo.attest_witness(&id, &witness, &path, "qoder:test", 2_000)
            .unwrap();
        let original = repo.keys().unwrap();
        let foreign = KeyFile::generate().unwrap();
        let value = attestation(&repo, &id);
        let entry = original.keys.get(&key.key_id).unwrap().clone();
        assert!(matches!(
            verify_signer(&entry, &foreign.public, &value),
            Err(RepoError::AttestationUntrusted(_))
        ));
        for case in 0..4 {
            let mut keys = original.clone();
            match case {
                0 => {
                    keys.keys.remove(&key.key_id);
                }
                1 => {
                    keys.keys.get_mut(&key.key_id).unwrap().public_key = None;
                }
                2 => {
                    keys.keys.get_mut(&key.key_id).unwrap().public_key =
                        Some(foreign.public.clone());
                }
                3 => {
                    keys.keys.get_mut(&key.key_id).unwrap().role = "viewer".to_string();
                }
                _ => unreachable!(),
            }
            keys.save(&root).unwrap();
            assert!(matches!(
                repo.admit_signed(&id, &witness),
                Err(RepoError::AttestationUntrusted(_))
            ));
        }
    }

    #[test]
    fn signing_before_trust_admission_is_rejected() {
        let (root, mut repo, id, witness, key, path) = seed("trust-time");
        let events = repo.journal().events().len();
        assert!(
            repo.attest_witness(&id, &witness, &path, "qoder:test", 1_000)
                .is_err()
        );
        assert_eq!(repo.journal().events().len(), events);
        repo.attest_witness(&id, &witness, &path, "qoder:test", 2_000)
            .unwrap();
        let mut keys = repo.keys().unwrap();
        keys.keys.get_mut(&key.key_id).unwrap().added_at_ms = 2_001;
        keys.save(&root).unwrap();
        assert!(matches!(
            repo.admit_signed(&id, &witness),
            Err(RepoError::AttestationUntrusted(_))
        ));
    }

    #[test]
    fn every_signed_statement_field_is_tamper_evident() {
        let (_root, mut repo, id, witness, key, path) = seed("statement");
        repo.attest_witness(&id, &witness, &path, "qoder:test", 2_000)
            .unwrap();
        let value = attestation(&repo, &id);
        let commit = repo.commit_at(&id).unwrap();
        type Mutation = (&'static str, fn(&mut Attestation));
        let mutations: [Mutation; 10] = [
            ("schema", |bad| bad.schema = "other".to_string()),
            ("algorithm", |bad| bad.algorithm = "other".to_string()),
            ("commit", |bad| bad.commit = Hash::of(b"other-commit")),
            ("witness", |bad| bad.witness = Hash::of(b"other-witness")),
            ("tree", |bad| bad.tree = Hash::of(b"other-tree")),
            ("base", |bad| bad.base = Some(Hash::of(b"other-base"))),
            ("key_id", |bad| bad.key_id = "other".to_string()),
            ("signature", |bad| bad.signature = "00".repeat(64)),
            ("signed_at_ms", |bad| bad.signed_at_ms += 1),
            ("session", |bad| bad.session = "other".to_string()),
        ];
        for (field, mutate) in mutations {
            let mut bad = value.clone();
            mutate(&mut bad);
            assert!(
                bad.verify(&key.public, &id, &commit, None, &witness)
                    .is_err(),
                "{field} 必须让验签或绑定失败"
            );
        }
        let bindings: [fn(&mut Attestation); 6] = [
            |bad| bad.schema = "other".to_string(),
            |bad| bad.algorithm = "other".to_string(),
            |bad| bad.commit = Hash::of(b"other-commit"),
            |bad| bad.witness = Hash::of(b"other-witness"),
            |bad| bad.tree = Hash::of(b"other-tree"),
            |bad| bad.base = Some(Hash::of(b"other-base")),
        ];
        for mutate in bindings {
            let mut bad = value.clone();
            mutate(&mut bad);
            bad.signature = key.sign_hex(&bad.statement()).unwrap();
            assert!(
                bad.verify(&key.public, &id, &commit, None, &witness)
                    .is_err(),
                "有效签名不得绕过 schema/算法/提交/树/父树/见证绑定"
            );
        }
    }

    #[test]
    fn manually_duplicated_sidecar_is_rejected() {
        let (_root, mut repo, id, witness, _key, path) = seed("duplicate-event");
        repo.attest_witness(&id, &witness, &path, "qoder:test", 2_000)
            .unwrap();
        let event = repo
            .journal()
            .events()
            .iter()
            .find(|event| event.kind == EVENT_KIND)
            .unwrap()
            .clone();
        let operation = event.payload["operation"].as_str().unwrap().to_string();
        let begin = repo
            .journal()
            .events()
            .iter()
            .find(|candidate| candidate.hash.to_hex() == operation)
            .unwrap()
            .clone();
        repo.journal_mut()
            .append(EVENT_KIND, event.payload, 2_001)
            .unwrap();
        repo.finish_operation(&begin, "attest", "ok", json!({}), 2_002)
            .unwrap();
        assert!(matches!(
            repo.admit_signed(&id, &witness),
            Err(RepoError::AttestationInvalid(_))
        ));
        let report = crate::audit::status(&repo).unwrap();
        assert!(
            report
                .issues
                .iter()
                .any(|issue| issue.kind == "attestation_duplicate")
        );
    }

    #[test]
    fn cross_commit_attestation_cannot_be_replayed() {
        let (_root, mut repo, id, _witness, _key, path) = seed("replay");
        let mut files = BTreeMap::new();
        files.insert("b.txt".to_string(), b"beta\n".to_vec());
        let (tree, _) = repo.stage(&files, 1_100).unwrap();
        let base = repo.commit_at(&id).unwrap().tree;
        let witness = Witness::from_run(
            tree,
            Some(base),
            vec!["cargo".into(), "test".into()],
            crate::witness::RunOutput::new(0, b"ok\n".to_vec(), Vec::new(), 1_100, 5),
        )
        .encode();
        let other = repo.commit(request(Some(witness.clone()))).unwrap().id;
        repo.attest_witness(&other, &witness, &path, "qoder:test", 2_000)
            .unwrap();
        let event = repo
            .journal()
            .events()
            .iter()
            .find(|event| event.kind == EVENT_KIND)
            .unwrap()
            .clone();
        let mut payload = event.payload;
        payload["commit"] = json!(id.to_hex());
        repo.journal_mut()
            .append(EVENT_KIND, payload, 2_001)
            .unwrap();
        assert!(repo.admit_signed(&id, b"{}").is_err());
        let report = crate::audit::status(&repo).unwrap();
        assert!(!report.ok);
    }
}
