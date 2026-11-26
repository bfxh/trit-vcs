//! Ed25519 密钥文件与提交签名：把 key_id 绑到提交字节，而不是只绑到信任表条目。
//!
//! 私钥文件是 `trit-key-v1` JSON：secret/public/key_id。`key init` 生成；
//! `commit --sign-key FILE` 只签一次提交的 canonical 对象字节，签名落
//! `signature` 事件（不改变提交对象 id，也不改变仓库状态）。

use std::fs;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hash::Hash;
use crate::keys::public_key_id;
use crate::model::Commit;
use crate::repo::{Repo, RepoError};

pub const SCHEMA: &str = "trit-key-v1";
pub const PUBLIC_LEN: usize = 32;
pub const SECRET_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyFile {
    pub schema: String,
    pub secret: String,
    pub public: String,
    pub key_id: String,
}

impl KeyFile {
    pub fn generate() -> Result<Self, RepoError> {
        let mut secret = [0u8; SECRET_LEN];
        getrandom::fill(&mut secret)
            .map_err(|err| RepoError::BadHead(format!("生成随机私钥失败：{err}")))?;
        let signing = SigningKey::from_bytes(&secret);
        let public = signing.verifying_key().to_bytes();
        Ok(Self {
            schema: SCHEMA.to_string(),
            secret: encode_hex(&secret),
            public: encode_hex(&public),
            key_id: public_key_id(&public),
        })
    }

    pub fn load(path: &Path) -> Result<Self, RepoError> {
        let text = fs::read_to_string(path)?;
        let mut key: Self = serde_json::from_str(&text)
            .map_err(|err| RepoError::BadHead(format!("密钥文件 {}: {err}", path.display())))?;
        // 用户可能手写大写 hex；内存里统一成小写，避免与信任表逐字符比较时假红。
        key.secret.make_ascii_lowercase();
        key.public.make_ascii_lowercase();
        if let Ok(public) = decode_hex::<PUBLIC_LEN>(&key.public, "public") {
            key.key_id = public_key_id(&public);
        }
        key.validate()?;
        Ok(key)
    }

    pub fn save_new(&self, path: &Path) -> Result<(), RepoError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|err| RepoError::BadHead(format!("密钥文件编码失败：{err}")))?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(&bytes)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<(), RepoError> {
        if self.schema != SCHEMA {
            return Err(RepoError::BadHead(format!(
                "密钥文件 schema 必须是 {SCHEMA}"
            )));
        }
        let secret: [u8; SECRET_LEN] = decode_hex(&self.secret, "secret")?;
        let public: [u8; PUBLIC_LEN] = decode_hex(&self.public, "public")?;
        let signing = SigningKey::from_bytes(&secret);
        if signing.verifying_key().to_bytes() != public {
            return Err(RepoError::BadHead(
                "密钥文件 public 与 secret 不匹配".to_string(),
            ));
        }
        if self.key_id != public_key_id(&public) {
            return Err(RepoError::BadHead(
                "密钥文件 key_id 与公钥指纹不匹配".to_string(),
            ));
        }
        Ok(())
    }

    pub fn public_bytes(&self) -> Result<[u8; PUBLIC_LEN], RepoError> {
        decode_hex(&self.public, "public")
    }

    fn signing_key(&self) -> Result<SigningKey, RepoError> {
        let secret: [u8; SECRET_LEN] = decode_hex(&self.secret, "secret")?;
        let signing = SigningKey::from_bytes(&secret);
        if signing.verifying_key().to_bytes() != self.public_bytes()? {
            return Err(RepoError::BadHead("密钥文件公钥不匹配".to_string()));
        }
        Ok(signing)
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, RepoError> {
        Ok(self.signing_key()?.sign(message))
    }

    pub fn sign_hex(&self, message: &[u8]) -> Result<String, RepoError> {
        Ok(encode_hex(&self.sign(message)?.to_bytes()))
    }
}

impl Repo {
    /// 对一条已存在的提交签 Ed25519，并把签名作为 `signature` 事件落链。
    pub fn sign_commit(
        &mut self,
        commit: &Hash,
        key_path: &Path,
        session: &str,
        at_ms: u64,
    ) -> Result<Hash, RepoError> {
        if session.trim().is_empty() || session.chars().any(char::is_control) {
            return Err(RepoError::BadHead("session 不能为空".to_string()));
        }
        let _guard = self.lock_state()?;
        let key = KeyFile::load(key_path)?;
        let bytes = self.store().get_chunk(commit)?;
        Commit::decode(&bytes).map_err(|err| {
            RepoError::BadHead(format!("提交 {} 不是合法提交：{err}", commit.short()))
        })?;
        let keys = self.keys()?;
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
        let signature = key.sign(&bytes)?;
        let signature_hex = encode_hex(&signature.to_bytes());
        let signature_hash = Hash::of(&signature.to_bytes());
        let commit_hex = commit.to_hex();
        let key_id = key.key_id.clone();
        let session_owned = session.to_string();
        self.with_operation(
            "sign_commit",
            json!({
                "commit": commit_hex,
                "key_id": key_id,
                "session": session_owned,
            }),
            at_ms,
            move |repo| {
                let before = repo.state_digest()?.to_hex();
                let after = repo.state_digest()?.to_hex();
                repo.journal_mut().append(
                    "signature",
                    json!({
                        "commit": commit_hex,
                        "key_id": key_id,
                        "algorithm": "ed25519",
                        "signature": signature_hex,
                        "signed_at_ms": at_ms,
                        "session": session,
                        "state_before": before,
                        "state_after": after,
                    }),
                    at_ms,
                )?;
                Ok(signature_hash)
            },
        )
    }
}

pub fn verify_signature(
    public_hex: &str,
    signature_hex: &str,
    message: &[u8],
) -> Result<(), RepoError> {
    let public = public_key_bytes(public_hex)?;
    let signature_bytes: [u8; SIGNATURE_LEN] = decode_hex(signature_hex, "signature")?;
    let key = VerifyingKey::from_bytes(&public)
        .map_err(|err| RepoError::BadHead(format!("公钥不合法：{err}")))?;
    let signature = Signature::from_bytes(&signature_bytes);
    key.verify_strict(message, &signature)
        .map_err(|err| RepoError::BadHead(format!("签名不通过：{err}")))
}

pub fn public_key_bytes(public_hex: &str) -> Result<[u8; PUBLIC_LEN], RepoError> {
    let public: [u8; PUBLIC_LEN] = decode_hex(public_hex, "public")?;
    VerifyingKey::from_bytes(&public)
        .map_err(|err| RepoError::BadHead(format!("公钥不合法：{err}")))?;
    Ok(public)
}

fn encode_hex<const N: usize>(bytes: &[u8; N]) -> String {
    let mut out = String::with_capacity(N * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn decode_hex<const N: usize>(text: &str, field: &str) -> Result<[u8; N], RepoError> {
    if text.len() != N * 2 || !text.is_ascii() {
        return Err(RepoError::BadHead(format!("{field} 必须是 {N} 字节 hex")));
    }
    let mut out = [0u8; N];
    for (index, chunk) in text.as_bytes().chunks(2).enumerate() {
        let hi = chunk[0] as char;
        let lo = chunk[1] as char;
        let hi = hi
            .to_digit(16)
            .ok_or_else(|| RepoError::BadHead(format!("{field} 不是 hex")))?;
        let lo = lo
            .to_digit(16)
            .ok_or_else(|| RepoError::BadHead(format!("{field} 不是 hex")))?;
        out[index] = ((hi << 4) | lo) as u8;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::gate::ClaimSpec;
    use crate::keys::TrustEntry;
    use crate::repo::CommitRequest;

    fn temp(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("trit-vcs-signing-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn keyfile_roundtrip_signs_and_verifies() {
        let root = temp("roundtrip");
        fs::create_dir_all(&root).unwrap();
        let key = KeyFile::generate().unwrap();
        let path = root.join("key.json");
        key.save_new(&path).unwrap();
        let loaded = KeyFile::load(&path).unwrap();
        let signature = loaded.sign(b"trit").unwrap();
        verify_signature(&key.public, &encode_hex(&signature.to_bytes()), b"trit").unwrap();
        assert!(
            verify_signature(&key.public, &encode_hex(&signature.to_bytes()), b"tampered").is_err()
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn signed_commit_is_audited_and_bad_signature_is_red() {
        let root = temp("audit");
        fs::create_dir_all(&root).unwrap();
        let mut repo = Repo::init(&root).unwrap();
        let mut files = BTreeMap::new();
        files.insert("a.txt".to_string(), b"alpha".to_vec());
        repo.stage(&files, 1_000).unwrap();
        let outcome = repo
            .commit(CommitRequest {
                message: "signed".to_string(),
                session: "qoder:sign".to_string(),
                claims: Vec::<ClaimSpec>::new(),
                evidence: Vec::new(),
                tags: Vec::new(),
                allow_unclaimed: true,
                witness: None,
                intent: None,
                parents_override: None,
                now_secs: 1_000,
            })
            .unwrap();
        let key = KeyFile::generate().unwrap();
        let key_path = root.join("key.json");
        key.save_new(&key_path).unwrap();
        repo.add_key(
            TrustEntry {
                key_id: key.key_id.clone(),
                principal: "qoder:sign".to_string(),
                role: "author".to_string(),
                added_at_ms: 1_001,
                public_key: Some(key.public.clone()),
                rotated_from: None,
                revoked_at_ms: None,
                revoke_reason: None,
            },
            "qoder:sign",
            1_001,
        )
        .unwrap();
        repo.sign_commit(&outcome.id, &key_path, "qoder:sign", 1_002)
            .unwrap();
        let report = crate::audit::status(&repo).unwrap();
        assert!(report.ok, "合法签名应审计绿：{:?}", report.issues);

        let state = repo.state_digest().unwrap().to_hex();
        repo.journal_mut()
            .append(
                "signature",
                json!({
                    "commit": outcome.id.to_hex(),
                    "key_id": key.key_id,
                    "algorithm": "ed25519",
                    "signature": "00".repeat(SIGNATURE_LEN),
                    "signed_at_ms": 1_003,
                    "session": "qoder:bad",
                    "state_before": state,
                    "state_after": state,
                }),
                1_003,
            )
            .unwrap();
        let bad = crate::audit::status(&repo).unwrap();
        assert!(!bad.ok);
        assert!(
            bad.issues
                .iter()
                .any(|issue| issue.kind == "signature_invalid"),
            "{:?}",
            bad.issues
        );
        let _ = fs::remove_dir_all(&root);
    }
}
