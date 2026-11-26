//! 跨机视图快照与客户端 pin：服务端给出「当前 journal 高度/头/前缀根 + ref tip」，
//! 客户端把上一次成功同步看到的视图记进 `trit-sync-v1` 事件；下一次同步用
//! 检查点间 consistency proof 验证服务端历史只是往后追加，而不是回滚或换了一条。
//!
//! 这不是透明日志，也不是服务端签名：它只能发现「同一客户端见过的两个视图不一致」。
//! 两个客户端之间互相没见过对方的 pin，所以分裂视图仍要靠后续的签名检查点/共享锚。

use serde_json::{Value, json};

use crate::checkpoint;
use crate::checkpoint::consistency::{self, ConsistencyProof};
use crate::hash::Hash;
use crate::journal::Event;
use crate::keys::public_key_id;
use crate::repo::{Repo, RepoError};
use crate::signing::{KeyFile, public_key_bytes, verify_signature};
use crate::sync;

pub const SCHEMA: &str = "trit-view-v1";
pub const SIG_SCHEMA: &str = "trit-view-sig-v1";
pub const MAX_PIN_PROOF_HEIGHT: usize = 1_000_000;

/// 服务端在某一刻的 journal 视图 + 某个 ref 的 tip。
/// 服务端对一次视图的 Ed25519 签名：自证「持有私钥的人确认了这个高度/根/tip」。
/// 它不等于可信时间戳，也不自动建立信任；客户端第一次只能 TOFU，之后钉住同一公钥。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewSignature {
    pub key_id: String,
    pub public_key: String,
    pub signature: String,
}

impl ViewSignature {
    pub fn sign(key: &KeyFile, name: &str, snapshot: &Snapshot) -> Result<Self, RepoError> {
        Ok(Self {
            key_id: key.key_id.clone(),
            public_key: key.public.clone(),
            signature: key.sign_hex(&signing_message(name, snapshot))?,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": SIG_SCHEMA,
            "algorithm": "ed25519",
            "key_id": self.key_id,
            "public_key": self.public_key,
            "signature": self.signature,
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ViewError> {
        let object = value
            .as_object()
            .ok_or_else(|| ViewError::Bad("视图签名不是 JSON 对象".to_string()))?;
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "schema" | "algorithm" | "key_id" | "public_key" | "signature"
            ) {
                return Err(ViewError::Bad(format!("视图签名含未知字段 {key}")));
            }
        }
        if object.get("schema").and_then(Value::as_str) != Some(SIG_SCHEMA) {
            return Err(ViewError::Bad("视图签名 schema 不受支持".to_string()));
        }
        if object.get("algorithm").and_then(Value::as_str) != Some("ed25519") {
            return Err(ViewError::Bad("视图签名算法只支持 ed25519".to_string()));
        }
        let key_id = object
            .get("key_id")
            .and_then(Value::as_str)
            .filter(|key| key.len() <= 128)
            .ok_or_else(|| ViewError::Bad("视图签名 key_id 不合法".to_string()))?
            .to_string();
        let public_key = object
            .get("public_key")
            .and_then(Value::as_str)
            .ok_or_else(|| ViewError::Bad("视图签名缺 public_key".to_string()))?
            .to_string();
        let signature = object
            .get("signature")
            .and_then(Value::as_str)
            .ok_or_else(|| ViewError::Bad("视图签名缺 signature".to_string()))?
            .to_string();
        let public = public_key_bytes(&public_key)
            .map_err(|err| ViewError::Bad(format!("视图签名公钥不合法：{err}")))?;
        if key_id != public_key_id(&public) {
            return Err(ViewError::Bad(
                "视图签名 key_id 与公钥指纹不匹配".to_string(),
            ));
        }
        if signature.len() != crate::signing::SIGNATURE_LEN * 2
            || !signature.is_ascii()
            || !signature.chars().all(|ch| ch.is_ascii_hexdigit())
        {
            return Err(ViewError::Bad("视图签名必须是 64 字节 hex".to_string()));
        }
        Ok(Self {
            key_id,
            public_key,
            signature,
        })
    }

    pub fn verify(&self, name: &str, snapshot: &Snapshot) -> Result<(), ViewError> {
        verify_signature(
            &self.public_key,
            &self.signature,
            &signing_message(name, snapshot),
        )
        .map_err(|err| ViewError::Bad(format!("视图签名不通过：{err}")))
    }
}

/// 签名域分离：ref、高度、头、根、tip 逐行写死，避免把字段挪位置造成重放。
pub fn signing_message(name: &str, snapshot: &Snapshot) -> Vec<u8> {
    format!(
        "trit-view-sig-v1\nref:{name}\nheight:{}\nhead:{}\nroot:{}\ntip:{}\n",
        snapshot.height,
        snapshot
            .head
            .map(|id| id.to_hex())
            .unwrap_or_else(|| "-".to_string()),
        snapshot.root.to_hex(),
        snapshot
            .tip
            .map(|id| id.to_hex())
            .unwrap_or_else(|| "-".to_string())
    )
    .into_bytes()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub height: usize,
    pub head: Option<Hash>,
    pub root: Hash,
    pub tip: Option<Hash>,
}

impl Snapshot {
    /// 从仓库当前 journal 与 ref 生成快照。ref 名先校验，避免把坏名字当“没有这个 ref”。
    pub fn of(repo: &Repo, name: &str) -> Result<Self, RepoError> {
        Repo::validate_ref(name)?;
        let events = repo.journal().events();
        let leaf_hashes: Vec<Hash> = events.iter().map(|event| event.hash).collect();
        Ok(Self {
            height: events.len(),
            head: events.last().map(|event| event.hash),
            root: checkpoint::merkle_root(&leaf_hashes),
            tip: repo.ref_commit(name)?,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "schema": SCHEMA,
            "height": self.height,
            "head": self.head.map(|id| id.to_hex()),
            "root": self.root.to_hex(),
            "tip": self.tip.map(|id| id.to_hex()),
        })
    }

    /// `trit-sync-v1` 事件里的 `view` 还带 `pin_before`/`pin_status`；这里只取快照五字段，仍走严格解析。
    pub fn from_evidence(value: &Value) -> Result<Self, ViewError> {
        Self::from_json(&json!({
            "schema": value.get("schema"),
            "height": value.get("height"),
            "head": value.get("head"),
            "root": value.get("root"),
            "tip": value.get("tip"),
        }))
    }

    /// 严格解析：未知字段拒绝，高度/根/头/tip 任一形状不对就整条拒绝。
    pub fn from_json(value: &Value) -> Result<Self, ViewError> {
        let object = value
            .as_object()
            .ok_or_else(|| ViewError::Bad("视图不是 JSON 对象".to_string()))?;
        for key in object.keys() {
            if !matches!(key.as_str(), "schema" | "height" | "head" | "root" | "tip") {
                return Err(ViewError::Bad(format!("视图含未知字段 {key}")));
            }
        }
        if object.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
            return Err(ViewError::Bad("视图 schema 不受支持".to_string()));
        }
        let height = object
            .get("height")
            .and_then(Value::as_u64)
            .and_then(|raw| usize::try_from(raw).ok())
            .filter(|height| *height <= MAX_PIN_PROOF_HEIGHT)
            .ok_or_else(|| ViewError::Bad("视图 height 不合法".to_string()))?;
        let head = nullable_hash(object.get("head"), "head")?;
        let root = object
            .get("root")
            .and_then(Value::as_str)
            .and_then(Hash::from_hex)
            .ok_or_else(|| ViewError::Bad("视图 root 不合法".to_string()))?;
        let tip = nullable_hash(object.get("tip"), "tip")?;
        if height == 0 && head.is_some() {
            return Err(ViewError::Bad("高度为 0 时 head 必须为空".to_string()));
        }
        if height > 0 && head.is_none() {
            return Err(ViewError::Bad("高度非 0 时 head 不能为空".to_string()));
        }
        Ok(Self {
            height,
            head,
            root,
            tip,
        })
    }
}

/// 上一次成功同步留下的 pin：只取能证明「历史没有倒退」的字段。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pin {
    pub height: usize,
    pub head: Option<Hash>,
    pub root: Hash,
    pub tip: Option<Hash>,
    /// 服务端签名者指纹；首次同步没有旧 pin 时为 TOFU 记录，之后必须保持不变。
    pub signer: Option<String>,
    /// 签名者公钥（hex）；和 `signer` 成对存在，便于审计离线复验。
    pub signer_key: Option<String>,
}

impl From<Snapshot> for Pin {
    fn from(snapshot: Snapshot) -> Self {
        Self {
            height: snapshot.height,
            head: snapshot.head,
            root: snapshot.root,
            tip: snapshot.tip,
            signer: None,
            signer_key: None,
        }
    }
}

impl Pin {
    pub fn to_json(&self) -> Value {
        json!({
            "height": self.height,
            "head": self.head.map(|id| id.to_hex()),
            "root": self.root.to_hex(),
            "tip": self.tip.map(|id| id.to_hex()),
            "signer": self.signer,
            "signer_key": self.signer_key,
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ViewError> {
        let object = value
            .as_object()
            .ok_or_else(|| ViewError::Bad("pin 不是 JSON 对象".to_string()))?;
        for key in object.keys() {
            if !matches!(
                key.as_str(),
                "height" | "head" | "root" | "tip" | "signer" | "signer_key"
            ) {
                return Err(ViewError::Bad(format!("pin 含未知字段 {key}")));
            }
        }
        let height = object
            .get("height")
            .and_then(Value::as_u64)
            .and_then(|raw| usize::try_from(raw).ok())
            .filter(|height| *height <= MAX_PIN_PROOF_HEIGHT)
            .ok_or_else(|| ViewError::Bad("pin height 不合法".to_string()))?;
        let head = nullable_hash(object.get("head"), "head")?;
        let root = object
            .get("root")
            .and_then(Value::as_str)
            .and_then(Hash::from_hex)
            .ok_or_else(|| ViewError::Bad("pin root 不合法".to_string()))?;
        let tip = nullable_hash(object.get("tip"), "tip")?;
        if (height == 0) != head.is_none() {
            return Err(ViewError::Bad(
                "pin 的 height 与 head 不一致（0 条必须无头，非 0 条必须有头）".to_string(),
            ));
        }
        let signer = optional_string(object.get("signer"), "signer")?;
        let signer_key = optional_string(object.get("signer_key"), "signer_key")?;
        if signer.is_some() != signer_key.is_some() {
            return Err(ViewError::Bad(
                "pin 的 signer 与 signer_key 必须成对出现".to_string(),
            ));
        }
        if let (Some(key_id), Some(public_hex)) = (&signer, &signer_key) {
            let public = public_key_bytes(public_hex)
                .map_err(|err| ViewError::Bad(format!("pin signer_key 不合法：{err}")))?;
            if key_id != &public_key_id(&public) {
                return Err(ViewError::Bad(
                    "pin 的 signer 与 signer_key 指纹不匹配".to_string(),
                ));
            }
        }
        Ok(Self {
            height,
            head,
            root,
            tip,
            signer,
            signer_key,
        })
    }
}

fn optional_string(value: Option<&Value>, field: &str) -> Result<Option<String>, ViewError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) if !raw.is_empty() && raw.len() <= 256 => Ok(Some(raw.clone())),
        Some(_) => Err(ViewError::Bad(format!("{field} 必须是非空字符串"))),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ViewError {
    #[error("视图不合法：{0}")]
    Bad(String),
    #[error("服务端历史回滚：已固定 {pinned} 条事件，服务端只有 {actual} 条")]
    Rollback { pinned: usize, actual: usize },
    #[error("服务端历史与已固定视图分裂：{0}")]
    Equivocation(String),
    #[error("已固定的视图由 {signer} 签名，但服务端这次没有签名")]
    Unsigned { signer: String },
    #[error("服务端视图签名者变了：已固定 {pinned}，本次 {actual}")]
    SignerChanged { pinned: String, actual: String },
}

impl ViewError {
    pub fn kind(&self) -> &'static str {
        match self {
            ViewError::Bad(_) => "view_bad",
            ViewError::Rollback { .. } => "remote_rollback",
            ViewError::Equivocation(_) => "remote_equivocation",
            ViewError::Unsigned { .. } => "remote_view_unsigned",
            ViewError::SignerChanged { .. } => "remote_signer_changed",
        }
    }

    pub fn commands(&self) -> Vec<String> {
        match self {
            ViewError::Bad(detail) => vec![
                format!("服务端视图形状不合法：{detail}"),
                "先 `trit-vcs view <ref> --remote <url> --json` 看服务端到底回了什么".to_string(),
            ],
            ViewError::Rollback { pinned, actual } => vec![
                format!(
                    "已固定的前缀是 {pinned} 条事件，服务端只回 {actual} 条：它删了尾巴或换成了更短的历史"
                ),
                "不要拉取/不要发布；先把服务端整份 journal 与旧 pin 交给审计员，确认是回滚还是换了中央仓".to_string(),
            ],
            ViewError::Equivocation(detail) => vec![
                format!("服务端前缀证明对不上：{detail}"),
                "不要删除本地 journal/pin；先在 `audit log --kind publish,pull --json` 里找出上一次成功视图，再和服务端日志逐条对".to_string(),
            ],
            ViewError::Unsigned { signer } => vec![
                format!("上一次视图由 {signer} 签名，这一次服务端没给签名：可能换成了无密钥的旧服务端"),
                "不要当作普通升级；先用 `trit-vcs view <ref> --remote ... --json` 确认服务端配置，再决定是否显式降级".to_string(),
            ],
            ViewError::SignerChanged { pinned, actual } => vec![
                format!("视图签名者从 {pinned} 变成了 {actual}，但没有经过旧钥签名的轮换声明"),
                "停止同步；先核对服务端新公钥指纹是否从独立渠道确认过，再决定是否重建 pin".to_string(),
            ],
        }
    }
}

/// 只接受 `http://host:port`：与客户端 `normalize_base` 的落账形态一致，不带路径/尾斜杠。
pub fn valid_remote(raw: &str) -> bool {
    let Some(rest) = raw.trim().strip_prefix("http://") else {
        return false;
    };
    !rest.is_empty() && !rest.contains('/') && rest.contains(':')
}

/// 在客户端 journal 里找同一 `(remote, ref)` 最近一次成功 HTTP 同步记录的视图。
///
/// pin 不放独立文件：它必须和同步事件一起进哈希链，改 pin 等于改账。
pub fn latest_pin(repo: &Repo, remote: &str, name: &str) -> Result<Option<Pin>, ViewError> {
    for event in repo.journal().events().iter().rev() {
        if !matches!(event.kind.as_str(), "publish" | "pull") {
            continue;
        }
        if event.payload.get("schema").and_then(Value::as_str) != Some(sync::SCHEMA) {
            continue;
        }
        if event.payload.get("transport").and_then(Value::as_str) != Some("http") {
            continue;
        }
        if !matches!(
            event.payload.get("side").and_then(Value::as_str),
            Some("source" | "client")
        ) {
            continue;
        }
        if event.payload.get("name").and_then(Value::as_str) != Some(name) {
            continue;
        }
        if event.payload.get("remote").and_then(Value::as_str) != Some(remote) {
            continue;
        }
        let Some(view) = event.payload.get("view") else {
            continue;
        };
        if view.is_null() {
            continue;
        }
        let snapshot = Snapshot::from_evidence(view)?;
        let signature = match view.get("signature") {
            None | Some(Value::Null) => None,
            Some(raw) => Some(ViewSignature::from_json(raw)?),
        };
        if let Some(signature) = &signature {
            signature.verify(name, &snapshot)?;
        }
        let mut pin = Pin::from(snapshot);
        if let Some(signature) = signature {
            pin.signer = Some(signature.key_id);
            pin.signer_key = Some(signature.public_key);
        }
        return Ok(Some(pin));
    }
    Ok(None)
}

/// 把服务端返回的视图与本地 pin 对账；`proof` 是服务端对 `pin.height` 给出的旧→新一致性证明。
pub fn verify_pin(
    pin: Option<&Pin>,
    view: &Snapshot,
    proof: Option<&ConsistencyProof>,
) -> Result<PinStatus, ViewError> {
    let Some(pin) = pin else {
        return Ok(PinStatus::First);
    };
    if pin.height > view.height {
        return Err(ViewError::Rollback {
            pinned: pin.height,
            actual: view.height,
        });
    }
    if pin.height == view.height {
        if pin.root != view.root || pin.head != view.head {
            return Err(ViewError::Equivocation(format!(
                "同一高度 {} 的前缀根/头不同：pin {}… / 服务端 {}…",
                pin.height,
                pin.root.short(),
                view.root.short()
            )));
        }
        return Ok(PinStatus::Unchanged);
    }
    // 高度变长时不能只看“pin 的头还在这棵树里”：那只能证明一条叶在，不能证明旧根是新根的前缀。
    let Some(proof) = proof else {
        return Err(ViewError::Equivocation(
            "服务端没有提供旧前缀到新前缀的一致性证明".to_string(),
        ));
    };
    if proof.from_size != pin.height
        || proof.to_size != view.height
        || proof.old_root != pin.root
        || proof.new_root != view.root
    {
        return Err(ViewError::Equivocation(format!(
            "一致性证明尺寸/根不符：{}→{}，旧根 {}…，新根 {}…",
            proof.from_size,
            proof.to_size,
            proof.old_root.short(),
            proof.new_root.short()
        )));
    }
    match consistency::verify_consistency(proof) {
        Ok(true) => Ok(PinStatus::Advanced),
        Ok(false) => Err(ViewError::Equivocation(
            "一致性证明复算不通过：旧前缀不是新根的前缀".to_string(),
        )),
        Err(err) => Err(ViewError::Equivocation(format!(
            "一致性证明形状不合法：{err}"
        ))),
    }
}

/// 校验本次视图签名，并钉住签名者连续性：
/// 旧 pin 有签名者 ⇒ 本次必须同一签名者；旧 pin 无签名者允许一次性升级到签名视图。
pub fn verify_view_signature(
    pin: Option<&Pin>,
    name: &str,
    view: &Snapshot,
    signature: Option<&ViewSignature>,
) -> Result<(), ViewError> {
    if let Some(signature) = signature {
        signature.verify(name, view)?;
    }
    let Some(pin) = pin else {
        return Ok(());
    };
    let Some(expected) = &pin.signer_key else {
        return Ok(());
    };
    let Some(signature) = signature else {
        return Err(ViewError::Unsigned {
            signer: pin.signer.clone().unwrap_or_else(|| expected.clone()),
        });
    };
    if signature.public_key != *expected || pin.signer.as_deref() != Some(signature.key_id.as_str())
    {
        return Err(ViewError::SignerChanged {
            pinned: pin.signer.clone().unwrap_or_default(),
            actual: signature.key_id.clone(),
        });
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinStatus {
    First,
    Unchanged,
    Advanced,
}

impl PinStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            PinStatus::First => "first",
            PinStatus::Unchanged => "unchanged",
            PinStatus::Advanced => "advanced",
        }
    }
}

/// audit 事件里 `view` 的形态：快照 + 服务端签名（可选）+ 上一次 pin + 对账结论。
pub fn evidence_json(
    snapshot: &Snapshot,
    pin: Option<&Pin>,
    status: PinStatus,
    signature: Option<&ViewSignature>,
) -> Value {
    let mut view = snapshot.to_json();
    view["signature"] = signature.map(ViewSignature::to_json).unwrap_or(Value::Null);
    view["pin_before"] = pin.map(Pin::to_json).unwrap_or(Value::Null);
    view["pin_status"] = json!(status.as_str());
    view
}

fn nullable_hash(value: Option<&Value>, field: &str) -> Result<Option<Hash>, ViewError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(raw)) => Hash::from_hex(raw)
            .map(Some)
            .ok_or_else(|| ViewError::Bad(format!("{field} 不是合法哈希"))),
        Some(_) => Err(ViewError::Bad(format!("{field} 必须是字符串或 null"))),
    }
}

/// 生成服务端对某个旧高度的 consistency proof；旧高度超界返回 `None`（由调用方判回滚）。
pub fn proof_from(
    events: &[Event],
    from_height: usize,
) -> Result<Option<ConsistencyProof>, ViewError> {
    if from_height > events.len() {
        return Ok(None);
    }
    let leaves: Vec<Hash> = events.iter().map(|event| event.hash).collect();
    consistency::consistency_proof(&leaves, from_height)
        .map(Some)
        .map_err(|err| ViewError::Bad(format!("生成一致性证明失败：{err}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::KeyFile;

    fn snapshot(height: usize, head: Option<Hash>) -> Snapshot {
        let leaves: Vec<Hash> = (0..height)
            .map(|i| Hash::of(format!("e{i}").as_bytes()))
            .collect();
        Snapshot {
            height,
            head,
            root: checkpoint::merkle_root(&leaves),
            tip: None,
        }
    }

    #[test]
    fn view_json_roundtrips_strictly() {
        let view = snapshot(3, Some(Hash::of(b"e2")));
        let json = view.to_json();
        assert_eq!(Snapshot::from_json(&json).unwrap(), view);
        let mut bad = json.clone();
        bad["extra"] = json!(1);
        assert!(matches!(Snapshot::from_json(&bad), Err(ViewError::Bad(_))));
        let mut bad = json;
        bad["root"] = json!("zz");
        assert!(matches!(Snapshot::from_json(&bad), Err(ViewError::Bad(_))));
    }

    #[test]
    fn pin_json_requires_height_head_agreement() {
        let pin = Pin::from(snapshot(2, Some(Hash::of(b"e1"))));
        assert_eq!(Pin::from_json(&pin.to_json()).unwrap(), pin);
        let mut bad = pin.to_json();
        bad["head"] = Value::Null;
        assert!(matches!(Pin::from_json(&bad), Err(ViewError::Bad(_))));
        let mut bad = pin.to_json();
        bad["height"] = json!(0);
        assert!(matches!(Pin::from_json(&bad), Err(ViewError::Bad(_))));
    }

    #[test]
    fn pin_rejects_shorter_history() {
        let mut old = snapshot(3, Some(Hash::of(b"e2")));
        old.tip = Some(Hash::of(b"t"));
        let new = snapshot(2, Some(Hash::of(b"e1")));
        let err = verify_pin(Some(&Pin::from(old)), &new, None).unwrap_err();
        assert!(matches!(err, ViewError::Rollback { .. }));
    }

    #[test]
    fn pin_same_height_requires_same_root_and_head() {
        let pin = Pin::from(snapshot(3, Some(Hash::of(b"e2"))));
        let same = snapshot(3, Some(Hash::of(b"e2")));
        assert_eq!(
            verify_pin(Some(&pin), &same, None).unwrap(),
            PinStatus::Unchanged
        );
        let mut other = same.clone();
        other.root = Hash::of(b"other");
        assert!(matches!(
            verify_pin(Some(&pin), &other, None),
            Err(ViewError::Equivocation(_))
        ));
    }

    #[test]
    fn advanced_pin_requires_consistency_proof() {
        let old = snapshot(3, Some(Hash::of(b"e2")));
        let pin = Pin::from(old);
        let new = snapshot(6, Some(Hash::of(b"e5")));
        assert!(matches!(
            verify_pin(Some(&pin), &new, None),
            Err(ViewError::Equivocation(_))
        ));

        let leaves: Vec<Hash> = (0..6)
            .map(|i| Hash::of(format!("e{i}").as_bytes()))
            .collect();
        let proof = consistency::consistency_proof(&leaves, 3).unwrap();
        assert_eq!(
            verify_pin(Some(&pin), &new, Some(&proof)).unwrap(),
            PinStatus::Advanced
        );
    }

    #[test]
    fn advanced_pin_rejects_tampered_proof() {
        let old = snapshot(3, Some(Hash::of(b"e2")));
        let pin = Pin::from(old);
        let new = snapshot(6, Some(Hash::of(b"e5")));
        let leaves: Vec<Hash> = (0..6)
            .map(|i| Hash::of(format!("e{i}").as_bytes()))
            .collect();
        let mut proof = consistency::consistency_proof(&leaves, 3).unwrap();
        proof.old_root = Hash::of(b"other-prefix");
        assert!(
            matches!(
                verify_pin(Some(&pin), &new, Some(&proof)),
                Err(ViewError::Equivocation(_))
            ),
            "旧根被换掉必须拒绝"
        );
    }

    #[test]
    fn advanced_pin_rejects_foreign_valid_proof() {
        // 另一条历史的 3 叶前缀证明本身能验过，但它不是本 pin 的根；必须靠 old_root 绑定拦住。
        let old_leaves: Vec<Hash> = (0..3)
            .map(|i| Hash::of(format!("a{i}").as_bytes()))
            .collect();
        let old_head = *old_leaves.last().unwrap();
        let old = Snapshot {
            height: 3,
            head: Some(old_head),
            root: checkpoint::merkle_root(&old_leaves),
            tip: None,
        };
        let pin = Pin::from(old);
        let new_height = 6;
        let new_leaves: Vec<Hash> = (0..new_height)
            .map(|i| Hash::of(format!("b{i}").as_bytes()))
            .collect();
        let new = Snapshot {
            height: new_height,
            head: new_leaves.last().copied(),
            root: checkpoint::merkle_root(&new_leaves),
            tip: None,
        };
        let proof = consistency::consistency_proof(&new_leaves, 3).unwrap();
        assert!(consistency::verify_consistency(&proof).unwrap());
        assert!(
            matches!(
                verify_pin(Some(&pin), &new, Some(&proof)),
                Err(ViewError::Equivocation(_))
            ),
            "外来但自洽的前缀证明必须因旧根不符被拒"
        );
    }

    #[test]
    fn first_pin_is_tofu() {
        assert_eq!(
            verify_pin(None, &snapshot(1, Some(Hash::of(b"e0"))), None).unwrap(),
            PinStatus::First
        );
    }

    #[test]
    fn signed_view_roundtrips_and_rejects_tampering() {
        let key = KeyFile::generate().unwrap();
        let view = snapshot(3, Some(Hash::of(b"e2")));
        let signature = ViewSignature::sign(&key, "main", &view).unwrap();
        assert_eq!(signature.key_id, key.key_id);
        let json = signature.to_json();
        let parsed = ViewSignature::from_json(&json).unwrap();
        parsed.verify("main", &view).unwrap();

        let mut bad = json.clone();
        bad["signature"] = json!("00".repeat(crate::signing::SIGNATURE_LEN));
        assert!(
            ViewSignature::from_json(&bad)
                .unwrap()
                .verify("main", &view)
                .is_err()
        );
        parsed.verify("main", &snapshot(4, None)).unwrap_err();
        parsed.verify("other", &view).unwrap_err();

        let mut unknown = json;
        unknown["extra"] = json!(1);
        assert!(matches!(
            ViewSignature::from_json(&unknown),
            Err(ViewError::Bad(_))
        ));
        let mut wrong_id = signature.to_json();
        wrong_id["key_id"] = json!("ed25519:dead");
        assert!(matches!(
            ViewSignature::from_json(&wrong_id),
            Err(ViewError::Bad(_))
        ));
    }

    #[test]
    fn pinned_signer_must_not_change_or_disappear() {
        let key1 = KeyFile::generate().unwrap();
        let key2 = KeyFile::generate().unwrap();
        let view = snapshot(3, Some(Hash::of(b"e2")));
        let sig1 = ViewSignature::sign(&key1, "main", &view).unwrap();
        let sig2 = ViewSignature::sign(&key2, "main", &view).unwrap();
        let mut pin = Pin::from(view.clone());
        pin.signer = Some(key1.key_id.clone());
        pin.signer_key = Some(key1.public.clone());

        verify_view_signature(Some(&pin), "main", &view, Some(&sig1)).unwrap();
        assert!(matches!(
            verify_view_signature(Some(&pin), "main", &view, Some(&sig2)),
            Err(ViewError::SignerChanged { .. })
        ));
        assert!(matches!(
            verify_view_signature(Some(&pin), "main", &view, None),
            Err(ViewError::Unsigned { .. })
        ));
        // 无签名的旧 pin 允许升级到签名视图；这是单向收紧，不是静默放松。
        let pin = Pin::from(view.clone());
        verify_view_signature(Some(&pin), "main", &view, Some(&sig1)).unwrap();
    }
}
