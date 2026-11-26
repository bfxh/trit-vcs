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
use crate::repo::{Repo, RepoError};
use crate::sync;

pub const SCHEMA: &str = "trit-view-v1";
pub const MAX_PIN_PROOF_HEIGHT: usize = 1_000_000;

/// 服务端在某一刻的 journal 视图 + 某个 ref 的 tip。
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
}

impl From<Snapshot> for Pin {
    fn from(snapshot: Snapshot) -> Self {
        Self {
            height: snapshot.height,
            head: snapshot.head,
            root: snapshot.root,
            tip: snapshot.tip,
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
        })
    }

    pub fn from_json(value: &Value) -> Result<Self, ViewError> {
        let object = value
            .as_object()
            .ok_or_else(|| ViewError::Bad("pin 不是 JSON 对象".to_string()))?;
        for key in object.keys() {
            if !matches!(key.as_str(), "height" | "head" | "root" | "tip") {
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
        Ok(Self {
            height,
            head,
            root,
            tip,
        })
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
}

impl ViewError {
    pub fn kind(&self) -> &'static str {
        match self {
            ViewError::Bad(_) => "view_bad",
            ViewError::Rollback { .. } => "remote_rollback",
            ViewError::Equivocation(_) => "remote_equivocation",
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
        return match Snapshot::from_evidence(view) {
            Ok(snapshot) => Ok(Some(Pin::from(snapshot))),
            Err(err) => Err(err),
        };
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

/// audit 事件里 `view` 的形态：快照 + 上一次 pin（可选）+ 对账结论。
pub fn evidence_json(snapshot: &Snapshot, pin: Option<&Pin>, status: PinStatus) -> Value {
    let mut view = snapshot.to_json();
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
}
