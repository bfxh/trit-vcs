//! 跨仓同步关联：客户端生成 op_id，服务端回传并核对 request_id。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::hash::Hash;
use crate::journal::Event;
use crate::repo::{Repo, RepoError};

pub(crate) const SCHEMA: &str = "trit-sync-v1";

static NEXT_OP: AtomicU64 = AtomicU64::new(0);

pub(crate) fn new_op_id() -> String {
    let counter = NEXT_OP.fetch_add(1, Ordering::Relaxed);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    Hash::of(format!("sync:{}:{now}:{counter}", std::process::id()).as_bytes()).to_hex()
}

pub(crate) fn valid_op_id(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub(crate) fn commit_evidence(repo: &Repo, commit: &Hash) -> Result<Vec<Hash>, RepoError> {
    let commit = repo.commit_at(commit)?;
    Ok([commit.claim_set, commit.witness]
        .into_iter()
        .flatten()
        .collect())
}

pub(crate) struct SyncSuccess<'a> {
    pub(crate) action: &'a str,
    pub(crate) op_id: &'a str,
    pub(crate) transport: &'a str,
    pub(crate) side: &'a str,
    pub(crate) request_id: Option<&'a str>,
    pub(crate) actor: Option<&'a str>,
    pub(crate) name: &'a str,
    pub(crate) commit: Hash,
    pub(crate) stage: &'a str,
    pub(crate) detail: Value,
}

impl SyncSuccess<'_> {
    fn payload(&self) -> Value {
        let mut payload = self.detail.clone();
        payload["schema"] = json!(SCHEMA);
        payload["action"] = json!(self.action);
        payload["op_id"] = json!(self.op_id);
        payload["transport"] = json!(self.transport);
        payload["side"] = json!(self.side);
        payload["request_id"] = json!(self.request_id);
        payload["actor"] = json!(self.actor);
        payload["name"] = json!(self.name);
        payload["commit"] = json!(self.commit.to_hex());
        payload["stage"] = json!(self.stage);
        payload
    }
}

pub(crate) fn append_locked(
    repo: &mut Repo,
    success: &SyncSuccess<'_>,
    state_before: Hash,
    at_ms: u64,
) -> Result<Event, RepoError> {
    let mut payload = success.payload();
    payload["state_before"] = json!(state_before.to_hex());
    payload["state_after"] = json!(repo.state_digest()?.to_hex());
    repo.append_audit_locked(success.action, payload, at_ms)
}

pub(crate) fn append(
    repo: &mut Repo,
    success: &SyncSuccess<'_>,
    at_ms: u64,
) -> Result<Event, RepoError> {
    let _guard = repo.lock_state()?;
    let before = repo.state_digest()?;
    append_locked(repo, success, before, at_ms)
}

fn wall_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

pub(crate) fn now_ms() -> u64 {
    wall_ms()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_ids_are_hash_shaped_and_unique() {
        let ids: std::collections::HashSet<_> = (0..1_000).map(|_| new_op_id()).collect();
        assert_eq!(ids.len(), 1_000);
        assert!(ids.iter().all(|id| valid_op_id(id)));
    }

    #[test]
    fn op_id_validation_is_exact_hex_without_trimming() {
        let id = Hash::of(b"op").to_hex();
        assert!(valid_op_id(&id));
        assert!(valid_op_id(&id.to_uppercase()));
        for raw in [
            format!(" {id}"),
            format!("{id} "),
            format!("\r\n{id}\r\n"),
            format!("{id}\0"),
            "broken".to_string(),
        ] {
            assert!(!valid_op_id(&raw), "{raw:?}");
        }
    }
}
