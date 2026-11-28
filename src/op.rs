//! 写前/写后操作协议：把“操作开始”和“操作结果”都变成可审计事件。
//!
//! 这里只定义事件形状与封闭骨架，不决定哪些操作要调用它；具体调用点在
//! `repo` 的 `stage/commit/set_ref/adopt`、`claims` 的 `add/release`。
//! 关键不变量：`op_begin.state_before` 与上一条已知 `state_after` 必须接得上。

use serde_json::{Value, json};

use crate::hash::Hash;
use crate::journal::Event;
use crate::repo::{CommitRequest, Repo, RepoError};

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl Repo {
    /// 写前记录：在任何可能改仓库状态的步骤之前，先把“我要做什么、动手前是什么状态”入链。
    ///
    /// 这让审计从“事后猜有没有漏账”前移到“操作开始就有账”：如果进程死在
    /// `op_begin` 与 `op_result` 之间，至少留下一条开放操作和动手前的状态摘要。
    pub fn begin_operation(
        &mut self,
        op: &str,
        args: Value,
        at_ms: u64,
    ) -> Result<Event, RepoError> {
        let _guard = self.lock_state()?;
        self.begin_operation_locked(op, args, at_ms)
    }

    pub(crate) fn begin_operation_locked(
        &mut self,
        op: &str,
        args: Value,
        at_ms: u64,
    ) -> Result<Event, RepoError> {
        self.recover_txn_locked()?;
        let state_before = self.state_digest()?.to_hex();
        let txn_id = Repo::new_txn_id(&state_before, self.journal().events().len() as u64);
        self.prepare_txn_locked(&txn_id, op, &args, &state_before)?;
        Ok(self.journal_mut().append(
            "op_begin",
            json!({
                "op": op,
                "args": args,
                "state_before": state_before,
                "txn_id": txn_id,
            }),
            at_ms,
        )?)
    }

    /// 写后收口：记录这次操作是成功还是失败，以及落盘后的状态摘要。
    pub fn finish_operation(
        &mut self,
        begin: &Event,
        op: &str,
        status: &str,
        result: Value,
        at_ms: u64,
    ) -> Result<Event, RepoError> {
        let _guard = self.lock_state()?;
        self.finish_operation_locked(begin, op, status, result, at_ms)
    }

    pub(crate) fn finish_operation_locked(
        &mut self,
        begin: &Event,
        op: &str,
        status: &str,
        result: Value,
        at_ms: u64,
    ) -> Result<Event, RepoError> {
        let state_after = self.state_digest()?.to_hex();
        let event = self.journal_mut().append(
            "op_result",
            json!({
                "op": op,
                "begin": begin.seq,
                "begin_hash": begin.hash.to_hex(),
                "status": status,
                "state_after": state_after,
                "result": result,
            }),
            at_ms,
        )?;
        // 快照清不掉不改变已收口的事实；残留 txn 会在下一次持锁写时按
        // “已有 op_result”分支只清目录，不会回滚。
        let _ = self.clear_txn_locked();
        Ok(event)
    }

    pub fn append_audit(
        &mut self,
        kind: &str,
        payload: Value,
        at_ms: u64,
    ) -> Result<Event, RepoError> {
        let _guard = self.lock_state()?;
        self.append_audit_locked(kind, payload, at_ms)
    }

    pub(crate) fn append_audit_locked(
        &mut self,
        kind: &str,
        payload: Value,
        at_ms: u64,
    ) -> Result<Event, RepoError> {
        Ok(self.journal_mut().append(kind, payload, at_ms)?)
    }

    pub(crate) fn with_operation_locked<T>(
        &mut self,
        op: &str,
        args: Value,
        at_ms: u64,
        body: impl FnOnce(&mut Self) -> Result<T, RepoError>,
    ) -> Result<T, RepoError> {
        let _guard = self.lock_state()?;
        self.with_operation(op, args, at_ms, body)
    }

    /// `begin_operation` + 执行 + `finish_operation` 的封闭骨架。
    ///
    /// 失败也落 `op_result`；如果连收口都写不进去（磁盘坏了），原始错误优先返回，
    /// 留下的开放操作由 `audit` 报 `op_open`/`state_drift`，不会静默。
    pub(crate) fn with_operation<T>(
        &mut self,
        op: &str,
        args: Value,
        at_ms: u64,
        body: impl FnOnce(&mut Self) -> Result<T, RepoError>,
    ) -> Result<T, RepoError> {
        let begin = self.begin_operation_locked(op, args, at_ms)?;
        match body(self) {
            Ok(value) => {
                self.finish_operation_locked(&begin, op, "ok", json!({}), at_ms)?;
                Ok(value)
            }
            Err(err) => {
                let _ = self.finish_operation_locked(
                    &begin,
                    op,
                    "failed",
                    json!({"error": err.to_string()}),
                    at_ms,
                );
                Err(err)
            }
        }
    }

    /// 把判据回执落成对象并把摘要写进链；回执本身不改仓库状态。
    pub fn record_accept(
        &mut self,
        receipt: &crate::accept::AcceptReceipt,
    ) -> Result<Hash, RepoError> {
        let bytes = receipt
            .encode()
            .map_err(|err| RepoError::BadHead(format!("回执编码失败：{err}")))?;
        let (digest, _) = self.store.put_chunk(&bytes)?;
        let now = wall_ms();
        self.append_audit(
            "accept",
            json!({
                "receipt": digest.to_hex(),
                "tree": receipt.tree.to_hex(),
                "base": receipt.base.map(|base| base.to_hex()),
                "session": receipt.session,
                "claim_ids": receipt.claim_ids,
                "passed": receipt.passed,
                "at_secs": receipt.at_secs,
            }),
            now,
        )?;
        Ok(digest)
    }

    /// 被提交门拒绝也是一次真实尝试：状态没变，但“谁在什么时候试了什么、为什么被拒”
    /// 必须进链。写不进就保留原始拒绝错误；审计至少能看到 gate 事件缺失导致的语义缺口。
    pub(crate) fn record_gate_denied_locked(&mut self, req: &CommitRequest, err: &RepoError) {
        let at_ms = wall_ms().max(req.now_secs.saturating_mul(1000));
        let state = self.state_digest().ok().map(|digest| digest.to_hex());
        let _ = self.journal_mut().append(
            "gate",
            json!({
                "action": "commit",
                "decision": "denied",
                "reason": crate::remediation::kind(err),
                "message": err.to_string(),
                "session": req.session.clone(),
                "claims": req.claims.len(),
                "state_before": state.clone(),
                "state_after": state,
            }),
            at_ms,
        );
    }

    /// 服务端/远端入口的业务拒绝：鉴权已经通过，但这次写请求因为业务规则没被执行。
    /// 记 `action`/`reason`/`message`/`detail`，不把请求头或 token 抄进账本。
    /// 锁或落账失败只让拒绝保持拒绝，并明确告警；绝不能因此放行写请求。
    pub(crate) fn record_deny(&mut self, action: &str, reason: &str, message: &str, detail: Value) {
        let Ok(_guard) = self.lock_state() else {
            eprintln!("trit-vcs: 拒绝事件无法落账：仓库状态锁不可用（{action}/{reason}）");
            return;
        };
        let state = match self.state_digest() {
            Ok(digest) => digest.to_hex(),
            Err(err) => {
                eprintln!("trit-vcs: 拒绝事件无法落账：状态摘要失败（{action}/{reason}）：{err}");
                return;
            }
        };
        if let Err(err) = self.append_audit_locked(
            "deny",
            json!({
                "action": action,
                "decision": "denied",
                "reason": reason,
                "message": message,
                "detail": detail,
                "state_before": state.clone(),
                "state_after": state,
            }),
            wall_ms(),
        ) {
            eprintln!("trit-vcs: 拒绝事件无法落账（{action}/{reason}）：{err}");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;

    use serde_json::json;

    use super::*;
    use crate::hash::Hash;
    use crate::keys::TrustEntry;
    use crate::repo::Policy;
    use crate::signing::KeyFile;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("trit-vcs-op-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn public_audit_entry_points_respect_state_lock() {
        let root = temp("locked-entry-points");
        let mut repo = Repo::init(&root).unwrap();
        let begin = repo.begin_operation("manual", json!({}), 1_000).unwrap();
        let before = repo.journal().events().len();
        let guard = crate::claims::lock(&root).unwrap();

        assert!(matches!(
            repo.begin_operation("blocked", json!({}), 1_001),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.finish_operation(&begin, "manual", "ok", json!({}), 1_001),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.append_audit("note", json!({}), 1_001),
            Err(RepoError::StateLocked(_))
        ));
        assert_eq!(repo.journal().events().len(), before);

        drop(guard);
        repo.append_audit("note", json!({}), 1_002).unwrap();
        assert_eq!(repo.journal().events().len(), before + 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn repository_state_entry_points_respect_lock() {
        let root = temp("locked-repository-entry-points");
        let mut repo = Repo::init(&root).unwrap();
        let old_key = KeyFile::generate().unwrap();
        let new_key = KeyFile::generate().unwrap();
        repo.add_key(
            TrustEntry {
                key_id: old_key.key_id.clone(),
                principal: "audit:test".to_string(),
                role: "author".to_string(),
                added_at_ms: 1_000,
                public_key: Some(old_key.public.clone()),
                rotated_from: None,
                revoked_at_ms: None,
                revoke_reason: None,
            },
            "audit:test",
            1_000,
        )
        .unwrap();
        let missing_key = root.join("missing.key");
        let _guard = crate::claims::lock(&root).unwrap();

        assert!(matches!(
            repo.set_policy(&Policy::default(), "audit:test", 2_000),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.add_key(
                TrustEntry {
                    key_id: new_key.key_id.clone(),
                    principal: "audit:test".to_string(),
                    role: "author".to_string(),
                    added_at_ms: 2_000,
                    public_key: Some(new_key.public.clone()),
                    rotated_from: None,
                    revoked_at_ms: None,
                    revoke_reason: None,
                },
                "audit:test",
                2_000,
            ),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.revoke_key(&old_key.key_id, "test", "audit:test", 2_000),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.rotate_key(&old_key, &new_key, "test", "audit:test", 2_000),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.sign_commit(&Hash::of(b"missing"), &missing_key, "audit:test", 2_000),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.attest_witness(
                &Hash::of(b"missing"),
                b"{}",
                &missing_key,
                "audit:test",
                2_000,
            ),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.checkpoint(&missing_key, "audit:test", 2_000),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.stage(&BTreeMap::new(), 2),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            repo.commit(CommitRequest::default()),
            Err(RepoError::StateLocked(_))
        ));
        assert!(matches!(
            crate::merge::merge_audited(&mut repo, &Hash::of(b"ours"), &Hash::of(b"theirs"), None,),
            Err(crate::merge::MergeError::Repo(RepoError::StateLocked(_)))
        ));
        drop(_guard);
        let _ = std::fs::remove_dir_all(&root);
    }
}
