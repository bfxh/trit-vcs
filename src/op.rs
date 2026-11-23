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
        let state_before = self.state_digest()?.to_hex();
        Ok(self.journal_mut().append(
            "op_begin",
            json!({
                "op": op,
                "args": args,
                "state_before": state_before,
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
        let state_after = self.state_digest()?.to_hex();
        Ok(self.journal_mut().append(
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
        )?)
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
        let begin = self.begin_operation(op, args, at_ms)?;
        match body(self) {
            Ok(value) => {
                self.finish_operation(&begin, op, "ok", json!({}), at_ms)?;
                Ok(value)
            }
            Err(err) => {
                let _ = self.finish_operation(
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
        self.journal_mut().append(
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
    pub(crate) fn record_gate_denied(&mut self, req: &CommitRequest, err: &RepoError) {
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
}
