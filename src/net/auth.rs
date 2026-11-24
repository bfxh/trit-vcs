//! 鉴权失败记账：把“谁在哪个入口被 401”落进中央仓的哈希链，但不记 token/请求头。
//!
//! 只记带 `Authorization` 的失败与 `POST /v1/publish` 的失败；裸健康探针不进账，
//! 避免扫描器把账本刷爆。

use std::sync::Arc;

use super::{Request, State};

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn attempt_should_be_logged(request: &Request) -> bool {
    request.headers.contains_key("authorization")
        || (request.method == "POST" && request.path == "/v1/publish")
}

pub(super) fn record_denied(state: &Arc<State>, request: &Request, reason: &str) {
    let Ok(mut repo) = state.repo.lock() else {
        eprintln!("trit-vcs: 鉴权拒绝事件无法落账：服务器仓库锁中毒");
        return;
    };
    let at_ms = wall_ms();
    let Ok(_guard) = repo.lock_state() else {
        eprintln!("trit-vcs: 鉴权拒绝事件无法落账：仓库状态锁不可用");
        return;
    };
    let state_before = match repo.state_digest() {
        Ok(digest) => digest.to_hex(),
        Err(err) => {
            eprintln!("trit-vcs: 鉴权拒绝事件无法落账：状态摘要失败：{err}");
            return;
        }
    };
    let state_after = state_before.clone();
    if let Err(err) = repo.append_audit_locked(
        "auth",
        serde_json::json!({
            "action": "auth",
            "decision": "denied",
            "reason": reason,
            "method": request.method,
            "path": request.path,
            "status": 401,
            "state_before": state_before,
            "state_after": state_after,
        }),
        at_ms,
    ) {
        eprintln!("trit-vcs: 鉴权拒绝事件无法落账：{err}");
    }
}
