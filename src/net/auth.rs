//! 鉴权记账：成功与失败都带服务端生成的 request id；token 与请求头不落账。
//!
//! 只记带 `Authorization` 的失败与 `POST /v1/publish` 的失败；裸健康探针不进账，
//! 避免扫描器把账本刷爆。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{Request, State};
use crate::hash::Hash;

static NEXT_REQUEST: AtomicU64 = AtomicU64::new(0);

fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub(super) fn request_id() -> String {
    let counter = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
    let now = wall_ms();
    Hash::of(format!("{}:{now}:{counter}", std::process::id()).as_bytes()).to_hex()
}

/// 逐个 token 常量时间比较；全部扫完再返回，避免匹配位置成为额外时序信号。
/// 命中后主体取该条目的显式 actor，否则退回 `serve --actor` 的全局身份。
pub(super) fn authenticate(
    headers: &BTreeMap<String, String>,
    state: &Arc<State>,
) -> Option<String> {
    let token = super::bearer_token(headers)?;
    let mut matched = None;
    for binding in &state.tokens {
        if super::ct_eq(token.as_bytes(), binding.token.as_bytes()) {
            matched = Some(
                binding
                    .actor
                    .clone()
                    .or_else(|| state.actor.clone())
                    .unwrap_or_else(|| "bearer:unidentified".to_string()),
            );
        }
    }
    matched
}

pub(super) fn attempt_should_be_logged(request: &Request) -> bool {
    request.headers.contains_key("authorization")
        || (request.method == "POST" && request.path == "/v1/publish")
}

pub(super) fn record_denied(state: &Arc<State>, request: &Request, reason: &str) {
    record(state, request, "denied", Some(reason));
}

pub(super) fn record_allowed(state: &Arc<State>, request: &Request) {
    record(state, request, "allowed", None);
}

fn record(state: &Arc<State>, request: &Request, decision: &str, reason: Option<&str>) {
    let Ok(mut repo) = state.repo.lock() else {
        eprintln!("trit-vcs: 鉴权事件无法落账：服务器仓库锁中毒");
        return;
    };
    let at_ms = wall_ms();
    let Ok(_guard) = repo.lock_state() else {
        eprintln!("trit-vcs: 鉴权事件无法落账：仓库状态锁不可用");
        return;
    };
    let state_before = match repo.state_digest() {
        Ok(digest) => digest.to_hex(),
        Err(err) => {
            eprintln!("trit-vcs: 鉴权事件无法落账：状态摘要失败：{err}");
            return;
        }
    };
    let state_after = state_before.clone();
    let mut payload = serde_json::json!({
        "schema": "trit-auth-v2",
        "action": "auth",
        "decision": decision,
        "method": request.method,
        "path": request.path,
        "request_id": request.request_id,
        "actor": request.actor,
        // 只记 TCP 对端 IP，不记临时端口；反代部署时这里就是反代地址。
        "source": request.source,
        "state_before": state_before,
        "state_after": state_after,
    });
    if let Some(reason) = reason {
        payload["reason"] = serde_json::json!(reason);
        payload["status"] = serde_json::json!(401);
    }
    if let Err(err) = repo.append_audit_locked("auth", payload, at_ms) {
        eprintln!("trit-vcs: 鉴权事件无法落账：{err}");
    }
}
