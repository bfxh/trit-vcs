//! `publish` 在进入仓库锁之前就能判死的请求形状错误：也要落 `deny`，
//! 否则“被拒但没账”会在真正收对象之前发生。

use std::sync::Arc;

use super::{Request, State};
use crate::repo::Repo;

pub(super) fn record_publish_rejected(
    state: &Arc<State>,
    request: &Request,
    name: Option<&str>,
    tip: Option<&str>,
    status: u16,
    reason: &str,
    message: &str,
) {
    let Ok(mut repo) = state.repo.lock() else {
        return;
    };
    repo.record_deny(
        "publish",
        reason,
        message,
        serde_json::json!({
            "ref": name,
            "tip": tip,
            "method": request.method,
            "path": request.path,
            "request_id": request.request_id,
            "op_id": request.valid_op_id(),
            "actor": request.actor,
            "length": request.length,
            "status": status,
        }),
    );
}

pub(super) fn record_pull_rejected(
    state: &Arc<State>,
    request: &Request,
    name: Option<&str>,
    prefix: Option<&str>,
    status: u16,
    reason: &str,
    message: &str,
) {
    let Ok(mut repo) = state.repo.lock() else {
        return;
    };
    record_pull_in_repo(&mut repo, request, name, prefix, status, reason, message);
}

pub(super) fn record_pull_in_repo(
    repo: &mut Repo,
    request: &Request,
    name: Option<&str>,
    prefix: Option<&str>,
    status: u16,
    reason: &str,
    message: &str,
) {
    repo.record_deny(
        "pull",
        reason,
        message,
        serde_json::json!({
            "ref": name,
            "prefix": prefix,
            "method": request.method,
            "path": request.path,
            "request_id": request.request_id,
            "op_id": request.valid_op_id(),
            "actor": request.actor,
            "status": status,
        }),
    );
}

/// 视图请求的入口拒绝：坏 ref 名/坏的 pin 查询同样要留账，不能只在响应里报 400。
pub(super) fn record_view_rejected(
    state: &Arc<State>,
    request: &Request,
    name: Option<&str>,
    status: u16,
    reason: &str,
    message: &str,
) {
    let Ok(mut repo) = state.repo.lock() else {
        return;
    };
    repo.record_deny(
        "view",
        reason,
        message,
        serde_json::json!({
            "ref": name,
            "method": request.method,
            "path": request.path,
            "request_id": request.request_id,
            "op_id": request.valid_op_id(),
            "actor": request.actor,
            "status": status,
        }),
    );
}
