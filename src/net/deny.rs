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
            "status": status,
        }),
    );
}
