//! `GET /v1/pull` 的发送面：从中央仓算计划、写响应头、流式发送对象。
//!
//! 拒绝（缺 ref、未知 ref、清单/历史不完整）也在这里落 `deny`；
//! 一旦 200 头已发出，只剩流中断，不再算“业务拒绝”。

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

use super::deny;
use super::{NetError, Request, State, respond_json, respond_remote};

pub(super) fn handle(
    stream: &mut TcpStream,
    request: &Request,
    state: &Arc<State>,
) -> Result<(), NetError> {
    let op_id = match request.require_op_id() {
        Ok(Some(op_id)) => op_id,
        Ok(None) => crate::sync::new_op_id(),
        Err(err) => {
            deny::record_pull_rejected(
                state,
                request,
                None,
                None,
                err.status(),
                err.kind(),
                &err.to_string(),
            );
            return respond_json(
                stream,
                err.status(),
                "bad_request",
                &err.to_string(),
                &request.correlation_headers(),
            );
        }
    };
    let Some(name) = request.query.get("ref") else {
        deny::record_pull_rejected(
            state,
            request,
            None,
            None,
            400,
            "missing_ref",
            "pull 需要 ?ref=NAME",
        );
        return respond_json(
            stream,
            400,
            "bad_request",
            "pull 需要 ?ref=NAME",
            &request.correlation_headers(),
        );
    };
    let prefix = request
        .query
        .get("prefix")
        .map(String::as_str)
        .filter(|p| !p.is_empty());
    let mut repo = state.repo.lock().expect("服务器仓库锁中毒");
    let plan = match crate::remote::pull_plan(&repo, name, prefix) {
        Ok(plan) => plan,
        Err(err) => {
            deny::record_pull_in_repo(
                &mut repo,
                request,
                Some(name),
                prefix,
                err.status(),
                err.kind(),
                &err.to_string(),
            );
            return respond_remote(stream, &err, request);
        }
    };
    let total = match plan.body.byte_len(repo.store()) {
        Ok(total) => total,
        Err(err) => {
            let err: crate::remote::RemoteError = err.into();
            deny::record_pull_in_repo(
                &mut repo,
                request,
                Some(name),
                prefix,
                err.status(),
                err.kind(),
                &err.to_string(),
            );
            return respond_remote(stream, &err, request);
        }
    };
    let head = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/octet-stream\r\ncontent-length: {total}\r\n\
         x-trit-request-id: {}\r\nx-trit-op-id: {op_id}\r\nx-trit-ref: {name}\r\nx-trit-tip: {}\r\nx-trit-manifest: {}\r\nx-trit-files: {}\r\n\
         x-trit-objects: {}\r\nconnection: close\r\n\r\n",
        request.request_id,
        plan.tip.to_hex(),
        plan.manifest.to_hex(),
        plan.files,
        plan.body.count()
    );
    stream.write_all(head.as_bytes())?;
    if let Err(err) = plan.body.write(repo.store(), &mut *stream) {
        // 头已经发出去了，只能在流上直接断；客户端会读到截断并判红。
        return Err(NetError::Wire(err.to_string()));
    }
    crate::sync::append(
        &mut repo,
        &crate::sync::SyncSuccess {
            action: "pull",
            op_id: &op_id,
            transport: "http",
            side: "central",
            request_id: Some(&request.request_id),
            actor: request.actor.as_deref(),
            name,
            commit: plan.tip,
            stage: "response_sent",
            detail: serde_json::json!({"prefix": prefix, "files": plan.files}),
        },
        crate::sync::now_ms(),
    )
    .map_err(|err| NetError::Repo(err.to_string()))?;
    Ok(())
}
