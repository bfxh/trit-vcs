//! `GET /v1/view`：把中央仓当前 journal 视图与某个 ref 的 tip 给客户端，
//! 并在客户端带旧 pin 时附上旧前缀到新前缀的一致性证明。
//!
//! 端点只读，不改仓库状态；鉴权仍走 Bearer token，成功/失败鉴权由入口统一落 `auth`。

use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;

use serde_json::{Value, json};

use super::{NetError, Request, State, deny, respond_json_value};
use crate::hash::Hash;
use crate::view::{self, MAX_PIN_PROOF_HEIGHT, Snapshot, ViewSignature};

pub(super) fn handle(
    stream: &mut TcpStream,
    request: &Request,
    state: &Arc<State>,
) -> Result<(), NetError> {
    let Some(name) = request.query.get("ref") else {
        deny::record_view_rejected(
            state,
            request,
            None,
            400,
            "missing_ref",
            "view 需要 ?ref=NAME",
        );
        return respond_json_value(
            stream,
            400,
            &json!({"ok": false, "kind": "bad_request", "message": "view 需要 ?ref=NAME"}),
            &request.correlation_headers(),
        );
    };
    let pin = match parse_pin(&request.query) {
        Ok(pin) => pin,
        Err(message) => {
            deny::record_view_rejected(
                state,
                request,
                Some(name),
                400,
                "bad_view_request",
                &message,
            );
            return respond_json_value(
                stream,
                400,
                &json!({"ok": false, "kind": "bad_request", "message": message}),
                &request.correlation_headers(),
            );
        }
    };
    let repo = state.repo.lock().expect("服务器仓库锁中毒");
    let snapshot = match Snapshot::of(&repo, name) {
        Ok(snapshot) => snapshot,
        Err(err) => {
            let status = if matches!(err, crate::repo::RepoError::BadRefName(_)) {
                400
            } else {
                500
            };
            drop(repo);
            deny::record_view_rejected(
                state,
                request,
                Some(name),
                status,
                "bad_ref",
                &err.to_string(),
            );
            return respond_json_value(
                stream,
                status,
                &json!({"ok": false, "kind": "bad_ref", "message": err.to_string()}),
                &request.correlation_headers(),
            );
        }
    };
    let consistency = match pin {
        None => None,
        Some((from_height, _from_root)) => {
            match view::proof_from(repo.journal().events(), from_height) {
                Ok(proof) => proof,
                Err(err) => {
                    drop(repo);
                    return respond_json_value(
                        stream,
                        500,
                        &json!({"ok": false, "kind": err.kind(), "message": err.to_string()}),
                        &request.correlation_headers(),
                    );
                }
            }
        }
    };
    // 快照/证明已拥有自己的数据，签名不必继续占着中央仓锁。
    drop(repo);
    let signature = match state.view_key.as_ref() {
        None => None,
        Some(key) => match ViewSignature::sign(key, name, &snapshot) {
            Ok(signature) => Some(signature),
            Err(err) => {
                return respond_json_value(
                    stream,
                    500,
                    &json!({"ok": false, "kind": "view_sign_failed", "message": err.to_string()}),
                    &request.correlation_headers(),
                );
            }
        },
    };
    let mut body = snapshot.to_json();
    body["ok"] = json!(true);
    body["ref"] = json!(name);
    body["signature"] = signature
        .as_ref()
        .map(ViewSignature::to_json)
        .unwrap_or(Value::Null);
    body["consistency"] = consistency
        .map(|proof| serde_json::to_value(proof).unwrap_or(Value::Null))
        .unwrap_or(Value::Null);

    let bytes = serde_json::to_vec(&body).map_err(|err| NetError::Repo(err.to_string()))?;
    stream.write_all(
        format!(
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
             x-trit-request-id: {}\r\nconnection: close\r\n\r\n",
            bytes.len(),
            request.request_id
        )
        .as_bytes(),
    )?;
    stream.write_all(&bytes)?;
    Ok(())
}

/// `from_height` 与 `from_root` 必须成对出现；返回旧高度与旧根。
fn parse_pin(
    query: &std::collections::BTreeMap<String, String>,
) -> Result<Option<(usize, Hash)>, String> {
    let height = query.get("from_height");
    let root = query.get("from_root");
    match (height, root) {
        (None, None) => Ok(None),
        (Some(height), Some(root)) => {
            let height = height
                .parse::<u64>()
                .ok()
                .and_then(|raw| usize::try_from(raw).ok())
                .filter(|height| *height <= MAX_PIN_PROOF_HEIGHT)
                .ok_or_else(|| "from_height 不合法".to_string())?;
            let root = Hash::from_hex(root).ok_or_else(|| "from_root 不合法".to_string())?;
            Ok(Some((height, root)))
        }
        _ => Err("from_height 与 from_root 必须成对出现".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn pin_query_requires_both_fields() {
        let mut query = BTreeMap::new();
        assert_eq!(parse_pin(&query).unwrap(), None);
        query.insert("from_height".to_string(), "3".to_string());
        assert!(parse_pin(&query).is_err());
        query.insert("from_root".to_string(), Hash::of(b"r").to_hex());
        assert!(parse_pin(&query).unwrap().is_some());
        query.insert("from_height".to_string(), "x".to_string());
        assert!(parse_pin(&query).is_err());
        query.insert("from_height".to_string(), "1000001".to_string());
        assert!(parse_pin(&query).is_err());
    }
}
