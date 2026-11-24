//! `claim_signature` 事件：重建认领声明，核对操作、状态、信任与 Ed25519 签名。

use serde_json::Value;

use super::{AuditIssue, parse_hash};
use crate::claims::signing::{ClaimStatement, EVENT_KIND, SCHEMA};
use crate::gate::ClaimSpec;
use crate::journal::Event;
use crate::keys::public_key_id;
use crate::repo::Repo;
use crate::signing;

pub(super) fn check_claim_event(
    events: &[Event],
    index: usize,
    event: &Event,
    require_signed_claims: bool,
    issues: &mut Vec<AuditIssue>,
) {
    let signed = event.payload.get("signed").and_then(Value::as_bool);
    if require_signed_claims && signed != Some(true) {
        missing(issues, event, "当时策略要求认领变更签名，但事件未标记已签");
        return;
    }
    if signed != Some(true) {
        return;
    }
    let Some(operation) = event.payload.get("operation").and_then(Value::as_str) else {
        missing(issues, event, "标记已签但缺 operation");
        return;
    };
    let end = events
        .iter()
        .skip(index + 1)
        .position(|candidate| {
            candidate.kind == "op_result"
                && candidate.payload.get("begin_hash").and_then(Value::as_str) == Some(operation)
        })
        .map(|offset| index + 1 + offset)
        .unwrap_or(events.len());
    let claim_hash = event.hash.to_hex();
    let has_signature = events[index + 1..end].iter().any(|candidate| {
        candidate.kind == EVENT_KIND
            && candidate.payload.get("operation").and_then(Value::as_str) == Some(operation)
            && candidate.payload.get("claim_event").and_then(Value::as_str)
                == Some(claim_hash.as_str())
    });
    if !has_signature {
        missing(
            issues,
            event,
            "标记已签但收口前没有 claim_signature sidecar",
        );
    }
}

fn missing(issues: &mut Vec<AuditIssue>, event: &Event, detail: &str) {
    issues.push(AuditIssue::new(
        "claim_signature_missing",
        format!("第 {} 条 {}{detail}", event.seq, event.kind),
    ));
}

pub(super) fn check_claim_signature(
    repo: &Repo,
    events: &[Event],
    index: usize,
    event: &Event,
    issues: &mut Vec<AuditIssue>,
) {
    let payload = &event.payload;
    let Some(operation) = parse_hash(payload.get("operation")) else {
        bad(issues, event, "缺合法 operation");
        return;
    };
    let Some(action) = text(payload, "action") else {
        bad(issues, event, "缺 action");
        return;
    };
    if !matches!(action, "claim_add" | "claim_release") {
        bad(issues, event, "action 不是 claim_add/claim_release");
        return;
    }
    if payload.get("schema").and_then(Value::as_str) != Some(SCHEMA) {
        bad(issues, event, "schema 不是认领签名 v1");
        return;
    }
    if payload.get("algorithm").and_then(Value::as_str) != Some("ed25519") {
        bad(issues, event, "algorithm 不是 ed25519");
        return;
    }
    let Some(claim_hash) = parse_hash(payload.get("claim_event")) else {
        bad(issues, event, "缺合法 claim_event");
        return;
    };
    let Some(key_id) = text(payload, "key_id") else {
        bad(issues, event, "缺 key_id");
        return;
    };
    let Some(principal) = text(payload, "principal") else {
        bad(issues, event, "缺 principal");
        return;
    };
    let Some(owner) = text(payload, "owner") else {
        bad(issues, event, "缺 owner");
        return;
    };
    let Some(signature) = text(payload, "signature") else {
        bad(issues, event, "缺 signature");
        return;
    };
    let Some(signed_at) = payload.get("signed_at_ms").and_then(Value::as_u64) else {
        bad(issues, event, "缺 signed_at_ms");
        return;
    };
    let Some(begin) = events
        .iter()
        .find(|candidate| candidate.hash == operation && candidate.kind == "op_begin")
    else {
        operation_bad(issues, event, "operation 没有指向 op_begin");
        return;
    };
    let Some(claim_event) = events.iter().find(|candidate| candidate.hash == claim_hash) else {
        operation_bad(issues, event, "claim_event 不存在");
        return;
    };
    if begin.seq >= claim_event.seq || claim_event.seq >= event.seq {
        operation_bad(issues, event, "op_begin/claim/signature 顺序不成立");
        return;
    }
    if begin.payload.get("op").and_then(Value::as_str) != Some(action)
        || claim_event.kind != action
        || claim_event.payload.get("operation").and_then(Value::as_str)
            != Some(operation.to_hex().as_str())
        || claim_event.payload.get("signed").and_then(Value::as_bool) != Some(true)
    {
        operation_bad(issues, event, "签名与认领事件/操作对不上");
        return;
    }
    let Some(before) = parse_hash(begin.payload.get("state_before")) else {
        operation_bad(issues, event, "op_begin 缺 state_before");
        return;
    };
    let Some(after) = parse_hash(claim_event.payload.get("state_after")) else {
        operation_bad(issues, event, "认领事件缺 state_after");
        return;
    };
    if parse_hash(payload.get("state_before")) != Some(before)
        || parse_hash(payload.get("state_after")) != Some(after)
    {
        bad(issues, event, "签名事件状态与操作前后状态不一致");
        return;
    }
    let Ok(claim) = serde_json::from_value::<ClaimSpec>(
        claim_event
            .payload
            .get("claim")
            .cloned()
            .unwrap_or(Value::Null),
    ) else {
        bad(issues, event, "认领事件缺合法 claim 对象");
        return;
    };
    if claim.owner != owner || !claim_matches_event(&claim, claim_event) {
        bad(issues, event, "签名 claim 与认领事件字段不一致");
        return;
    }
    let Some(result) = events.iter().skip(index + 1).find(|candidate| {
        candidate.kind == "op_result"
            && candidate.payload.get("begin_hash").and_then(Value::as_str)
                == Some(operation.to_hex().as_str())
    }) else {
        operation_bad(issues, event, "签名操作没有 op_result");
        return;
    };
    if result.payload.get("op").and_then(Value::as_str) != Some(action)
        || result.payload.get("status").and_then(Value::as_str) != Some("ok")
    {
        operation_bad(issues, event, "签名操作没有成功收口");
        return;
    }
    if events[..index].iter().any(|candidate| {
        candidate.kind == EVENT_KIND
            && candidate.payload.get("operation").and_then(Value::as_str)
                == Some(operation.to_hex().as_str())
    }) {
        bad(issues, event, "同一认领操作有重复签名");
        return;
    }

    let authorization = match key_authorization_before(events, begin, key_id) {
        KeyAuthorizationState::Trusted(entry) => entry,
        KeyAuthorizationState::Revoked => {
            issues.push(AuditIssue::new(
                "claim_signature_revoked",
                format!("第 {} 条认领操作开始时 key {key_id} 已吊销", event.seq),
            ));
            return;
        }
        KeyAuthorizationState::Missing => {
            issues.push(AuditIssue::new(
                "claim_signature_untrusted",
                format!(
                    "第 {} 条认领操作开始前没有 key add/rotate 信任 {key_id}",
                    event.seq
                ),
            ));
            return;
        }
    };
    if key_revoked_during(events, begin, result, key_id) {
        issues.push(AuditIssue::new(
            "claim_signature_revoked",
            format!(
                "第 {} 条认领操作收口前 key {key_id} 被吊销或轮换",
                event.seq
            ),
        ));
        return;
    }

    let keys = match repo.keys() {
        Ok(keys) => keys,
        Err(err) => {
            issues.push(AuditIssue::new(
                "claim_signature_untrusted",
                format!("第 {} 条认领签名读不到信任表：{err}", event.seq),
            ));
            return;
        }
    };
    let Some(entry) = keys.keys.get(key_id) else {
        issues.push(AuditIssue::new(
            "claim_signature_untrusted",
            format!("第 {} 条认领签名的 key {key_id} 不在信任表", event.seq),
        ));
        return;
    };
    let public = match authorization.public.as_deref() {
        Some(public) => {
            if entry.public_key.as_deref() != Some(public) {
                issues.push(AuditIssue::new(
                    "claim_signature_untrusted",
                    format!("第 {} 条认领签名的 key 公钥与信任事件不一致", event.seq),
                ));
                return;
            }
            public
        }
        None => {
            let Some(public) = entry.public_key.as_deref() else {
                issues.push(AuditIssue::new(
                    "claim_signature_untrusted",
                    format!("第 {} 条认领签名的 key {key_id} 没有公钥", event.seq),
                ));
                return;
            };
            public
        }
    };
    let public_bytes = match signing::public_key_bytes(public) {
        Ok(bytes) => bytes,
        Err(err) => {
            issues.push(AuditIssue::new(
                "claim_signature_untrusted",
                format!("第 {} 条认领签名的公钥不合法：{err}", event.seq),
            ));
            return;
        }
    };
    if public_key_id(&public_bytes) != key_id {
        issues.push(AuditIssue::new(
            "claim_signature_untrusted",
            format!("第 {} 条认领签名的 key_id 与公钥指纹不符", event.seq),
        ));
        return;
    }
    if entry.principal != authorization.principal
        || entry.role != authorization.role
        || authorization.role != "author"
        || claim.owner != principal
        || principal != authorization.principal
    {
        issues.push(AuditIssue::new(
            "claim_signature_untrusted",
            format!(
                "第 {} 条认领签名的 principal/role/owner 授权关系不成立",
                event.seq
            ),
        ));
        return;
    }
    if let Some(revoked_at) = entry.revoked_at_ms
        && signed_at > revoked_at
    {
        issues.push(AuditIssue::new(
            "claim_signature_revoked",
            format!(
                "第 {} 条认领签名时 key {key_id} 已吊销（{} > {}）",
                event.seq, signed_at, revoked_at
            ),
        ));
        return;
    }
    if parse_hash(result.payload.get("state_after")) != Some(after) {
        operation_bad(issues, event, "op_result.state_after 与签名状态不一致");
        return;
    }
    let statement = ClaimStatement {
        schema: SCHEMA,
        action,
        operation: operation.to_hex(),
        claim: &claim,
        state_before: before.to_hex(),
        state_after: after.to_hex(),
        key_id,
        principal,
        owner,
        signed_at_ms: signed_at,
    }
    .to_bytes();
    let statement = match statement {
        Ok(statement) => statement,
        Err(err) => {
            issues.push(AuditIssue::new(
                "claim_signature_invalid",
                format!("第 {} 条认领声明重建失败：{err}", event.seq),
            ));
            return;
        }
    };
    if let Err(err) = signing::verify_signature(public, signature, &statement) {
        issues.push(AuditIssue::new(
            "claim_signature_invalid",
            format!("第 {} 条认领签名验不过：{err}", event.seq),
        ));
    }
}

struct KeyAuthorization {
    principal: String,
    role: String,
    public: Option<String>,
}

enum KeyAuthorizationState {
    Trusted(KeyAuthorization),
    Revoked,
    Missing,
}

fn key_authorization_before(
    events: &[Event],
    begin: &Event,
    key_id: &str,
) -> KeyAuthorizationState {
    let mut state = KeyAuthorizationState::Missing;
    for event in events.iter().filter(|event| event.seq < begin.seq) {
        if event.kind != "key" {
            continue;
        }
        let action = event.payload.get("action").and_then(Value::as_str);
        let event_key = event.payload.get("key_id").and_then(Value::as_str);
        let revoked = match action {
            Some("revoke") => event_key == Some(key_id),
            Some("rotate") => {
                event.payload.get("old_key_id").and_then(Value::as_str) == Some(key_id)
            }
            _ => false,
        };
        if revoked {
            state = KeyAuthorizationState::Revoked;
        } else if matches!(action, Some("add" | "rotate")) && event_key == Some(key_id) {
            let Some(principal) = event.payload.get("principal").and_then(Value::as_str) else {
                state = KeyAuthorizationState::Missing;
                continue;
            };
            let Some(role) = event.payload.get("role").and_then(Value::as_str) else {
                state = KeyAuthorizationState::Missing;
                continue;
            };
            let public = if action == Some("rotate") {
                event.payload.get("new_public").and_then(Value::as_str)
            } else {
                event.payload.get("public_key").and_then(Value::as_str)
            };
            state = KeyAuthorizationState::Trusted(KeyAuthorization {
                principal: principal.to_string(),
                role: role.to_string(),
                public: public.map(str::to_string),
            });
        }
    }
    state
}

fn key_revoked_during(events: &[Event], begin: &Event, result: &Event, key_id: &str) -> bool {
    events.iter().any(|event| {
        event.seq > begin.seq
            && event.seq < result.seq
            && event.kind == "key"
            && (event.payload.get("action").and_then(Value::as_str) == Some("revoke")
                && event.payload.get("key_id").and_then(Value::as_str) == Some(key_id)
                || event.payload.get("action").and_then(Value::as_str) == Some("rotate")
                    && event.payload.get("old_key_id").and_then(Value::as_str) == Some(key_id))
    })
}

fn claim_matches_event(claim: &ClaimSpec, event: &Event) -> bool {
    let payload = &event.payload;
    payload.get("id").and_then(Value::as_str) == Some(claim.id.as_str())
        && payload.get("owner").and_then(Value::as_str) == Some(claim.owner.as_str())
        && payload.get("paths").and_then(Value::as_u64) == Some(claim.paths.len() as u64)
        && payload.get("acquired_at").and_then(Value::as_u64) == Some(claim.acquired_at)
        && payload.get("expires_at").and_then(Value::as_u64) == Some(claim.expires_at)
        && payload
            .get("path_list")
            .and_then(Value::as_array)
            .is_some_and(|paths| {
                paths
                    .iter()
                    .map(|path| path.as_str().map(str::to_string))
                    .collect::<Option<Vec<_>>>()
                    == Some(claim.paths.clone())
            })
}

fn text<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
}

fn bad(issues: &mut Vec<AuditIssue>, event: &Event, detail: &str) {
    issues.push(AuditIssue::new(
        "claim_signature_bad",
        format!("第 {} 条认领签名{detail}", event.seq),
    ));
}

fn operation_bad(issues: &mut Vec<AuditIssue>, event: &Event, detail: &str) {
    issues.push(AuditIssue::new(
        "claim_signature_operation",
        format!("第 {} 条认领签名{detail}", event.seq),
    ));
}
