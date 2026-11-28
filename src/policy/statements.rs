//! v5/v6 策略签名规范载荷：角色阈值、主体计票与变更原因/工单。

use std::collections::BTreeMap;

use serde::Serialize;

use crate::repo::RepoError;

use super::{POLICY_SCHEMA_V5, POLICY_SCHEMA_V6, Policy};

/// 每角色最低签名策略的规范字节。`policy_role_thresholds` 只保存大于 1 的角色；
/// 没写的角色仍按 1 个签名覆盖，字段顺序固定便于审计复算。
#[derive(Serialize)]
struct PolicyStatementV5<'a> {
    schema: &'static str,
    action: &'static str,
    session: &'a str,
    require_witness: bool,
    require_intent: bool,
    require_signed_claims: bool,
    require_signed_witness: bool,
    require_signed_policy: bool,
    policy_threshold: u8,
    policy_roles: &'a [String],
    policy_role_thresholds: &'a BTreeMap<String, u8>,
    policy_principal_quorum: bool,
    previous_policy_hash: Option<&'a str>,
    policy_hash: &'a str,
    signed_at_ms: u64,
    key_id: &'a str,
}

pub(crate) fn policy_statement_v5_bytes(
    session: &str,
    policy: &Policy,
    previous_policy_hash: Option<&str>,
    policy_hash: &str,
    signed_at_ms: u64,
    key_id: &str,
) -> Result<Vec<u8>, RepoError> {
    serde_json::to_vec(&PolicyStatementV5 {
        schema: POLICY_SCHEMA_V5,
        action: "set",
        session,
        require_witness: policy.require_witness,
        require_intent: policy.require_intent,
        require_signed_claims: policy.require_signed_claims,
        require_signed_witness: policy.require_signed_witness,
        require_signed_policy: policy.require_signed_policy,
        policy_threshold: policy.policy_threshold,
        policy_roles: &policy.policy_roles,
        policy_role_thresholds: &policy.policy_role_thresholds,
        policy_principal_quorum: policy.policy_principal_quorum,
        previous_policy_hash,
        policy_hash,
        signed_at_ms,
        key_id,
    })
    .map_err(|err| RepoError::BadHead(format!("策略签名载荷编码失败：{err}")))
}

/// 策略变更原因/工单的规范字节。v6 固定包含角色阈值、主体计票与原因/工单，
/// 即使为空也显式编码，避免审计字段缺失时误用低版本载荷。
#[derive(Serialize)]
struct PolicyStatementV6<'a> {
    schema: &'static str,
    action: &'static str,
    session: &'a str,
    require_witness: bool,
    require_intent: bool,
    require_signed_claims: bool,
    require_signed_witness: bool,
    require_signed_policy: bool,
    require_policy_reason: bool,
    policy_threshold: u8,
    policy_roles: &'a [String],
    policy_role_thresholds: &'a BTreeMap<String, u8>,
    policy_principal_quorum: bool,
    policy_reason: &'a str,
    policy_ticket: Option<&'a str>,
    previous_policy_hash: Option<&'a str>,
    policy_hash: &'a str,
    signed_at_ms: u64,
    key_id: &'a str,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn policy_statement_v6_bytes(
    session: &str,
    policy: &Policy,
    reason: &str,
    ticket: Option<&str>,
    previous_policy_hash: Option<&str>,
    policy_hash: &str,
    signed_at_ms: u64,
    key_id: &str,
) -> Result<Vec<u8>, RepoError> {
    serde_json::to_vec(&PolicyStatementV6 {
        schema: POLICY_SCHEMA_V6,
        action: "set",
        session,
        require_witness: policy.require_witness,
        require_intent: policy.require_intent,
        require_signed_claims: policy.require_signed_claims,
        require_signed_witness: policy.require_signed_witness,
        require_signed_policy: policy.require_signed_policy,
        require_policy_reason: policy.require_policy_reason,
        policy_threshold: policy.policy_threshold,
        policy_roles: &policy.policy_roles,
        policy_role_thresholds: &policy.policy_role_thresholds,
        policy_principal_quorum: policy.policy_principal_quorum,
        policy_reason: reason,
        policy_ticket: ticket,
        previous_policy_hash,
        policy_hash,
        signed_at_ms,
        key_id,
    })
    .map_err(|err| RepoError::BadHead(format!("策略签名载荷编码失败：{err}")))
}
