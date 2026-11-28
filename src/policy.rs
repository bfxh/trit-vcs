//! 仓库策略的受审计变更：改 `policy.json` 前后都进同一套写前/写后协议。
//!
//! 策略本身只有门禁开关，但它是“谁能提交什么”的依据；手工改文件虽然会被
//! `state_digest` 漂移抓到，却没有一条能说明“谁在什么时候把哪一项打开了”的事件。
//! 这里补上 `policy` 事件，并让 `policy_hash` 与 `state_digest` 使用同一套字节哈希。
//!
//! 可选 Ed25519 签名把“改策略的人”绑到事件：`policy set --sign-key` 会签
//! 旧/新策略摘要、五个开关、阈值、角色集合、每角色最低签名数、session、时间和 key id；
//! `require_signed_policy` 打开后，后续策略变更必须带足够数量、覆盖所需角色且由不同主体批准的策略签名，否则审计判红。

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::hash::Hash;
use crate::repo::{DIR, Repo, RepoError};
use crate::signing::KeyFile;

mod statements;
pub(crate) use statements::{policy_statement_v5_bytes, policy_statement_v6_bytes};

pub(crate) const POLICY_SCHEMA: &str = "trit-policy-v1";
pub(crate) const POLICY_SCHEMA_V2: &str = "trit-policy-v2";
pub(crate) const POLICY_SCHEMA_V3: &str = "trit-policy-v3";
pub(crate) const POLICY_SCHEMA_V4: &str = "trit-policy-v4";
pub(crate) const POLICY_SCHEMA_V5: &str = "trit-policy-v5";
pub(crate) const POLICY_SCHEMA_V6: &str = "trit-policy-v6";
pub const MAX_POLICY_THRESHOLD: u8 = 16;
pub const MAX_POLICY_ROLES: usize = 4;
pub const POLICY_SIGNER_ROLES: &[&str] = &["auditor", "release"];

fn default_policy_threshold() -> u8 {
    1
}

fn default_policy_roles() -> Vec<String> {
    vec!["auditor".to_string()]
}

/// 仓库策略（`.tritvcs/policy.json`）。默认全关：不影响别项目，成熟后逐项目 opt-in。
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub require_witness: bool,
    #[serde(default)]
    pub require_intent: bool,
    #[serde(default)]
    pub require_signed_claims: bool,
    #[serde(default)]
    pub require_signed_witness: bool,
    /// 打开后，后续 `policy` 事件必须有 Ed25519 签名；开启这条的策略变更自身也必须签名。
    #[serde(default)]
    pub require_signed_policy: bool,
    /// 打开后，后续策略变更必须提供非空原因；原因只进事件与签名，不写入 `policy.json`。
    #[serde(default)]
    pub require_policy_reason: bool,
    /// 严格策略需要多少个不同的签名。`0` 视为非法配置。
    #[serde(default = "default_policy_threshold")]
    pub policy_threshold: u8,
    /// 严格策略必须覆盖的角色，每个角色至少一个签名；默认只有 `auditor`。
    #[serde(default = "default_policy_roles")]
    pub policy_roles: Vec<String>,
    /// 阈值按不同主体（principal）而不是不同 key 计数；默认关闭，保持旧事件语义。
    #[serde(default)]
    pub policy_principal_quorum: bool,
    /// 每个策略角色的最低签名数；空表示每个角色只要求 1 个。键必须在 `policy_roles` 中。
    #[serde(default)]
    pub policy_role_thresholds: BTreeMap<String, u8>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            require_witness: false,
            require_intent: false,
            require_signed_claims: false,
            require_signed_witness: false,
            require_signed_policy: false,
            require_policy_reason: false,
            policy_threshold: 1,
            policy_roles: default_policy_roles(),
            policy_principal_quorum: false,
            policy_role_thresholds: BTreeMap::new(),
        }
    }
}

/// 策略签名覆盖的规范字节。字段顺序固定，签名和审计必须用同一份形状。
#[derive(Serialize)]
struct PolicyStatement<'a> {
    schema: &'static str,
    action: &'static str,
    session: &'a str,
    require_witness: bool,
    require_intent: bool,
    require_signed_claims: bool,
    require_signed_witness: bool,
    require_signed_policy: bool,
    previous_policy_hash: Option<&'a str>,
    policy_hash: &'a str,
    signed_at_ms: u64,
    key_id: &'a str,
}

pub(crate) fn policy_statement_bytes(
    session: &str,
    policy: &Policy,
    previous_policy_hash: Option<&str>,
    policy_hash: &str,
    signed_at_ms: u64,
    key_id: &str,
) -> Result<Vec<u8>, RepoError> {
    serde_json::to_vec(&PolicyStatement {
        schema: POLICY_SCHEMA,
        action: "set",
        session,
        require_witness: policy.require_witness,
        require_intent: policy.require_intent,
        require_signed_claims: policy.require_signed_claims,
        require_signed_witness: policy.require_signed_witness,
        require_signed_policy: policy.require_signed_policy,
        previous_policy_hash,
        policy_hash,
        signed_at_ms,
        key_id,
    })
    .map_err(|err| RepoError::BadHead(format!("策略签名载荷编码失败：{err}")))
}

/// 多签策略的规范字节。每个签名者各签一份，`key_id` 与 `signed_at_ms` 是
/// 该签名者自己的值；其余字段必须完全一致，尤其是 `policy_threshold`。
#[derive(Serialize)]
struct PolicyStatementV2<'a> {
    schema: &'static str,
    action: &'static str,
    session: &'a str,
    require_witness: bool,
    require_intent: bool,
    require_signed_claims: bool,
    require_signed_witness: bool,
    require_signed_policy: bool,
    policy_threshold: u8,
    previous_policy_hash: Option<&'a str>,
    policy_hash: &'a str,
    signed_at_ms: u64,
    key_id: &'a str,
}

pub(crate) fn policy_statement_v2_bytes(
    session: &str,
    policy: &Policy,
    previous_policy_hash: Option<&str>,
    policy_hash: &str,
    signed_at_ms: u64,
    key_id: &str,
) -> Result<Vec<u8>, RepoError> {
    serde_json::to_vec(&PolicyStatementV2 {
        schema: POLICY_SCHEMA_V2,
        action: "set",
        session,
        require_witness: policy.require_witness,
        require_intent: policy.require_intent,
        require_signed_claims: policy.require_signed_claims,
        require_signed_witness: policy.require_signed_witness,
        require_signed_policy: policy.require_signed_policy,
        policy_threshold: policy.policy_threshold,
        previous_policy_hash,
        policy_hash,
        signed_at_ms,
        key_id,
    })
    .map_err(|err| RepoError::BadHead(format!("策略签名载荷编码失败：{err}")))
}

/// 混合角色策略的规范字节。`policy_roles` 已按字典序规范化，签名者必须
/// 覆盖每个角色的至少一把 key；阈值仍按不同 key 计数。
#[derive(Serialize)]
struct PolicyStatementV3<'a> {
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
    previous_policy_hash: Option<&'a str>,
    policy_hash: &'a str,
    signed_at_ms: u64,
    key_id: &'a str,
}

pub(crate) fn policy_statement_v3_bytes(
    session: &str,
    policy: &Policy,
    previous_policy_hash: Option<&str>,
    policy_hash: &str,
    signed_at_ms: u64,
    key_id: &str,
) -> Result<Vec<u8>, RepoError> {
    serde_json::to_vec(&PolicyStatementV3 {
        schema: POLICY_SCHEMA_V3,
        action: "set",
        session,
        require_witness: policy.require_witness,
        require_intent: policy.require_intent,
        require_signed_claims: policy.require_signed_claims,
        require_signed_witness: policy.require_signed_witness,
        require_signed_policy: policy.require_signed_policy,
        policy_threshold: policy.policy_threshold,
        policy_roles: &policy.policy_roles,
        previous_policy_hash,
        policy_hash,
        signed_at_ms,
        key_id,
    })
    .map_err(|err| RepoError::BadHead(format!("策略签名载荷编码失败：{err}")))
}

/// 主体计票策略的规范字节。`policy_threshold` 在这版语义下表示“不同主体数”，
/// 同时仍要求这些签名覆盖 `policy_roles` 中的每个角色。
#[derive(Serialize)]
struct PolicyStatementV4<'a> {
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
    policy_principal_quorum: bool,
    previous_policy_hash: Option<&'a str>,
    policy_hash: &'a str,
    signed_at_ms: u64,
    key_id: &'a str,
}

pub(crate) fn policy_statement_v4_bytes(
    session: &str,
    policy: &Policy,
    previous_policy_hash: Option<&str>,
    policy_hash: &str,
    signed_at_ms: u64,
    key_id: &str,
) -> Result<Vec<u8>, RepoError> {
    serde_json::to_vec(&PolicyStatementV4 {
        schema: POLICY_SCHEMA_V4,
        action: "set",
        session,
        require_witness: policy.require_witness,
        require_intent: policy.require_intent,
        require_signed_claims: policy.require_signed_claims,
        require_signed_witness: policy.require_signed_witness,
        require_signed_policy: policy.require_signed_policy,
        policy_threshold: policy.policy_threshold,
        policy_roles: &policy.policy_roles,
        policy_principal_quorum: policy.policy_principal_quorum,
        previous_policy_hash,
        policy_hash,
        signed_at_ms,
        key_id,
    })
    .map_err(|err| RepoError::BadHead(format!("策略签名载荷编码失败：{err}")))
}

/// 本次变更必须覆盖的角色：当前与新严格策略的角色并集。关闭严格策略
/// 也必须由旧角色批准，避免单钥把多角色策略直接关掉。
pub(crate) fn policy_roles_for_change(
    current_require: bool,
    current_roles: &[String],
    next_require: bool,
    next_roles: &[String],
) -> Vec<String> {
    if !current_require && !next_require {
        return Vec::new();
    }
    let mut roles = Vec::new();
    if current_require {
        roles.extend(current_roles.iter().cloned());
    }
    if next_require {
        roles.extend(next_roles.iter().cloned());
    }
    roles.sort();
    roles.dedup();
    roles
}

/// 把角色列表规范化成固定顺序；重复、空列表和未知角色都拒绝。
pub fn normalize_policy_roles(roles: &[String]) -> Result<Vec<String>, RepoError> {
    if roles.is_empty() {
        return Err(RepoError::BadHead("policy_roles 不能为空".to_string()));
    }
    if roles.len() > MAX_POLICY_ROLES {
        return Err(RepoError::BadHead(format!(
            "policy_roles 最多 {MAX_POLICY_ROLES} 个；收到 {}",
            roles.len()
        )));
    }
    let mut seen = HashSet::new();
    for role in roles {
        if !POLICY_SIGNER_ROLES.contains(&role.as_str()) {
            return Err(RepoError::BadHead(format!(
                "policy_roles 只支持 auditor/release；收到 {role}"
            )));
        }
        if !seen.insert(role.clone()) {
            return Err(RepoError::BadHead(format!("policy_roles 不能重复：{role}")));
        }
    }
    let mut normalized = roles.to_vec();
    normalized.sort();
    Ok(normalized)
}

/// 本次变更必须收集的签名数：当前严格阈值与新严格阈值取较大者，
/// 至少覆盖所有要求角色（每个角色至少一个有效签名）。
pub(crate) fn policy_quorum(
    current_require: bool,
    current_threshold: u8,
    next_require: bool,
    next_threshold: u8,
) -> usize {
    if !current_require && !next_require {
        return 0;
    }
    let current = if current_require {
        usize::from(current_threshold.max(1))
    } else {
        1
    };
    let next = if next_require {
        usize::from(next_threshold.max(1))
    } else {
        1
    };
    current.max(next)
}

fn normalized_role_thresholds(
    roles: &[String],
    thresholds: &BTreeMap<String, u8>,
) -> Result<BTreeMap<String, u8>, RepoError> {
    let mut normalized = BTreeMap::new();
    for (role, threshold) in thresholds {
        if !roles.contains(role) {
            return Err(RepoError::BadHead(format!(
                "policy_role_thresholds 含未在 policy_roles 中的角色：{role}"
            )));
        }
        if !(1..=MAX_POLICY_THRESHOLD).contains(threshold) {
            return Err(RepoError::BadHead(format!(
                "角色 {role} 的签名阈值必须在 1..={MAX_POLICY_THRESHOLD}；收到 {threshold}"
            )));
        }
        if *threshold > 1 {
            normalized.insert(role.clone(), *threshold);
        }
    }
    Ok(normalized)
}

fn effective_role_threshold(thresholds: &BTreeMap<String, u8>, role: &str) -> u8 {
    thresholds.get(role).copied().unwrap_or(1)
}

pub(crate) fn policy_role_mins_for_change(
    current_require: bool,
    current_thresholds: &BTreeMap<String, u8>,
    next_require: bool,
    next_thresholds: &BTreeMap<String, u8>,
    required_roles: &[String],
) -> BTreeMap<String, usize> {
    required_roles
        .iter()
        .map(|role| {
            let current = if current_require {
                usize::from(effective_role_threshold(current_thresholds, role))
            } else {
                0
            };
            let next = if next_require {
                usize::from(effective_role_threshold(next_thresholds, role))
            } else {
                0
            };
            (role.clone(), current.max(next))
        })
        .collect()
}

fn ensure_policy_threshold(policy: &Policy) -> Result<(), RepoError> {
    if !(1..=MAX_POLICY_THRESHOLD).contains(&policy.policy_threshold) {
        return Err(RepoError::BadHead(format!(
            "policy_threshold 必须在 1..={MAX_POLICY_THRESHOLD}；收到 {}",
            policy.policy_threshold
        )));
    }
    let roles = normalize_policy_roles(&policy.policy_roles)?;
    normalized_role_thresholds(&roles, &policy.policy_role_thresholds)?;
    let role_min_sum = roles
        .iter()
        .map(|role| {
            u16::from(effective_role_threshold(
                &policy.policy_role_thresholds,
                role,
            ))
        })
        .sum::<u16>();
    if role_min_sum > u16::from(MAX_POLICY_THRESHOLD) {
        return Err(RepoError::BadHead(format!(
            "每个角色最低签名数合计 {role_min_sum} 超过上限 {MAX_POLICY_THRESHOLD}"
        )));
    }
    if usize::from(policy.policy_threshold) < roles.len() {
        return Err(RepoError::BadHead(format!(
            "policy_threshold {} 小于策略角色数 {}；每个角色至少需要一个签名",
            policy.policy_threshold,
            roles.len()
        )));
    }
    if usize::from(policy.policy_threshold) < usize::from(role_min_sum) {
        return Err(RepoError::BadHead(format!(
            "policy_threshold {} 小于每角色最低签名数合计 {role_min_sum}",
            policy.policy_threshold
        )));
    }
    Ok(())
}

fn policy_file_hash(path: &Path) -> Result<Option<Hash>, RepoError> {
    match fs::read(path) {
        Ok(bytes) => Ok(Some(Hash::of(&bytes))),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(RepoError::Io(err)),
    }
}

fn ensure_trusted_signer(
    repo: &Repo,
    key: &KeyFile,
    required_roles: &[String],
) -> Result<(String, String), RepoError> {
    let keys = repo.keys()?;
    let Some(entry) = keys.keys.get(&key.key_id) else {
        return Err(RepoError::BadHead(format!(
            "key {} 不在信任表；先 key add",
            key.key_id
        )));
    };
    if entry.public_key.as_deref() != Some(key.public.as_str()) {
        return Err(RepoError::BadHead(format!(
            "key {} 的公钥与信任表不一致",
            key.key_id
        )));
    }
    if entry.is_revoked() {
        return Err(RepoError::BadHead(format!("key {} 已吊销", key.key_id)));
    }
    if !required_roles.is_empty() && !required_roles.iter().any(|role| role == &entry.role) {
        return Err(RepoError::BadHead(format!(
            "策略签名要求角色 {}；key {} 的角色是 {}",
            required_roles.join("/"),
            key.key_id,
            entry.role
        )));
    }
    Ok((entry.role.clone(), entry.principal.clone()))
}

impl Repo {
    /// 写入整份策略，并记录 `policy` 事件。参数是“完整策略”，不是增量：
    /// 调用方必须明确本次要打开/关闭哪些开关，避免旧的 true 被悄悄带过去。
    pub fn set_policy(
        &mut self,
        policy: &Policy,
        session: &str,
        at_ms: u64,
    ) -> Result<Hash, RepoError> {
        self.set_policy_with_signer(policy, session, at_ms, None)
    }

    /// 与 `set_policy` 相同，但可用一组 Ed25519 私钥给本次策略变更签名。
    ///
    /// 当前策略或新策略打开 `require_signed_policy` 时，签名数必须达到
    /// 两边阈值的较大者，并且覆盖当前/新策略要求的所有角色；每把 key 都必须是
    /// 信任表里对应角色的不同 key。签名覆盖旧/新摘要、完整开关、阈值、角色、
    /// session 与各自 key id。
    pub fn set_policy_with_signers(
        &mut self,
        policy: &Policy,
        session: &str,
        at_ms: u64,
        signers: &[&Path],
    ) -> Result<Hash, RepoError> {
        self.set_policy_with_reason_and_signers(policy, session, at_ms, signers, None, None)
    }

    /// 与 `set_policy_with_signers` 相同，并额外记录策略变更原因/工单。
    ///
    /// 当前或新策略打开 `require_policy_reason` 时，reason 必须非空；关闭这条开关
    /// 的变更自身也必须带原因。reason/ticket 进入 v6 事件与签名载荷，但不写入
    /// `policy.json`。
    #[allow(clippy::too_many_arguments)]
    pub fn set_policy_with_reason_and_signers(
        &mut self,
        policy: &Policy,
        session: &str,
        at_ms: u64,
        signers: &[&Path],
        reason: Option<&str>,
        ticket: Option<&str>,
    ) -> Result<Hash, RepoError> {
        let _guard = self.lock_state()?;
        ensure_policy_threshold(policy)?;
        let mut next = policy.clone();
        next.policy_roles = normalize_policy_roles(&next.policy_roles)?;
        next.policy_role_thresholds =
            normalized_role_thresholds(&next.policy_roles, &next.policy_role_thresholds)?;
        let current = self.policy()?;
        ensure_policy_threshold(&current)?;
        let reason = reason.map(str::trim).filter(|value| !value.is_empty());
        let ticket = ticket.map(str::trim).filter(|value| !value.is_empty());
        if (current.require_policy_reason || next.require_policy_reason) && reason.is_none() {
            return Err(RepoError::BadHead(
                "策略要求本次变更提供非空 --policy-reason".to_string(),
            ));
        }
        let reason_owned = reason.unwrap_or("").to_string();
        let ticket_owned = ticket.map(str::to_string);
        let required_roles = policy_roles_for_change(
            current.require_signed_policy,
            &current.policy_roles,
            next.require_signed_policy,
            &next.policy_roles,
        );
        let role_mins = policy_role_mins_for_change(
            current.require_signed_policy,
            &current.policy_role_thresholds,
            next.require_signed_policy,
            &next.policy_role_thresholds,
            &required_roles,
        );
        let required = policy_quorum(
            current.require_signed_policy,
            current.policy_threshold,
            next.require_signed_policy,
            next.policy_threshold,
        )
        .max(required_roles.len())
        .max(role_mins.values().sum());
        let require_principals = current.policy_principal_quorum || next.policy_principal_quorum;
        let keys = signers
            .iter()
            .map(|path| KeyFile::load(path))
            .collect::<Result<Vec<_>, _>>()?;
        if required > 0 && keys.is_empty() {
            return Err(RepoError::BadHead(format!(
                "策略要求 {required} 个签名（角色 {}）；policy set 需要 --sign-key <私钥文件>",
                required_roles.join("/")
            )));
        }
        if required > 0 && keys.len() < required {
            return Err(RepoError::BadHead(format!(
                "策略要求至少 {required} 个不同签名（角色 {}）；只收到 {} 个 --sign-key",
                required_roles.join("/"),
                keys.len()
            )));
        }
        let mut seen = HashSet::new();
        let mut covered = HashSet::new();
        let mut role_counts: HashMap<String, usize> = HashMap::new();
        let mut principal_roles: HashMap<String, String> = HashMap::new();
        for key in &keys {
            if !seen.insert(key.key_id.clone()) {
                return Err(RepoError::BadHead(format!(
                    "policy set 收到重复的签名 key：{}",
                    key.key_id
                )));
            }
            let (role, principal) = ensure_trusted_signer(self, key, &required_roles)?;
            if let Some(existing_role) = principal_roles.get(&principal) {
                if existing_role != &role {
                    return Err(RepoError::BadHead(format!(
                        "同一主体不能同时批准多个策略角色：{principal} 同时覆盖 {existing_role} 与 {role}"
                    )));
                }
            } else {
                principal_roles.insert(principal, role.clone());
            }
            *role_counts.entry(role.clone()).or_default() += 1;
            covered.insert(role);
        }
        if let Some(missing) = required_roles
            .iter()
            .find(|role| !covered.contains(role.as_str()))
        {
            return Err(RepoError::BadHead(format!(
                "策略要求签名覆盖角色 {}；缺少 {missing}",
                required_roles.join("/")
            )));
        }
        for (role, minimum) in &role_mins {
            let count = role_counts.get(role).copied().unwrap_or(0);
            if count < *minimum {
                return Err(RepoError::BadHead(format!(
                    "策略要求角色 {role} 至少 {minimum} 个签名；只收到 {count} 个"
                )));
            }
        }
        if require_principals && principal_roles.len() < required {
            return Err(RepoError::BadHead(format!(
                "策略要求至少 {required} 个不同主体签名（角色 {}）；只收到 {} 个主体",
                required_roles.join("/"),
                principal_roles.len()
            )));
        }

        let path = self.root().join(DIR).join("policy.json");
        let policy_owned = next;
        let custom_roles =
            !(policy_owned.policy_roles.len() == 1 && policy_owned.policy_roles[0] == "auditor");
        let schema = if current.require_policy_reason
            || policy_owned.require_policy_reason
            || reason.is_some()
            || ticket.is_some()
        {
            POLICY_SCHEMA_V6
        } else if !policy_owned.policy_role_thresholds.is_empty() {
            POLICY_SCHEMA_V5
        } else if policy_owned.policy_principal_quorum {
            POLICY_SCHEMA_V4
        } else if custom_roles {
            POLICY_SCHEMA_V3
        } else {
            POLICY_SCHEMA_V2
        };
        let key_ids = keys
            .iter()
            .map(|key| key.key_id.clone())
            .collect::<Vec<_>>();
        let session_owned = session.to_string();
        let roles_owned = policy_owned.policy_roles.clone();
        let role_thresholds_owned = policy_owned.policy_role_thresholds.clone();
        let args = json!({
            "session": session_owned,
            "require_witness": policy_owned.require_witness,
            "require_intent": policy_owned.require_intent,
            "require_signed_claims": policy_owned.require_signed_claims,
            "require_signed_witness": policy_owned.require_signed_witness,
            "require_signed_policy": policy_owned.require_signed_policy,
            "require_policy_reason": policy_owned.require_policy_reason,
            "policy_threshold": policy_owned.policy_threshold,
            "policy_roles": roles_owned,
            "policy_role_thresholds": role_thresholds_owned,
            "policy_principal_quorum": policy_owned.policy_principal_quorum,
            "policy_reason": &reason_owned,
            "policy_ticket": &ticket_owned,
            "signed": !key_ids.is_empty(),
            "key_ids": key_ids,
        });
        self.with_operation("policy", args, at_ms, move |repo| {
            let before = repo.state_digest()?.to_hex();
            let previous = policy_file_hash(&path)?;
            let bytes = serde_json::to_vec_pretty(&policy_owned)
                .map_err(|err| RepoError::BadHead(format!("policy 编码失败：{err}")))?;
            let policy_hash = Hash::of(&bytes);
            let policy_hash_hex = policy_hash.to_hex();
            let previous_hex = previous.map(|hash| hash.to_hex());
            let signatures = keys
                .iter()
                .map(|key| {
                    let statement = if schema == POLICY_SCHEMA_V6 {
                        policy_statement_v6_bytes(
                            session,
                            &policy_owned,
                            &reason_owned,
                            ticket_owned.as_deref(),
                            previous_hex.as_deref(),
                            &policy_hash_hex,
                            at_ms,
                            &key.key_id,
                        )?
                    } else if schema == POLICY_SCHEMA_V5 {
                        policy_statement_v5_bytes(
                            session,
                            &policy_owned,
                            previous_hex.as_deref(),
                            &policy_hash_hex,
                            at_ms,
                            &key.key_id,
                        )?
                    } else if schema == POLICY_SCHEMA_V4 {
                        policy_statement_v4_bytes(
                            session,
                            &policy_owned,
                            previous_hex.as_deref(),
                            &policy_hash_hex,
                            at_ms,
                            &key.key_id,
                        )?
                    } else if custom_roles {
                        policy_statement_v3_bytes(
                            session,
                            &policy_owned,
                            previous_hex.as_deref(),
                            &policy_hash_hex,
                            at_ms,
                            &key.key_id,
                        )?
                    } else {
                        policy_statement_v2_bytes(
                            session,
                            &policy_owned,
                            previous_hex.as_deref(),
                            &policy_hash_hex,
                            at_ms,
                            &key.key_id,
                        )?
                    };
                    Ok::<_, RepoError>(json!({
                        "key_id": key.key_id.clone(),
                        "signature": key.sign_hex(&statement)?,
                        "signed_at_ms": at_ms,
                    }))
                })
                .collect::<Result<Vec<_>, _>>()?;

            fs::write(&path, &bytes)?;
            let after = repo.state_digest()?.to_hex();
            let mut payload = json!({
                "schema": schema,
                "session": session,
                "require_witness": policy_owned.require_witness,
                "require_intent": policy_owned.require_intent,
                "require_signed_claims": policy_owned.require_signed_claims,
                "require_signed_witness": policy_owned.require_signed_witness,
                "require_signed_policy": policy_owned.require_signed_policy,
                "require_policy_reason": policy_owned.require_policy_reason,
                "policy_threshold": policy_owned.policy_threshold,
                "previous_policy_hash": previous_hex,
                "policy_hash": policy_hash_hex,
                "state_before": before,
                "state_after": after,
            });
            if custom_roles
                || schema == POLICY_SCHEMA_V4
                || schema == POLICY_SCHEMA_V5
                || schema == POLICY_SCHEMA_V6
            {
                payload["policy_roles"] = json!(policy_owned.policy_roles);
            }
            if schema == POLICY_SCHEMA_V5 || schema == POLICY_SCHEMA_V6 {
                payload["policy_role_thresholds"] = json!(policy_owned.policy_role_thresholds);
            }
            if schema == POLICY_SCHEMA_V4
                || schema == POLICY_SCHEMA_V5
                || schema == POLICY_SCHEMA_V6
            {
                payload["policy_principal_quorum"] = json!(policy_owned.policy_principal_quorum);
            }
            if schema == POLICY_SCHEMA_V6 {
                payload["policy_reason"] = json!(reason_owned);
                payload["policy_ticket"] = json!(ticket_owned);
            }
            if !signatures.is_empty() {
                payload["action"] = json!("set");
                payload["algorithm"] = json!("ed25519");
                payload["signatures"] = json!(signatures);
            }
            repo.journal_mut().append("policy", payload, at_ms)?;
            Ok(policy_hash)
        })
    }

    /// 单钥便捷入口；语义与 `set_policy_with_signers` 完全一致。
    pub fn set_policy_with_signer(
        &mut self,
        policy: &Policy,
        session: &str,
        at_ms: u64,
        signer: Option<&Path>,
    ) -> Result<Hash, RepoError> {
        let signers = signer.into_iter().collect::<Vec<_>>();
        self.set_policy_with_signers(policy, session, at_ms, &signers)
    }
}

#[cfg(test)]
#[cfg(test)]
mod tests;
