//! 审计的补充测试：失败操作如果已经把状态改掉，不能只凭 `status=failed` 放过。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;

use super::status;
use crate::gate::ClaimSpec;
use crate::hash::Hash;
use crate::keys::{TrustEntry, TrustStore};
use crate::repo::{CommitRequest, DIR, Repo, RepoError};
use crate::signing::KeyFile;

static NEXT: AtomicU64 = AtomicU64::new(0);

fn temp(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "trit-vcs-audit-extra-{tag}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

#[test]
fn failed_operation_that_changed_state_is_red() {
    let root = temp("op-failed");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let before = repo.state_digest().unwrap().to_hex();
    let begin = repo
        .journal_mut()
        .append(
            "op_begin",
            json!({"op": "manual", "state_before": before, "args": {}}),
            2_000,
        )
        .unwrap();
    let refs = root.join(DIR).join("refs");
    std::fs::create_dir_all(&refs).unwrap();
    std::fs::write(
        refs.join("hotfix"),
        format!("{}\n", Hash::of(b"not-a-commit")),
    )
    .unwrap();
    let after = repo.state_digest().unwrap().to_hex();
    repo.journal_mut()
        .append(
            "op_result",
            json!({
                "op": "manual",
                "begin": begin.seq,
                "begin_hash": begin.hash.to_hex(),
                "status": "failed",
                "state_after": after,
                "result": {},
            }),
            2_001,
        )
        .unwrap();
    let report = status(&repo).unwrap();
    assert!(!report.ok);
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.kind == "op_failed_state_change"),
        "失败操作改了状态必须判红：{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn auth_event_with_request_shape_is_audited_green() {
    let root = temp("auth-ok");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.journal_mut()
        .append(
            "auth",
            json!({
                "action": "auth",
                "decision": "denied",
                "reason": "bad_token",
                "method": "POST",
                "path": "/v1/publish",
                "status": 401,
                "state_before": digest,
                "state_after": digest,
            }),
            2_000,
        )
        .unwrap();
    let report = status(&repo).unwrap();
    assert!(report.ok, "{:?}", report.issues);
    assert_eq!(report.open_ops, 0);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn deny_event_with_business_reason_is_audited_green() {
    let root = temp("deny-ok");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.journal_mut()
        .append(
            "deny",
            json!({
                "action": "publish",
                "decision": "denied",
                "reason": "non_fast_forward",
                "message": "不是快进",
                "detail": {"ref": "main"},
                "state_before": digest,
                "state_after": digest,
            }),
            2_000,
        )
        .unwrap();
    let report = status(&repo).unwrap();
    assert!(report.ok, "{:?}", report.issues);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn deny_event_without_reason_is_red() {
    let root = temp("deny-bad");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.journal_mut()
        .append(
            "deny",
            json!({
                "action": "publish",
                "decision": "denied",
                "message": "没写原因",
                "state_after": digest,
            }),
            2_000,
        )
        .unwrap();
    let report = status(&repo).unwrap();
    assert!(!report.ok);
    assert!(
        report.issues.iter().any(|issue| issue.kind == "deny_bad"),
        "{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn auth_event_without_401_is_red() {
    let root = temp("auth-bad");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.journal_mut()
        .append(
            "auth",
            json!({
                "action": "auth",
                "decision": "denied",
                "reason": "bad_token",
                "method": "GET",
                "path": "/v1/pull",
                "status": 200,
                "state_after": digest,
            }),
            2_000,
        )
        .unwrap();
    let report = status(&repo).unwrap();
    assert!(!report.ok);
    assert!(
        report.issues.iter().any(|issue| issue.kind == "auth_bad"),
        "{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn denied_commit_leaves_auditable_gate_event() {
    let root = temp("gate");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let mut files = BTreeMap::new();
    files.insert("a.txt".to_string(), b"audit\n".to_vec());
    repo.stage(&files, 1_000).unwrap();
    repo.commit(CommitRequest {
        message: "seed".to_string(),
        session: "audit:test".to_string(),
        claims: vec![ClaimSpec {
            id: "c1".to_string(),
            owner: "audit:test".to_string(),
            paths: vec!["a.txt".to_string()],
            acquired_at: 1,
            expires_at: u64::MAX / 2,
        }],
        now_secs: 1_000,
        ..Default::default()
    })
    .unwrap();
    let mut files = BTreeMap::new();
    files.insert("b.txt".to_string(), b"denied\n".to_vec());
    repo.stage(&files, 2_000).unwrap();
    let err = repo
        .commit(CommitRequest {
            message: "denied".to_string(),
            session: "audit:test".to_string(),
            now_secs: 2_000,
            ..Default::default()
        })
        .unwrap_err();
    assert!(matches!(err, RepoError::Unclaimed { .. }), "{err}");
    let gate = repo
        .journal()
        .events()
        .iter()
        .find(|event| event.kind == "gate")
        .expect("拒绝必须留下来 gate 事件");
    assert_eq!(gate.payload["decision"], "denied");
    let report = status(&repo).unwrap();
    assert!(
        report.ok,
        "合法的 gate 拒绝事件不应把审计判红：{:?}",
        report.issues
    );
    assert_eq!(report.open_ops, 0);
    assert_eq!(report.level, "L2");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn versioned_policy_without_signed_claim_flag_fails_closed() {
    let root = temp("policy-fail-closed");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.append_audit(
        "policy",
        json!({
            "schema": "trit-policy-v1",
            "session": "audit:test",
            "require_witness": false,
            "require_intent": false,
            "policy_hash": Hash::of(b"policy").to_hex(),
            "state_before": digest,
            "state_after": digest,
        }),
        2_000,
    )
    .unwrap();
    repo.append_audit(
        "claim_add",
        json!({
            "signed": false,
            "state_before": digest,
            "state_after": digest,
        }),
        2_001,
    )
    .unwrap();

    let report = status(&repo).unwrap();
    assert!(!report.ok);
    assert!(
        report.issues.iter().any(|issue| {
            issue.kind == "policy_bad" && issue.detail.contains("require_signed_claims")
        }),
        "缺 require_signed_claims 必须单独报 policy_bad：{:?}",
        report.issues
    );
    assert!(
        report.issues.iter().any(|issue| {
            issue.kind == "policy_bad" && issue.detail.contains("require_signed_witness")
        }),
        "缺 require_signed_witness 必须单独报 policy_bad：{:?}",
        report.issues
    );
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.kind == "claim_signature_missing"),
        "缺字段的新策略必须按要求签名回放：{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn legacy_policy_without_signed_claim_flag_keeps_unsigned_claims_compatible() {
    let root = temp("policy-legacy");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.append_audit(
        "policy",
        json!({
            "session": "audit:test",
            "require_witness": false,
            "require_intent": false,
            "policy_hash": Hash::of(b"policy").to_hex(),
            "state_before": digest,
            "state_after": digest,
        }),
        2_000,
    )
    .unwrap();
    repo.append_audit(
        "claim_add",
        json!({
            "signed": false,
            "state_before": digest,
            "state_after": digest,
        }),
        2_001,
    )
    .unwrap();

    let report = status(&repo).unwrap();
    assert!(report.ok, "{:?}", report.issues);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn explicit_non_string_policy_schema_is_red() {
    let root = temp("policy-schema-type");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    for schema in [json!(null), json!(1), json!({}), json!("")] {
        repo.append_audit(
            "policy",
            json!({
                "schema": schema,
                "session": "audit:test",
                "require_witness": false,
                "require_intent": false,
                "require_signed_claims": false,
                "policy_hash": Hash::of(b"policy").to_hex(),
                "state_before": digest,
                "state_after": digest,
            }),
            2_000,
        )
        .unwrap();
    }

    let report = status(&repo).unwrap();
    assert!(!report.ok);
    assert_eq!(
        report
            .issues
            .iter()
            .filter(|issue| {
                issue.kind == "policy_bad" && issue.detail.contains("schema 不受支持")
            })
            .count(),
        4,
        "{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn key_add_public_key_shape_preserves_legacy_missing_or_null() {
    let root = temp("key-add-public-shape");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let key = KeyFile::generate().unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    let mut payload = json!({
        "action": "add",
        "key_id": key.key_id,
        "principal": "qoder:a",
        "role": "author",
        "session": "audit:test",
        "keystore_hash": Hash::of(b"keys").to_hex(),
        "state_before": digest,
        "state_after": digest,
    });
    for public in [json!(7), json!(""), json!(null)] {
        payload["public_key"] = public;
        repo.append_audit("key", payload.clone(), 2_000).unwrap();
    }
    payload.as_object_mut().unwrap().remove("public_key");
    repo.append_audit("key", payload, 2_000).unwrap();

    let report = status(&repo).unwrap();
    assert_eq!(
        report
            .issues
            .iter()
            .filter(|issue| {
                issue.kind == "key_bad" && issue.detail.contains("public_key 不是非空字符串")
            })
            .count(),
        2,
        "{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn key_add_public_key_fingerprint_mismatch_is_red() {
    let root = temp("key-add-public-fingerprint");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let key = KeyFile::generate().unwrap();
    let other = KeyFile::generate().unwrap();
    let mut store = TrustStore::default();
    store.keys.insert(
        key.key_id.clone(),
        TrustEntry {
            key_id: key.key_id.clone(),
            principal: "qoder:a".to_string(),
            role: "author".to_string(),
            added_at_ms: 1,
            public_key: Some(other.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        },
    );
    let keystore_hash = store.save(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.append_audit(
        "key",
        json!({
            "action": "add",
            "key_id": key.key_id,
            "principal": "qoder:a",
            "role": "author",
            "session": "audit:test",
            "public_key": other.public,
            "keystore_hash": keystore_hash.to_hex(),
            "state_before": digest,
            "state_after": digest,
        }),
        2_000,
    )
    .unwrap();

    let report = status(&repo).unwrap();
    assert!(
        report
            .issues
            .iter()
            .any(|issue| { issue.kind == "key_bad" && issue.detail.contains("指纹不一致") }),
        "{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn key_add_public_key_must_match_trust_store() {
    let root = temp("key-add-public-trust");
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root).unwrap();
    let mut repo = Repo::init(&root).unwrap();
    let key = KeyFile::generate().unwrap();
    let other = KeyFile::generate().unwrap();
    let mut store = TrustStore::default();
    store.keys.insert(
        key.key_id.clone(),
        TrustEntry {
            key_id: key.key_id.clone(),
            principal: "qoder:a".to_string(),
            role: "author".to_string(),
            added_at_ms: 1,
            public_key: Some(other.public),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        },
    );
    let keystore_hash = store.save(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.append_audit(
        "key",
        json!({
            "action": "add",
            "key_id": key.key_id,
            "principal": "qoder:a",
            "role": "author",
            "session": "audit:test",
            "public_key": key.public,
            "keystore_hash": keystore_hash.to_hex(),
            "state_before": digest,
            "state_after": digest,
        }),
        2_000,
    )
    .unwrap();

    let report = status(&repo).unwrap();
    assert!(
        report.issues.iter().any(|issue| {
            issue.kind == "key_bad" && issue.detail.contains("public_key 与信任表不一致")
        }),
        "{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}
