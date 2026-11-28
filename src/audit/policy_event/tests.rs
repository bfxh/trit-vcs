use super::*;
use crate::keys::TrustEntry;
use crate::signing::KeyFile;
use serde_json::json;

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "trit-vcs-policy-audit-{name}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn add_key(repo: &mut Repo, key: &KeyFile, path: &std::path::Path, role: &str) {
    key.save_new(path).unwrap();
    repo.add_key(
        TrustEntry {
            key_id: key.key_id.clone(),
            principal: "qoder:policy".to_string(),
            role: role.to_string(),
            added_at_ms: 1_000,
            public_key: Some(key.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        },
        "qoder:admin",
        1_000,
    )
    .unwrap();
}

fn signed_event(name: &str) -> (std::path::PathBuf, Repo, Event) {
    signed_event_with(name, "auditor", true)
}

fn signed_event_with(
    name: &str,
    role: &str,
    require_signed_policy: bool,
) -> (std::path::PathBuf, Repo, Event) {
    let root = temp(name);
    let mut repo = Repo::init(&root).unwrap();
    let key = KeyFile::generate().unwrap();
    let key_path = root.join("policy.key");
    add_key(&mut repo, &key, &key_path, role);
    repo.set_policy_with_signer(
        &Policy {
            require_signed_policy,
            ..Default::default()
        },
        "qoder:policy",
        2_000,
        Some(&key_path),
    )
    .unwrap();
    let event = repo
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "policy")
        .unwrap()
        .clone();
    (root, repo, event)
}

fn quorum_event(name: &str) -> (std::path::PathBuf, Repo, Event) {
    let root = temp(name);
    let mut repo = Repo::init(&root).unwrap();
    let first = KeyFile::generate().unwrap();
    let first_path = root.join("policy-first.key");
    add_key(&mut repo, &first, &first_path, "auditor");
    let second = KeyFile::generate().unwrap();
    let second_path = root.join("policy-second.key");
    add_key(&mut repo, &second, &second_path, "auditor");
    repo.set_policy_with_signers(
        &Policy {
            require_signed_policy: true,
            policy_threshold: 2,
            ..Default::default()
        },
        "qoder:policy",
        2_000,
        &[&first_path, &second_path],
    )
    .unwrap();
    let event = repo
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "policy")
        .unwrap()
        .clone();
    (root, repo, event)
}

fn issues(repo: &Repo, event: &Event, required_signatures: usize) -> Vec<AuditIssue> {
    let roles = if required_signatures == 0 {
        Vec::new()
    } else {
        vec!["auditor".to_string()]
    };
    issues_with_roles(repo, event, required_signatures, &roles)
}

fn issues_with_roles(
    repo: &Repo,
    event: &Event,
    required_signatures: usize,
    roles: &[String],
) -> Vec<AuditIssue> {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    check_policy(
        repo,
        event,
        required_signatures,
        roles,
        None,
        &mut issues,
        &mut warnings,
    );
    issues
}

#[test]
fn signed_policy_event_rejects_tampered_signature_and_required_flag() {
    let (root, repo, event) = signed_event("tamper");
    assert!(issues(&repo, &event, 1).is_empty());

    let mut bad_signature = event.clone();
    bad_signature.payload["signatures"][0]["signature"] = json!("00".repeat(64));
    assert!(
        issues(&repo, &bad_signature, 1)
            .iter()
            .any(|issue| issue.kind == "policy_signature_invalid")
    );

    let mut bad_flag = event.clone();
    bad_flag.payload["require_signed_policy"] = json!(false);
    assert!(
        issues(&repo, &bad_flag, 1)
            .iter()
            .any(|issue| issue.kind == "policy_signature_invalid"),
        "require_signed_policy 必须被签名覆盖"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn unsigned_policy_event_is_red_once_policy_requires_signature() {
    let (root, repo, event) = signed_event("unsigned");
    let mut unsigned = event;
    unsigned
        .payload
        .as_object_mut()
        .unwrap()
        .remove("signatures");
    unsigned.payload.as_object_mut().unwrap().remove("action");
    unsigned
        .payload
        .as_object_mut()
        .unwrap()
        .remove("algorithm");
    assert!(
        issues(&repo, &unsigned, 1)
            .iter()
            .any(|issue| issue.kind == "policy_unsigned")
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn strict_policy_rejects_non_auditor_signer() {
    let (root, repo, event) = signed_event_with("role", "author", false);
    assert!(
        issues(&repo, &event, 0).is_empty(),
        "未开 require_signed_policy 时非 auditor 签名仍可审计"
    );
    assert!(
        issues(&repo, &event, 1)
            .iter()
            .any(|issue| issue.kind == "policy_signer_role"),
        "require_signed_policy 生效时必须要求 auditor 角色"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn policy_quorum_counts_only_distinct_valid_signatures() {
    let (root, repo, event) = quorum_event("quorum-count");
    assert!(issues(&repo, &event, 2).is_empty());

    let mut duplicate = event.clone();
    let first = duplicate.payload["signatures"][0].clone();
    duplicate.payload["signatures"][1] = first;
    let duplicate_issues = issues(&repo, &duplicate, 2);
    assert!(
        duplicate_issues
            .iter()
            .any(|issue| issue.kind == "policy_signature_duplicate")
    );
    assert!(
        duplicate_issues
            .iter()
            .any(|issue| issue.kind == "policy_signature_insufficient")
    );

    let mut one = event.clone();
    one.payload["signatures"].as_array_mut().unwrap().pop();
    assert!(
        issues(&repo, &one, 2)
            .iter()
            .any(|issue| issue.kind == "policy_signature_insufficient")
    );
    let _ = std::fs::remove_dir_all(&root);
}

fn mixed_role_event(name: &str) -> (std::path::PathBuf, Repo, Event) {
    let root = temp(name);
    let mut repo = Repo::init(&root).unwrap();
    let auditor = KeyFile::generate().unwrap();
    let auditor_path = root.join("auditor.key");
    add_key(&mut repo, &auditor, &auditor_path, "auditor");
    let release = KeyFile::generate().unwrap();
    let release_path = root.join("release.key");
    add_key(&mut repo, &release, &release_path, "release");
    repo.set_policy_with_signers(
        &Policy {
            require_signed_policy: true,
            policy_threshold: 2,
            policy_roles: vec!["auditor".into(), "release".into()],
            ..Default::default()
        },
        "qoder:policy",
        2_000,
        &[&auditor_path, &release_path],
    )
    .unwrap();
    let event = repo
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "policy")
        .unwrap()
        .clone();
    (root, repo, event)
}

#[test]
fn mixed_role_policy_requires_each_role_and_binds_role_list() {
    let (root, repo, event) = mixed_role_event("mixed-role");
    let roles = vec!["auditor".to_string(), "release".to_string()];
    assert!(issues_with_roles(&repo, &event, 2, &roles).is_empty());

    let mut missing_release = event.clone();
    missing_release.payload["signatures"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(
        issues_with_roles(&repo, &missing_release, 2, &roles)
            .iter()
            .any(|issue| issue.kind == "policy_role_missing")
    );

    let mut changed_roles = event;
    changed_roles.payload["policy_roles"] = json!(["auditor"]);
    assert!(
        issues_with_roles(&repo, &changed_roles, 2, &roles)
            .iter()
            .any(|issue| issue.kind == "policy_signature_invalid"),
        "policy_roles 必须进入 v3 签名载荷"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn policy_threshold_is_part_of_the_signed_statement() {
    let (root, repo, event) = quorum_event("threshold-binding");
    let mut lowered = event;
    lowered.payload["policy_threshold"] = json!(1);
    assert!(
        issues(&repo, &lowered, 2)
            .iter()
            .any(|issue| issue.kind == "policy_signature_invalid"),
        "改低阈值必须使签名失效"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn v3_policy_requires_signed_claim_replay_to_cover_the_new_schema() {
    let root = temp("policy-v3-claims");
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.append_audit(
        "policy",
        json!({
            "schema": "trit-policy-v3",
            "session": "audit:test",
            "require_witness": false,
            "require_intent": false,
            "require_signed_witness": false,
            "require_signed_policy": false,
            "policy_threshold": 1,
            "policy_roles": ["auditor"],
            "policy_hash": Hash::of(b"policy-v3").to_hex(),
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

    let report = crate::audit::status(&repo).unwrap();
    assert!(
        report
            .issues
            .iter()
            .any(|issue| issue.kind == "claim_signature_missing"),
        "v3 策略必须参与 require_signed_claims 重放：{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}
