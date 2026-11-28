//! v6 策略变更原因/工单的审计回归。

use super::*;

fn reason_event(name: &str) -> (std::path::PathBuf, Repo, Event) {
    let root = temp(name);
    let mut repo = Repo::init(&root).unwrap();
    let key = KeyFile::generate().unwrap();
    let key_path = root.join("policy.key");
    add_key(&mut repo, &key, &key_path, "auditor");
    repo.set_policy_with_reason_and_signers(
        &Policy {
            require_signed_policy: true,
            require_policy_reason: true,
            ..Default::default()
        },
        "qoder:policy",
        2_000,
        &[&key_path],
        Some("rotate auditor key"),
        Some("OPS-7"),
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

fn issues_requiring_reason(
    repo: &Repo,
    event: &Event,
    required_signatures: usize,
) -> Vec<AuditIssue> {
    let mut issues = Vec::new();
    let mut warnings = Vec::new();
    check_policy(
        repo,
        event,
        required_signatures,
        &[],
        &BTreeMap::new(),
        false,
        true,
        None,
        &mut issues,
        &mut warnings,
    );
    issues
}

#[test]
fn v6_reason_and_ticket_are_bound_to_the_signature() {
    let (root, repo, event) = reason_event("policy-v6-reason-binding");
    assert!(issues(&repo, &event, 1).is_empty());

    let mut changed_reason = event.clone();
    changed_reason.payload["policy_reason"] = json!("attacker rationale");
    assert!(
        issues(&repo, &changed_reason, 1)
            .iter()
            .any(|issue| issue.kind == "policy_signature_invalid"),
        "改原因必须使 v6 签名失效"
    );

    let mut changed_ticket = event.clone();
    changed_ticket.payload["policy_ticket"] = json!("OPS-8");
    assert!(
        issues(&repo, &changed_ticket, 1)
            .iter()
            .any(|issue| issue.kind == "policy_signature_invalid"),
        "改工单必须使 v6 签名失效"
    );

    let mut changed_switch = event.clone();
    changed_switch.payload["require_policy_reason"] = json!(false);
    assert!(
        issues(&repo, &changed_switch, 1)
            .iter()
            .any(|issue| issue.kind == "policy_signature_invalid"),
        "关闭原因开关也必须使 v6 签名失效"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn v6_policy_event_requires_reason_fields() {
    let (root, repo, event) = reason_event("policy-v6-reason-fields");
    let mut missing_reason = event.clone();
    missing_reason
        .payload
        .as_object_mut()
        .unwrap()
        .remove("policy_reason");
    assert!(
        issues(&repo, &missing_reason, 1)
            .iter()
            .any(|issue| issue.kind == "policy_bad"),
        "v6 缺 policy_reason 必须报 policy_bad"
    );

    let mut missing_ticket = event.clone();
    missing_ticket
        .payload
        .as_object_mut()
        .unwrap()
        .remove("policy_ticket");
    assert!(
        issues(&repo, &missing_ticket, 1)
            .iter()
            .any(|issue| issue.kind == "policy_bad"),
        "v6 缺 policy_ticket 必须报 policy_bad"
    );

    let mut missing_switch = event.clone();
    missing_switch
        .payload
        .as_object_mut()
        .unwrap()
        .remove("require_policy_reason");
    assert!(
        issues(&repo, &missing_switch, 1)
            .iter()
            .any(|issue| issue.kind == "policy_bad"),
        "v6 缺 require_policy_reason 必须报 policy_bad"
    );

    let mut bad_ticket = event.clone();
    bad_ticket.payload["policy_ticket"] = json!(42);
    assert!(
        issues(&repo, &bad_ticket, 1)
            .iter()
            .any(|issue| issue.kind == "policy_bad"),
        "v6 的非字符串工单必须报 policy_bad"
    );

    let mut empty_reason = event;
    empty_reason.payload["policy_reason"] = json!("   ");
    assert!(
        issues_requiring_reason(&repo, &empty_reason, 1)
            .iter()
            .any(|issue| issue.kind == "policy_bad"),
        "require_policy_reason 下空原因必须报 policy_bad"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn v6_policy_requires_signed_claim_replay_to_cover_the_new_schema() {
    let root = temp("policy-v6-claims");
    let mut repo = Repo::init(&root).unwrap();
    let digest = repo.state_digest().unwrap().to_hex();
    repo.append_audit(
        "policy",
        json!({
            "schema": "trit-policy-v6",
            "session": "audit:test",
            "require_witness": false,
            "require_intent": false,
            "require_signed_witness": false,
            "require_signed_policy": false,
            "require_policy_reason": false,
            "policy_threshold": 1,
            "policy_roles": ["auditor"],
            "policy_role_thresholds": {},
            "policy_principal_quorum": false,
            "policy_reason": "",
            "policy_ticket": null,
            "policy_hash": Hash::of(b"policy-v6").to_hex(),
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
        "v6 策略必须参与 require_signed_claims 重放：{:?}",
        report.issues
    );
    let _ = std::fs::remove_dir_all(&root);
}
