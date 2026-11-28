use super::*;
use crate::keys::TrustEntry;

fn temp(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("trit-vcs-policy-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn signed_setup(name: &str) -> (std::path::PathBuf, Repo, KeyFile, std::path::PathBuf) {
    let root = temp(name);
    let mut repo = Repo::init(&root).unwrap();
    let key = KeyFile::generate().unwrap();
    let key_path = root.join("policy.key");
    key.save_new(&key_path).unwrap();
    repo.add_key(
        TrustEntry {
            key_id: key.key_id.clone(),
            principal: "qoder:policy".to_string(),
            role: "auditor".to_string(),
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
    (root, repo, key, key_path)
}

#[test]
fn signed_policy_change_is_audited_and_attributes_the_key() {
    let (root, mut repo, key, key_path) = signed_setup("signed");
    let policy = Policy {
        require_signed_policy: true,
        ..Default::default()
    };
    repo.set_policy_with_signer(&policy, "qoder:policy", 2_000, Some(&key_path))
        .unwrap();
    let report = crate::audit::status(&repo).unwrap();
    assert!(report.ok, "{:?}", report.issues);

    let event = repo
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "policy")
        .unwrap();
    assert_eq!(event.payload["require_signed_policy"], true);
    assert_eq!(event.payload["policy_threshold"], 1);
    assert_eq!(event.payload["algorithm"], "ed25519");
    assert_eq!(event.payload["schema"], POLICY_SCHEMA_V2);
    assert_eq!(event.payload["signatures"][0]["key_id"], key.key_id);
    assert!(event.payload["previous_policy_hash"].is_null());
    assert!(
        event.payload["signatures"][0]["signature"]
            .as_str()
            .is_some_and(|value| {
                value.len() == 128 && value.chars().all(|ch| ch.is_ascii_hexdigit())
            })
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn policy_quorum_requires_multiple_auditor_signatures_and_blocks_threshold_downgrade() {
    let (root, mut repo, key, key_path) = signed_setup("quorum");
    let second = KeyFile::generate().unwrap();
    let second_path = root.join("policy-second.key");
    second.save_new(&second_path).unwrap();
    repo.add_key(
        TrustEntry {
            key_id: second.key_id.clone(),
            principal: "qoder:policy-second".to_string(),
            role: "auditor".to_string(),
            added_at_ms: 1_500,
            public_key: Some(second.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        },
        "qoder:admin",
        1_500,
    )
    .unwrap();

    let strict_two = Policy {
        require_signed_policy: true,
        policy_threshold: 2,
        ..Default::default()
    };
    let err = repo
        .set_policy_with_signers(&strict_two, "qoder:policy", 2_000, &[&key_path])
        .unwrap_err();
    assert!(err.to_string().contains("至少 2"), "{err}");
    repo.set_policy_with_signers(
        &strict_two,
        "qoder:policy",
        2_000,
        &[&key_path, &second_path],
    )
    .unwrap();
    let report = crate::audit::status(&repo).unwrap();
    assert!(report.ok, "{:?}", report.issues);
    let event = repo
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "policy")
        .unwrap();
    assert_eq!(event.payload["policy_threshold"], 2);
    assert_eq!(event.payload["signatures"].as_array().unwrap().len(), 2);
    assert_eq!(event.payload["signatures"][0]["key_id"], key.key_id);

    let lower = Policy {
        policy_threshold: 1,
        ..Default::default()
    };
    let err = repo
        .set_policy_with_signers(&lower, "qoder:policy", 3_000, &[&key_path])
        .unwrap_err();
    assert!(
        err.to_string().contains("至少 2"),
        "调低阈值也必须先满足旧阈值：{err}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn mixed_role_policy_requires_each_role_and_blocks_role_drop() {
    let root = temp("mixed-role");
    let mut repo = Repo::init(&root).unwrap();
    let auditor = KeyFile::generate().unwrap();
    let auditor_path = root.join("auditor.key");
    auditor.save_new(&auditor_path).unwrap();
    repo.add_key(
        TrustEntry {
            key_id: auditor.key_id.clone(),
            principal: "qoder:auditor".to_string(),
            role: "auditor".to_string(),
            added_at_ms: 1_000,
            public_key: Some(auditor.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        },
        "qoder:admin",
        1_000,
    )
    .unwrap();
    let release = KeyFile::generate().unwrap();
    let release_path = root.join("release.key");
    release.save_new(&release_path).unwrap();
    repo.add_key(
        TrustEntry {
            key_id: release.key_id.clone(),
            principal: "qoder:release".to_string(),
            role: "release".to_string(),
            added_at_ms: 1_500,
            public_key: Some(release.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        },
        "qoder:admin",
        1_500,
    )
    .unwrap();
    let second_auditor = KeyFile::generate().unwrap();
    let second_auditor_path = root.join("auditor-second.key");
    second_auditor.save_new(&second_auditor_path).unwrap();
    repo.add_key(
        TrustEntry {
            key_id: second_auditor.key_id.clone(),
            principal: "qoder:auditor-second".to_string(),
            role: "auditor".to_string(),
            added_at_ms: 1_800,
            public_key: Some(second_auditor.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        },
        "qoder:admin",
        1_800,
    )
    .unwrap();

    let mixed = Policy {
        require_signed_policy: true,
        policy_threshold: 2,
        policy_roles: vec!["release".into(), "auditor".into()],
        ..Default::default()
    };
    let err = repo
        .set_policy_with_signers(&mixed, "qoder:policy", 2_000, &[&auditor_path])
        .unwrap_err();
    assert!(err.to_string().contains("至少 2"), "{err}");
    let err = repo
        .set_policy_with_signers(
            &mixed,
            "qoder:policy",
            2_000,
            &[&auditor_path, &second_auditor_path],
        )
        .unwrap_err();
    assert!(err.to_string().contains("缺少 release"), "{err}");
    repo.set_policy_with_signers(
        &mixed,
        "qoder:policy",
        2_000,
        &[&auditor_path, &release_path],
    )
    .unwrap();
    let report = crate::audit::status(&repo).unwrap();
    assert!(report.ok, "{:?}", report.issues);
    let event = repo
        .journal()
        .events()
        .iter()
        .rev()
        .find(|event| event.kind == "policy")
        .unwrap();
    assert_eq!(event.payload["schema"], POLICY_SCHEMA_V3);
    assert_eq!(event.payload["policy_roles"], json!(["auditor", "release"]));
    assert_eq!(event.payload["signatures"].as_array().unwrap().len(), 2);

    let auditor_only = Policy {
        require_signed_policy: true,
        policy_threshold: 1,
        policy_roles: vec!["auditor".into()],
        ..Default::default()
    };
    let err = repo
        .set_policy_with_signers(&auditor_only, "qoder:policy", 3_000, &[&auditor_path])
        .unwrap_err();
    assert!(
        err.to_string().contains("至少 2"),
        "降角色也必须先满足旧的多角色批准：{err}"
    );
    repo.set_policy_with_signers(
        &auditor_only,
        "qoder:policy",
        3_000,
        &[&auditor_path, &release_path],
    )
    .unwrap();
    let report = crate::audit::status(&repo).unwrap();
    assert!(report.ok, "{:?}", report.issues);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn mixed_role_policy_rejects_same_principal_for_two_roles() {
    let root = temp("same-principal");
    let mut repo = Repo::init(&root).unwrap();
    let auditor = KeyFile::generate().unwrap();
    let auditor_path = root.join("auditor.key");
    auditor.save_new(&auditor_path).unwrap();
    repo.add_key(
        TrustEntry {
            key_id: auditor.key_id.clone(),
            principal: "qoder:shared".to_string(),
            role: "auditor".to_string(),
            added_at_ms: 1_000,
            public_key: Some(auditor.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        },
        "qoder:admin",
        1_000,
    )
    .unwrap();
    let release = KeyFile::generate().unwrap();
    let release_path = root.join("release.key");
    release.save_new(&release_path).unwrap();
    repo.add_key(
        TrustEntry {
            key_id: release.key_id.clone(),
            principal: "qoder:shared".to_string(),
            role: "release".to_string(),
            added_at_ms: 1_500,
            public_key: Some(release.public.clone()),
            rotated_from: None,
            revoked_at_ms: None,
            revoke_reason: None,
        },
        "qoder:admin",
        1_500,
    )
    .unwrap();

    let mixed = Policy {
        require_signed_policy: true,
        policy_threshold: 2,
        policy_roles: vec!["auditor".into(), "release".into()],
        ..Default::default()
    };
    let err = repo
        .set_policy_with_signers(
            &mixed,
            "qoder:policy",
            2_000,
            &[&auditor_path, &release_path],
        )
        .unwrap_err();
    assert!(
        err.to_string().contains("同一主体不能同时批准多个策略角色"),
        "混合角色必须由不同主体批准：{err}"
    );
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn policy_rejects_unknown_or_unbalanced_roles() {
    let (root, mut repo, _key, _key_path) = signed_setup("roles-invalid");
    let unknown = Policy {
        require_signed_policy: true,
        policy_roles: vec!["owner".into()],
        ..Default::default()
    };
    let err = repo
        .set_policy(&unknown, "qoder:policy", 2_000)
        .unwrap_err();
    assert!(err.to_string().contains("只支持 auditor/release"), "{err}");
    let duplicate = Policy {
        require_signed_policy: true,
        policy_threshold: 2,
        policy_roles: vec!["auditor".into(), "auditor".into()],
        ..Default::default()
    };
    let err = repo
        .set_policy(&duplicate, "qoder:policy", 2_500)
        .unwrap_err();
    assert!(err.to_string().contains("不能重复"), "{err}");
    let unbalanced = Policy {
        require_signed_policy: true,
        policy_threshold: 1,
        policy_roles: vec!["auditor".into(), "release".into()],
        ..Default::default()
    };
    let err = repo
        .set_policy(&unbalanced, "qoder:policy", 3_000)
        .unwrap_err();
    assert!(err.to_string().contains("小于策略角色数"), "{err}");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn policy_role_list_changes_the_v3_statement_bytes() {
    let auditor_only = Policy {
        require_signed_policy: true,
        policy_threshold: 2,
        policy_roles: vec!["auditor".into()],
        ..Default::default()
    };
    let mixed = Policy {
        require_signed_policy: true,
        policy_threshold: 2,
        policy_roles: vec!["auditor".into(), "release".into()],
        ..Default::default()
    };
    let one =
        policy_statement_v3_bytes("qoder:policy", &auditor_only, None, "hash", 1, "key").unwrap();
    let two = policy_statement_v3_bytes("qoder:policy", &mixed, None, "hash", 1, "key").unwrap();
    assert_ne!(one, two, "v3 签名载荷必须覆盖 policy_roles");
}
