use super::*;

#[test]
fn signed_claim_add_and_release_are_auditable_sidecars() {
    let root = temp("signed-flow");
    let central = root.join("central");
    init(&central);
    let key_id = trust_key(&root, &central, "author.key", "qoder:a", "author");
    let key_path = path_text(&root.join("author.key"));
    let central_text = path_text(&central);

    let added = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "signed-1",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
            "--sign-key",
            &key_path,
            "--json",
        ],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    let events = journal_events(&central);
    assert_eq!(
        events
            .iter()
            .filter(|event| event["kind"] == "claim_signature")
            .count(),
        1
    );
    let claim_event = &events[event_index(&events, "claim_add")]["payload"];
    assert_eq!(claim_event["signed"], true);
    assert_eq!(claim_event["claim"]["owner"], "qoder:a");
    let claim_index = event_index(&events, "claim_add");
    let begin_index = (0..claim_index)
        .rev()
        .find(|&index| events[index]["kind"] == "op_begin")
        .unwrap();
    let signature = &events[event_index(&events, "claim_signature")]["payload"];
    assert_eq!(
        signature["state_before"],
        events[begin_index]["payload"]["state_before"]
    );
    assert_eq!(signature["state_after"], claim_event["state_after"]);
    assert_ne!(
        signature["state_before"], signature["state_after"],
        "认领写入必须改变状态，前后摘要不能都被写成操作后值"
    );
    let ledger: Value = serde_json::from_str(
        &fs::read_to_string(central.join(".tritvcs").join("claims.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(ledger.as_array().unwrap().len(), 1);
    assert!(ledger[0].get("signature").is_none());
    assert!(audit(&central)["ok"].as_bool().unwrap());

    let released = run(
        &root,
        &[
            "claims",
            "release",
            "--central",
            &central_text,
            "--id",
            "signed-1",
            "--owner",
            "qoder:a",
            "--sign-key",
            &key_path,
            "--json",
        ],
    );
    assert!(released.status.success(), "{}", stderr(&released));
    let report = audit(&central);
    assert!(report["ok"].as_bool().unwrap(), "{report}");
    let signatures = run(&central, &["audit", "log", "claim_signature", "--json"]);
    assert!(signatures.status.success(), "{}", stderr(&signatures));
    let logged: Value = serde_json::from_str(&stdout(&signatures)).unwrap();
    assert_eq!(logged.as_array().unwrap().len(), 2);
    assert_eq!(logged[0]["payload"]["key_id"], key_id);
    assert_eq!(logged[0]["payload"]["schema"], "trit-claim-sign-v1");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn signed_claim_policy_rejects_unsigned_writes_before_ledger_change() {
    let root = temp("signed-policy");
    let central = root.join("central");
    init(&central);
    let central_text = path_text(&central);
    let set = run(
        &central,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:admin",
            "--require-signed-claims",
            "--json",
        ],
    );
    assert!(set.status.success(), "{}", stderr(&set));
    let shown = run(&central, &["policy", "--json"]);
    let policy: Value = serde_json::from_str(&stdout(&shown)).unwrap();
    assert_eq!(policy["require_signed_claims"], true);

    let unsigned = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "blocked",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
            "--json",
        ],
    );
    assert!(!unsigned.status.success());
    let failure: Value = serde_json::from_str(&stdout(&unsigned)).unwrap();
    assert_eq!(failure["error"]["kind"], "claims_signature_required");
    assert!(!central.join(".tritvcs").join("claims.json").exists());

    trust_key(&root, &central, "author.key", "qoder:a", "author");
    let key_path = path_text(&root.join("author.key"));
    let signed = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "allowed",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
            "--sign-key",
            &key_path,
            "--json",
        ],
    );
    assert!(signed.status.success(), "{}", stderr(&signed));
    let malformed = run(
        &root,
        &[
            "claims",
            "release",
            "--central",
            &central_text,
            "--id",
            "allowed",
            "--owner",
            "qoder:a",
            "--sign-key",
        ],
    );
    assert_eq!(malformed.status.code(), Some(2));
    assert!(stderr(&malformed).contains("--sign-key"));
    assert!(audit(&central)["ok"].as_bool().unwrap());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn historical_unsigned_claims_remain_valid_after_policy_enablement() {
    let root = temp("signed-history");
    let central = root.join("central");
    init(&central);
    let central_text = path_text(&central);
    let added = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "legacy",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
        ],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    assert!(audit(&central)["ok"].as_bool().unwrap());
    let set = run(
        &central,
        &[
            "policy",
            "set",
            "--owner",
            "qoder:admin",
            "--require-signed-claims",
        ],
    );
    assert!(set.status.success(), "{}", stderr(&set));
    assert!(audit(&central)["ok"].as_bool().unwrap());

    trust_key(&root, &central, "author.key", "qoder:a", "author");
    let key_path = path_text(&root.join("author.key"));
    let unsigned = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "new-unsigned",
            "--owner",
            "qoder:a",
            "--path",
            "b.rs",
        ],
    );
    assert!(!unsigned.status.success());
    assert!(stderr(&unsigned).contains("claims_signature_required"));

    let disabled = run(
        &central,
        &["policy", "set", "--owner", "qoder:admin", "--json"],
    );
    assert!(disabled.status.success(), "{}", stderr(&disabled));
    let journal_path = central.join(".tritvcs").join("journal.jsonl");
    let baseline_journal = root.join("baseline-journal.jsonl");
    fs::copy(&journal_path, &baseline_journal).unwrap();
    rewrite_journal(&central, &baseline_journal, |events| {
        let policy_index = events
            .iter()
            .rposition(|event| event["kind"] == "policy")
            .unwrap();
        events[policy_index]["payload"]
            .as_object_mut()
            .unwrap()
            .remove("require_signed_claims");
        events[policy_index]["payload"]
            .as_object_mut()
            .unwrap()
            .remove("schema");
    });
    let allowed_after_disable = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "new-unsigned",
            "--owner",
            "qoder:a",
            "--path",
            "b.rs",
        ],
    );
    assert!(
        allowed_after_disable.status.success(),
        "{}",
        stderr(&allowed_after_disable)
    );
    assert!(audit(&central)["ok"].as_bool().unwrap());

    let released = run(
        &root,
        &[
            "claims",
            "release",
            "--central",
            &central_text,
            "--id",
            "legacy",
            "--owner",
            "qoder:a",
            "--sign-key",
            &key_path,
        ],
    );
    assert!(released.status.success(), "{}", stderr(&released));
    assert!(audit(&central)["ok"].as_bool().unwrap());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn claim_signer_requires_matching_author_principal_and_public_key() {
    let root = temp("signed-authz");
    let central = root.join("central");
    init(&central);
    let central_text = path_text(&central);
    let author_id = trust_key(&root, &central, "author.key", "qoder:a", "author");
    trust_key(&root, &central, "auditor.key", "qoder:audit", "auditor");
    let author_path = path_text(&root.join("author.key"));
    let auditor_path = path_text(&root.join("auditor.key"));

    let mismatch = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "mismatch",
            "--owner",
            "zcode:z",
            "--path",
            "a.rs",
            "--sign-key",
            &author_path,
        ],
    );
    assert!(!mismatch.status.success());
    assert!(stderr(&mismatch).contains("claims_signature_rejected"));
    let wrong_role = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "auditor",
            "--owner",
            "qoder:audit",
            "--path",
            "a.rs",
            "--sign-key",
            &auditor_path,
        ],
    );
    assert!(!wrong_role.status.success());
    assert!(stderr(&wrong_role).contains("claims_signature_rejected"));
    assert!(!central.join(".tritvcs").join("claims.json").exists());

    let untrusted_path = root.join("untrusted.key");
    let untrusted_text = path_text(&untrusted_path);
    let generated = run(&root, &["key", "init", "--out", &untrusted_text, "--json"]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    let untrusted_value: Value = serde_json::from_str(&stdout(&generated)).unwrap();
    let untrusted_id = untrusted_value["key_id"].as_str().unwrap();
    let untrusted = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "untrusted",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
            "--sign-key",
            &untrusted_text,
        ],
    );
    assert!(!untrusted.status.success());
    assert!(stderr(&untrusted).contains("不在中央仓信任表"));
    let added = run(
        &root,
        &[
            "key",
            "add",
            "--key-id",
            untrusted_id,
            "--principal",
            "qoder:a",
            "--role",
            "author",
            "--owner",
            "qoder:key-admin",
            "--repo",
            &central_text,
        ],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    let missing_public = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "no-public",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
            "--sign-key",
            &untrusted_text,
        ],
    );
    assert!(!missing_public.status.success());
    assert!(stderr(&missing_public).contains("没有公钥"));
    let keys_path = central.join(".tritvcs").join("keys.json");
    let trusted_keys = fs::read(&keys_path).unwrap();
    let mut keys: Value = serde_json::from_slice(&trusted_keys).unwrap();
    keys["keys"][untrusted_id]["public_key"] = keys["keys"][&author_id]["public_key"].clone();
    fs::write(&keys_path, serde_json::to_vec_pretty(&keys).unwrap()).unwrap();
    let mismatched_public = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "bad-public",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
            "--sign-key",
            &untrusted_text,
        ],
    );
    assert!(!mismatched_public.status.success());
    assert!(stderr(&mismatched_public).contains("公钥或指纹"));
    fs::write(keys_path, trusted_keys).unwrap();
    assert!(audit(&central)["ok"].as_bool().unwrap());
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn revoked_key_cannot_sign_but_historical_signature_stays_valid() {
    let root = temp("signed-revoke");
    let central = root.join("central");
    init(&central);
    let central_text = path_text(&central);
    let key_id = trust_key(&root, &central, "author.key", "qoder:a", "author");
    let key_path = path_text(&root.join("author.key"));
    let added = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "before-revoke",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
            "--sign-key",
            &key_path,
        ],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    let revoked = run(
        &central,
        &[
            "key",
            "revoke",
            "--key-id",
            &key_id,
            "--reason",
            "incident",
            "--owner",
            "qoder:key-admin",
        ],
    );
    assert!(revoked.status.success(), "{}", stderr(&revoked));
    assert!(audit(&central)["ok"].as_bool().unwrap());
    let denied = run(
        &root,
        &[
            "claims",
            "add",
            "--central",
            &central_text,
            "--id",
            "after-revoke",
            "--owner",
            "qoder:a",
            "--path",
            "b.rs",
            "--sign-key",
            &key_path,
        ],
    );
    assert!(!denied.status.success());
    assert!(stderr(&denied).contains("已吊销"));
    let events = journal_events(&central);
    let signed_at = events[event_index(&events, "claim_signature")]["payload"]["signed_at_ms"]
        .as_u64()
        .unwrap();
    let keys: Value = serde_json::from_str(
        &fs::read_to_string(central.join(".tritvcs").join("keys.json")).unwrap(),
    )
    .unwrap();
    assert!(keys["keys"][&key_id]["revoked_at_ms"].as_u64().unwrap() >= signed_at);
    let _ = fs::remove_dir_all(&root);
}
