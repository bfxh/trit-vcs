use super::*;

#[test]
fn claim_signature_audit_rejects_tampering_and_broken_authorization() {
    let root = temp("signed-tamper");
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
            "tamper-target",
            "--owner",
            "qoder:a",
            "--path",
            "a.rs",
            "--sign-key",
            &key_path,
        ],
    );
    assert!(added.status.success(), "{}", stderr(&added));
    let baseline_journal = root.join("baseline-journal.jsonl");
    fs::copy(
        central.join(".tritvcs").join("journal.jsonl"),
        &baseline_journal,
    )
    .unwrap();
    let baseline_keys = root.join("baseline-keys.json");
    fs::copy(central.join(".tritvcs").join("keys.json"), &baseline_keys).unwrap();
    let other_path = root.join("other.key");
    let other_text = path_text(&other_path);
    let generated = run(&root, &["key", "init", "--out", &other_text, "--json"]);
    assert!(generated.status.success(), "{}", stderr(&generated));
    let other: Value = serde_json::from_str(&stdout(&generated)).unwrap();
    let other_public = other["public"].clone();
    let zero_hash = "0".repeat(64);

    for case in [
        "signature",
        "schema",
        "algorithm",
        "action",
        "operation",
        "claim_event",
        "claim_fields",
        "claim_paths",
        "claim_state",
        "claim_operation",
        "state_after",
        "state_before",
        "signed_at",
        "principal",
        "signed_flag",
        "missing_signature",
        "policy_unsigned",
        "result_status",
        "result_state_after",
        "revoked_before_begin",
        "revoked_during",
        "rotated_during",
        "duplicate",
        "role",
        "missing_public",
        "fingerprint",
        "trust_public",
        "revoked",
        "key_added_later",
    ] {
        fs::write(
            central.join(".tritvcs").join("keys.json"),
            fs::read(&baseline_keys).unwrap(),
        )
        .unwrap();
        rewrite_journal(&central, &baseline_journal, |events| {
            let signature_index = event_index(events, "claim_signature");
            let claim_index = event_index(events, "claim_add");
            if case == "fingerprint" {
                let key_index = events
                    .iter()
                    .position(|event| {
                        event["kind"] == "key"
                            && event["payload"]["action"] == "add"
                            && event["payload"]["key_id"] == key_id
                    })
                    .unwrap();
                events[key_index]["payload"]["public_key"] = Value::Null;
            }
            match case {
                "signature" => {
                    let old = events[signature_index]["payload"]["signature"]
                        .as_str()
                        .unwrap();
                    let first = if old.starts_with('0') { '1' } else { '0' };
                    events[signature_index]["payload"]["signature"] =
                        json!(format!("{first}{}", &old[1..]));
                }
                "schema" => events[signature_index]["payload"]["schema"] = json!("bad"),
                "algorithm" => events[signature_index]["payload"]["algorithm"] = json!("rsa"),
                "action" => events[signature_index]["payload"]["action"] = json!("claim_release"),
                "operation" => events[signature_index]["payload"]["operation"] = json!(zero_hash),
                "claim_event" => {
                    events[signature_index]["payload"]["claim_event"] = json!(zero_hash)
                }
                "claim_fields" => events[claim_index]["payload"]["claim"]["owner"] = json!("evil"),
                "claim_paths" => {
                    events[claim_index]["payload"]["path_list"] = json!(["a.rs", "b.rs"])
                }
                "claim_state" => events[claim_index]["payload"]["state_after"] = json!(zero_hash),
                "claim_operation" => events[claim_index]["payload"]["operation"] = json!(zero_hash),
                "state_after" => {
                    events[signature_index]["payload"]["state_after"] = json!(zero_hash)
                }
                "state_before" => {
                    events[signature_index]["payload"]["state_before"] = json!(zero_hash)
                }
                "signed_at" => {
                    let old = events[signature_index]["payload"]["signed_at_ms"]
                        .as_u64()
                        .unwrap();
                    events[signature_index]["payload"]["signed_at_ms"] = json!(old + 1);
                }
                "principal" => events[signature_index]["payload"]["principal"] = json!("evil"),
                "signed_flag" => events[claim_index]["payload"]["signed"] = json!(false),
                "missing_signature" => {
                    events.remove(signature_index);
                }
                "policy_unsigned" => {
                    events.remove(signature_index);
                    let claim_index = event_index(events, "claim_add");
                    let begin_index = (0..claim_index)
                        .rev()
                        .find(|&index| events[index]["kind"] == "op_begin")
                        .unwrap();
                    let at_ms = events[begin_index]["at_ms"].clone();
                    let state_before = events[begin_index]["payload"]["state_before"].clone();
                    events[claim_index]["payload"]["signed"] = json!(false);
                    events.insert(
                        begin_index,
                        json!({
                            "seq": 0,
                            "at_ms": at_ms,
                            "kind": "policy",
                            "payload": {
                                "session": "qoder:admin",
                                "require_witness": false,
                                "require_intent": false,
                                "require_signed_claims": true,
                                "policy_hash": Hash::of(b"policy").as_bytes().to_vec(),
                                "state_before": state_before,
                                "state_after": state_before,
                            },
                            "prev": Value::Null,
                            "hash": [],
                        }),
                    );
                }
                "result_status" => {
                    events.last_mut().unwrap()["payload"]["status"] = json!("failed")
                }
                "result_state_after" => {
                    events.last_mut().unwrap()["payload"]["state_after"] = json!(zero_hash)
                }
                "revoked_before_begin" | "revoked_during" | "rotated_during" => {
                    let claim_index = event_index(events, "claim_add");
                    let begin_index = (0..claim_index)
                        .rev()
                        .find(|&index| events[index]["kind"] == "op_begin")
                        .unwrap();
                    let result_index = events
                        .iter()
                        .rposition(|event| event["kind"] == "op_result")
                        .unwrap();
                    let insert_at = if case == "revoked_before_begin" {
                        begin_index
                    } else {
                        result_index
                    };
                    let state = events[begin_index]["payload"]["state_before"].clone();
                    let payload = if case == "rotated_during" {
                        json!({
                            "action": "rotate",
                            "key_id": "ed25519:replacement",
                            "old_key_id": key_id,
                            "state_before": state,
                            "state_after": state,
                        })
                    } else {
                        json!({
                            "action": "revoke",
                            "key_id": key_id,
                            "state_before": state,
                            "state_after": state,
                        })
                    };
                    events.insert(
                        insert_at,
                        json!({
                            "seq": 0,
                            "at_ms": events[begin_index]["at_ms"],
                            "kind": "key",
                            "payload": payload,
                            "prev": Value::Null,
                            "hash": [],
                        }),
                    );
                }
                "duplicate" => events.insert(signature_index + 1, events[signature_index].clone()),
                "key_added_later" => {
                    events.retain(|event| {
                        !(event["kind"] == "key"
                            && event["payload"]["action"] == "add"
                            && event["payload"]["key_id"] == key_id)
                    });
                    rechain(events);
                    let signature_index = event_index(events, "claim_signature");
                    let claim_index = event_index(events, "claim_add");
                    let begin_index = (0..claim_index)
                        .rev()
                        .find(|&index| events[index]["kind"] == "op_begin")
                        .unwrap();
                    let operation = value_hash(&events[begin_index]["hash"]);
                    events[claim_index]["payload"]["operation"] = json!(operation.to_hex());
                    let claim_previous = value_hash(&events[begin_index]["hash"]);
                    let claim_event =
                        event_hash(&events[claim_index], claim_index, Some(claim_previous));
                    events[signature_index]["payload"]["operation"] = json!(operation.to_hex());
                    events[signature_index]["payload"]["claim_event"] = json!(claim_event.to_hex());
                    let result_index = events
                        .iter()
                        .rposition(|event| event["kind"] == "op_result")
                        .unwrap();
                    events[result_index]["payload"]["begin_hash"] = json!(operation.to_hex());
                }
                "role" | "missing_public" | "fingerprint" | "trust_public" | "revoked" => {
                    let mut keys: Value = serde_json::from_slice(
                        &fs::read(central.join(".tritvcs").join("keys.json")).unwrap(),
                    )
                    .unwrap();
                    match case {
                        "role" => keys["keys"][&key_id]["role"] = json!("auditor"),
                        "missing_public" => keys["keys"][&key_id]["public_key"] = Value::Null,
                        "fingerprint" | "trust_public" => {
                            keys["keys"][&key_id]["public_key"] = other_public.clone()
                        }
                        "revoked" => {
                            let signed_at = events[signature_index]["payload"]["signed_at_ms"]
                                .as_u64()
                                .unwrap();
                            keys["keys"][&key_id]["revoked_at_ms"] = json!(signed_at - 1);
                            keys["keys"][&key_id]["revoke_reason"] = json!("incident");
                        }
                        _ => unreachable!(),
                    }
                    fs::write(
                        central.join(".tritvcs").join("keys.json"),
                        serde_json::to_vec_pretty(&keys).unwrap(),
                    )
                    .unwrap();
                    sync_latest_state(&central, events);
                }
                _ => unreachable!(),
            }
            if matches!(
                case,
                "claim_fields" | "claim_paths" | "claim_state" | "claim_operation" | "signed_flag"
            ) {
                let previous = value_hash(&events[claim_index - 1]["hash"]);
                let repaired = event_hash(&events[claim_index], claim_index, Some(previous));
                events[signature_index]["payload"]["claim_event"] = json!(repaired.to_hex());
            }
            if matches!(
                case,
                "revoked_before_begin"
                    | "revoked_during"
                    | "rotated_during"
                    | "trust_public"
                    | "fingerprint"
            ) {
                rechain(events);
                let signature_index = event_index(events, "claim_signature");
                let claim_index = event_index(events, "claim_add");
                let begin_index = (0..claim_index)
                    .rev()
                    .find(|&index| events[index]["kind"] == "op_begin")
                    .unwrap();
                let result_index = events
                    .iter()
                    .rposition(|event| event["kind"] == "op_result")
                    .unwrap();
                let operation = value_hash(&events[begin_index]["hash"]);
                events[claim_index]["payload"]["operation"] = json!(operation.to_hex());
                let claim_event = event_hash(&events[claim_index], claim_index, Some(operation));
                events[signature_index]["payload"]["operation"] = json!(operation.to_hex());
                events[signature_index]["payload"]["claim_event"] = json!(claim_event.to_hex());
                events[result_index]["payload"]["begin_hash"] = json!(operation.to_hex());
            }
        });
        let report = audit_report(&central);
        assert!(
            !report["ok"].as_bool().unwrap(),
            "篡改 {case} 竟然通过：{report}"
        );
        let expected = match case {
            "signature" | "signed_at" => "claim_signature_invalid",
            "operation" | "claim_event" | "action" | "claim_operation" | "signed_flag"
            | "result_status" | "result_state_after" => "claim_signature_operation",
            "principal" | "role" | "missing_public" | "fingerprint" | "trust_public"
            | "key_added_later" => "claim_signature_untrusted",
            "revoked" | "revoked_before_begin" | "revoked_during" | "rotated_during" => {
                "claim_signature_revoked"
            }
            "missing_signature" | "policy_unsigned" => "claim_signature_missing",
            _ => "claim_signature_bad",
        };
        assert!(
            has_issue(&report, expected),
            "篡改 {case} 缺 {expected}：{report}"
        );
    }

    let _ = fs::remove_dir_all(&root);
}
