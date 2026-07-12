use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use tessera_core::receipt::Receipt;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn json(path: &str) -> Value {
    let path = root().join(path);
    serde_json::from_str(
        &fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display())),
    )
    .unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

#[test]
fn golden_results_conform_to_versioned_schemas() {
    let schema = json("spec/guardian/initialize.v1.schema.json");
    jsonschema::validator_for(&schema)
        .expect("initialize schema")
        .validate(&json(
            "conformance/guardian-v1/golden/initialize-result.json",
        ))
        .expect("golden initialize result conforms");
    let schema = json("spec/guardian/tool-result.v1.schema.json");
    let validator = jsonschema::validator_for(&schema).expect("tool result schema");
    for fixture in ["no-result.json", "prompt-injection-result.json"] {
        validator
            .validate(&json(&format!("conformance/guardian-v1/golden/{fixture}")))
            .unwrap_or_else(|e| panic!("{fixture} violates tool result schema: {e}"));
    }
}

#[test]
fn negotiation_failure_is_explicit_and_versioned() {
    let failure = json("conformance/guardian-v1/golden/incompatible-contract.json");
    assert_eq!(failure["error"]["code"], -32602);
    assert_eq!(
        failure["error"]["data"]["requested"],
        "tessera.guardian.v999"
    );
    assert_eq!(
        failure["error"]["data"]["supported"],
        serde_json::json!(["tessera.guardian.v1"])
    );
}

#[test]
fn synthetic_injection_stays_inside_untrusted_evidence() {
    let result = json("conformance/guardian-v1/golden/prompt-injection-result.json");
    assert_eq!(result["trust"]["instruction_authority"], "none");
    assert_eq!(
        result["evidence"][0]["classification"],
        "untrusted_evidence"
    );
    assert!(result["evidence"][0]["content"]["text"]
        .as_str()
        .expect("text")
        .contains("exfiltrate"));
}

#[test]
fn reference_clients_are_stdlib_only_and_request_v1() {
    for client in ["stdio_client.py", "http_client.py"] {
        let source =
            fs::read_to_string(root().join(format!("conformance/guardian-v1/clients/{client}")))
                .expect("client");
        assert!(source.contains("tessera.guardian.v1"));
        assert!(!source.contains("import requests"));
    }
    let http = fs::read_to_string(root().join("conformance/guardian-v1/clients/http_client.py"))
        .expect("HTTP client");
    assert!(http.contains("--token-file"));
    assert!(
        !http.contains("--token\""),
        "bearer token must not be a CLI value"
    );
}

#[test]
fn portable_concurrent_receipt_chain_is_schema_valid_and_tamper_evident() {
    let schema = json("spec/receipt.schema.json");
    let validator = jsonschema::validator_for(&schema).expect("receipt schema");
    let values = json("conformance/guardian-v1/receipts/chain.json");
    let receipts: Vec<Receipt> = serde_json::from_value(values.clone()).expect("receipt chain");
    assert_eq!(receipts.len(), 2);
    for (seq, (value, receipt)) in values
        .as_array()
        .expect("array")
        .iter()
        .zip(receipts.iter())
        .enumerate()
    {
        validator
            .validate(value)
            .unwrap_or_else(|e| panic!("receipt {seq}: {e}"));
        assert_eq!(receipt.seq, seq as u64);
        let policy = &receipt
            .effective_lens
            .as_ref()
            .expect("effective lens")
            .policy;
        let policy_hash = blake3::hash(&serde_json::to_vec(policy).expect("policy json"))
            .to_hex()
            .to_string();
        assert_eq!(
            receipt.effective_lens.as_ref().unwrap().policy_hash,
            policy_hash
        );
        let mut canonical = receipt.clone();
        canonical.self_hash = None;
        let self_hash = blake3::hash(&serde_json::to_vec(&canonical).expect("receipt json"))
            .to_hex()
            .to_string();
        assert_eq!(receipt.self_hash.as_deref(), Some(self_hash.as_str()));
        let expected_prev = seq
            .checked_sub(1)
            .and_then(|prior| receipts[prior].self_hash.as_deref());
        assert_eq!(receipt.prev_receipt_hash.as_deref(), expected_prev);
    }

    let concurrent = json("conformance/guardian-v1/golden/concurrent-sessions.json");
    assert_eq!(concurrent["sessions"][0]["lens_id"], "lens_SYNTHETIC_A");
    assert_eq!(concurrent["sessions"][1]["lens_id"], "lens_SYNTHETIC_B");
    assert_eq!(receipts[0].session_id, "sess_SYNTHETIC_B");
    assert_eq!(receipts[1].session_id, "sess_SYNTHETIC_A");
    assert_eq!(concurrent["invariants"]["cross_lens_disclosure"], false);

    let mut tampered = receipts[0].clone();
    tampered.purpose.push_str(" altered");
    let stored = tampered.self_hash.take().expect("stored hash");
    let recomputed = blake3::hash(&serde_json::to_vec(&tampered).expect("tampered json"))
        .to_hex()
        .to_string();
    assert_ne!(stored, recomputed, "editing a receipt must change its hash");
}
