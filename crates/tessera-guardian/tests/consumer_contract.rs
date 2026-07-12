use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};

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
}
