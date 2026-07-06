//! Lens policy model, schema validation, and storage.
//!
//! A Lens defines what an agent can see and how — the core access control
//! primitive in Tessera. A policy is persisted as JSON (the `policy_json`
//! column), and every write is validated against the canonical schema
//! (`spec/lens-policy.schema.json`) so that invalid policies are rejected
//! with field-level errors before they ever reach the database.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::artifact::Sensitivity;
use crate::space::SpaceId;
use crate::vault::{Vault, VaultError};

/// The canonical lens-policy JSON Schema, embedded at build time. This is the
/// exact file shipped in `spec/` — validation and the spec never drift.
const POLICY_SCHEMA_SRC: &str = include_str!("../../../../spec/lens-policy.schema.json");

#[derive(Error, Debug)]
pub enum LensError {
    #[error("lens not found: {0}")]
    NotFound(String),
    /// The policy failed schema validation. The message carries one line per
    /// offending field: `<field>: <reason>`.
    #[error("invalid lens policy:\n{0}")]
    Invalid(String),
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

/// Typed wrapper for lens identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LensId(pub String);

/// How much of an artifact is revealed to an agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisclosureMode {
    /// Artifact metadata + one-sentence summary. No verbatim text.
    Summary,
    /// Artifact metadata + verbatim excerpts up to `max_quote_chars`.
    Excerpt,
    /// Complete artifact content.
    Full,
}

impl DisclosureMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            DisclosureMode::Summary => "summary",
            DisclosureMode::Excerpt => "excerpt",
            DisclosureMode::Full => "full",
        }
    }
}

/// When user approval is required for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalRule {
    /// Never require approval (auto-approve).
    Never,
    /// Always require explicit user approval.
    Always,
    /// Require approval only for sensitive artifacts.
    OnSensitive,
}

impl ApprovalRule {
    pub fn as_str(&self) -> &'static str {
        match self {
            ApprovalRule::Never => "never",
            ApprovalRule::Always => "always",
            ApprovalRule::OnSensitive => "on_sensitive",
        }
    }
}

fn default_true() -> bool {
    true
}
fn default_ttl() -> u32 {
    60
}
fn default_sensitivity() -> Sensitivity {
    Sensitivity::Internal
}
fn default_approval() -> ApprovalRule {
    ApprovalRule::OnSensitive
}

/// A reusable access policy defining what an agent can see and how.
///
/// The serde field names and defaults mirror `spec/lens-policy.schema.json`
/// exactly (enforced by `schema_and_struct_stay_in_sync`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LensPolicy {
    pub id: LensId,
    pub name: String,
    pub space_ids: Vec<SpaceId>,
    #[serde(default)]
    pub space_exclude_ids: Vec<SpaceId>,
    #[serde(default)]
    pub tag_include: Vec<String>,
    #[serde(default)]
    pub tag_exclude: Vec<String>,
    /// Coarse file-type hints (v3 semantics: `pdf`, `docx`, `md`). Retained
    /// for compatibility; not yet compiled into retrieval.
    #[serde(default)]
    pub content_types: Vec<String>,
    /// Allowed artifact media types (MIME, e.g. `text/markdown`). This is the
    /// active media filter — it compiles into `RetrievalConstraints`.
    #[serde(default)]
    pub media_types: Vec<String>,
    pub disclosure_mode: DisclosureMode,
    // Omitted entirely when absent: the schema types this as an integer, so a
    // serialized `null` (from `None`) would fail validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_quote_chars: Option<u32>,
    #[serde(default = "default_true")]
    pub allow_metadata: bool,
    pub operations: Vec<String>,
    #[serde(default = "default_sensitivity")]
    pub sensitivity_ceiling: Sensitivity,
    #[serde(default = "default_approval")]
    pub approval_rule: ApprovalRule,
    #[serde(default = "default_ttl")]
    pub default_ttl_minutes: u32,
    #[serde(default = "now")]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default = "now")]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

fn now() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now()
}

impl LensPolicy {
    /// Build a policy with a fresh id, current timestamps, and schema
    /// defaults. Callers refine fields before `create`.
    pub fn new(name: impl Into<String>, space_ids: Vec<SpaceId>) -> Self {
        let ts = now();
        Self {
            id: LensId(format!("lens_{}", ulid::Ulid::new())),
            name: name.into(),
            space_ids,
            space_exclude_ids: Vec::new(),
            tag_include: Vec::new(),
            tag_exclude: Vec::new(),
            content_types: Vec::new(),
            media_types: Vec::new(),
            disclosure_mode: DisclosureMode::Summary,
            max_quote_chars: None,
            allow_metadata: true,
            operations: vec!["answer".to_string()],
            sensitivity_ceiling: Sensitivity::Internal,
            approval_rule: ApprovalRule::OnSensitive,
            default_ttl_minutes: 60,
            created_at: ts,
            updated_at: ts,
        }
    }
}

/// The compiled schema validator, built once per process from the embedded
/// spec. Returns an owned error only if the embedded schema itself is
/// malformed (a build-time bug surfaced at first use).
fn validator() -> Result<&'static jsonschema::Validator, LensError> {
    static VALIDATOR: OnceLock<Result<jsonschema::Validator, String>> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| {
            let schema: serde_json::Value =
                serde_json::from_str(POLICY_SCHEMA_SRC).map_err(|e| e.to_string())?;
            jsonschema::validator_for(&schema).map_err(|e| e.to_string())
        })
        .as_ref()
        .map_err(|e| LensError::Invalid(format!("embedded schema is invalid: {e}")))
}

/// Validate an already-parsed JSON value against the policy schema. Collects
/// every violation as a `<field>: <reason>` line.
fn validate_value(instance: &serde_json::Value) -> Result<(), LensError> {
    let validator = validator()?;
    let mut errors: Vec<String> = validator
        .iter_errors(instance)
        .map(|e| {
            let path = e.instance_path().to_string();
            let field = path.trim_start_matches('/').replace('/', ".");
            let field = if field.is_empty() { "(root)" } else { &field };
            format!("{field}: {e}")
        })
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        errors.sort();
        Err(LensError::Invalid(errors.join("\n")))
    }
}

/// Validate a policy against the schema. Callers get field-level errors.
pub fn validate(policy: &LensPolicy) -> Result<(), LensError> {
    validate_value(&serde_json::to_value(policy)?)
}

/// Parse JSON into a policy, rejecting it with field-level errors if it does
/// not satisfy the schema. Schema validation runs against the raw JSON first,
/// so structural problems surface as schema errors, not opaque serde errors.
pub fn from_json(json: &str) -> Result<LensPolicy, LensError> {
    let instance: serde_json::Value = serde_json::from_str(json)?;
    validate_value(&instance)?;
    Ok(serde_json::from_value(instance)?)
}

/// Serialize a policy to pretty JSON (for `lens show` / `lens edit`).
pub fn to_json(policy: &LensPolicy) -> Result<String, LensError> {
    Ok(serde_json::to_string_pretty(policy)?)
}

/// Persist a new lens. The policy is validated before insertion.
pub fn create(vault: &Vault, policy: &LensPolicy) -> Result<LensId, LensError> {
    validate(policy)?;
    let json = serde_json::to_string(policy)?;
    vault.conn().execute(
        "INSERT INTO lenses (id, name, policy_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            policy.id.0,
            policy.name,
            json,
            policy.created_at.to_rfc3339(),
            policy.updated_at.to_rfc3339(),
        ],
    )?;
    Ok(policy.id.clone())
}

/// List all lenses, newest first.
pub fn list(vault: &Vault) -> Result<Vec<LensPolicy>, LensError> {
    let mut stmt = vault
        .conn()
        .prepare("SELECT policy_json FROM lenses ORDER BY created_at DESC, id DESC")?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    rows.iter()
        .map(|json| Ok(serde_json::from_str(json)?))
        .collect()
}

/// Fetch one lens by id.
pub fn get(vault: &Vault, id: &LensId) -> Result<LensPolicy, LensError> {
    let json: String = vault
        .conn()
        .query_row(
            "SELECT policy_json FROM lenses WHERE id = ?1",
            [id.0.as_str()],
            |r| r.get(0),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => LensError::NotFound(id.0.clone()),
            other => LensError::Database(other),
        })?;
    Ok(serde_json::from_str(&json)?)
}

/// Replace an existing lens's policy. Validates, bumps `updated_at`, and
/// preserves the original `created_at`. The `policy.id` selects the row.
pub fn update(vault: &Vault, policy: &LensPolicy) -> Result<(), LensError> {
    // Preserve the original creation time regardless of what the caller sent.
    let created_at = get(vault, &policy.id)?.created_at;
    let mut stored = policy.clone();
    stored.created_at = created_at;
    stored.updated_at = now();
    validate(&stored)?;

    let json = serde_json::to_string(&stored)?;
    let changed = vault.conn().execute(
        "UPDATE lenses SET name = ?1, policy_json = ?2, updated_at = ?3 WHERE id = ?4",
        rusqlite::params![
            stored.name,
            json,
            stored.updated_at.to_rfc3339(),
            stored.id.0
        ],
    )?;
    if changed == 0 {
        return Err(LensError::NotFound(policy.id.0.clone()));
    }
    Ok(())
}

/// Delete a lens by id.
pub fn delete(vault: &Vault, id: &LensId) -> Result<(), LensError> {
    let changed = vault
        .conn()
        .execute("DELETE FROM lenses WHERE id = ?1", [id.0.as_str()])?;
    if changed == 0 {
        return Err(LensError::NotFound(id.0.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::KdfParams;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    fn test_vault() -> (tempfile::TempDir, Vault) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create vault");
        (dir, vault)
    }

    fn sample() -> LensPolicy {
        let mut p = LensPolicy::new("Client specs", vec![SpaceId("space_A".into())]);
        p.operations = vec!["answer".into(), "cite".into()];
        p.disclosure_mode = DisclosureMode::Excerpt;
        p.max_quote_chars = Some(800);
        p.media_types = vec!["text/markdown".into()];
        p
    }

    #[test]
    fn create_get_list_roundtrip() {
        let (_dir, vault) = test_vault();
        let p = sample();
        let id = create(&vault, &p).expect("create");

        let fetched = get(&vault, &id).expect("get");
        assert_eq!(fetched, p, "stored policy round-trips byte-for-byte");

        let all = list(&vault).expect("list");
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].id, id);
    }

    #[test]
    fn update_preserves_created_bumps_updated() {
        let (_dir, vault) = test_vault();
        let p = sample();
        let id = create(&vault, &p).expect("create");
        let original_created = p.created_at;

        let mut edited = get(&vault, &id).expect("get");
        edited.name = "Renamed".into();
        // Caller tampers with created_at — update must ignore it.
        edited.created_at = chrono::DateTime::<chrono::Utc>::MIN_UTC;
        update(&vault, &edited).expect("update");

        let after = get(&vault, &id).expect("get");
        assert_eq!(after.name, "Renamed");
        assert_eq!(after.created_at, original_created, "created_at preserved");
        assert!(after.updated_at >= original_created, "updated_at bumped");
    }

    #[test]
    fn delete_removes_lens() {
        let (_dir, vault) = test_vault();
        let id = create(&vault, &sample()).expect("create");
        delete(&vault, &id).expect("delete");
        assert!(matches!(get(&vault, &id), Err(LensError::NotFound(_))));
        assert!(matches!(delete(&vault, &id), Err(LensError::NotFound(_))));
    }

    #[test]
    fn get_and_update_missing_are_not_found() {
        let (_dir, vault) = test_vault();
        let ghost = LensId("lens_NOPE".into());
        assert!(matches!(get(&vault, &ghost), Err(LensError::NotFound(_))));
        let mut p = sample();
        p.id = ghost;
        assert!(matches!(update(&vault, &p), Err(LensError::NotFound(_))));
    }

    #[test]
    fn empty_space_ids_rejected_with_field_error() {
        let mut p = sample();
        p.space_ids = vec![];
        let err = validate(&p).expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("space_ids"),
            "field-level error names the field: {msg}"
        );
    }

    #[test]
    fn empty_operations_rejected_with_field_error() {
        let mut p = sample();
        p.operations = vec![];
        let err = validate(&p).expect_err("must reject");
        assert!(err.to_string().contains("operations"));
    }

    #[test]
    fn unknown_operation_rejected() {
        let mut p = sample();
        p.operations = vec!["exfiltrate".into()];
        let err = validate(&p).expect_err("must reject");
        assert!(err.to_string().contains("operations"));
    }

    #[test]
    fn create_rejects_invalid_policy_before_insert() {
        let (_dir, vault) = test_vault();
        let mut p = sample();
        p.operations = vec![];
        assert!(matches!(create(&vault, &p), Err(LensError::Invalid(_))));
        // Nothing was written.
        assert_eq!(list(&vault).expect("list").len(), 0);
    }

    #[test]
    fn from_json_rejects_bad_enum() {
        let json = r#"{
            "id": "lens_x", "name": "x",
            "space_ids": ["space_A"],
            "disclosure_mode": "peek",
            "operations": ["answer"]
        }"#;
        let err = from_json(json).expect_err("bad disclosure_mode");
        assert!(err.to_string().contains("disclosure_mode"));
    }

    #[test]
    fn from_json_applies_schema_defaults() {
        // Minimal valid policy: only required fields present.
        let json = r#"{
            "id": "lens_min", "name": "Minimal",
            "space_ids": ["space_A"],
            "disclosure_mode": "summary",
            "operations": ["answer"]
        }"#;
        let p = from_json(json).expect("valid minimal policy");
        assert!(p.allow_metadata, "allow_metadata defaults true");
        assert_eq!(p.default_ttl_minutes, 60);
        assert_eq!(p.sensitivity_ceiling, Sensitivity::Internal);
        assert_eq!(p.approval_rule, ApprovalRule::OnSensitive);
        assert!(p.media_types.is_empty());
    }

    /// The acceptance guard: the Rust struct's serialized field set must match
    /// the schema's declared properties exactly. Adding a field to one without
    /// the other fails here.
    #[test]
    fn schema_and_struct_stay_in_sync() {
        use std::collections::BTreeSet;

        let schema: serde_json::Value =
            serde_json::from_str(POLICY_SCHEMA_SRC).expect("schema parses");
        let schema_fields: BTreeSet<String> = schema["properties"]
            .as_object()
            .expect("properties object")
            .keys()
            .cloned()
            .collect();

        let value = serde_json::to_value(sample()).expect("serialize");
        let struct_fields: BTreeSet<String> = value
            .as_object()
            .expect("policy object")
            .keys()
            .cloned()
            .collect();

        assert_eq!(
            struct_fields, schema_fields,
            "LensPolicy fields and schema properties drifted"
        );
    }

    /// A fully-populated policy must satisfy its own schema — guards against
    /// enum rename drift between the struct and the schema's enum lists.
    #[test]
    fn default_summary_policy_validates() {
        // The out-of-the-box policy: summary disclosure, no max_quote_chars.
        // `None` must serialize as an ABSENT field, not `null`, or the schema
        // (which types max_quote_chars as integer) rejects it.
        let p = LensPolicy::new("Default", vec![SpaceId("space_A".into())]);
        assert!(p.max_quote_chars.is_none());
        let value = serde_json::to_value(&p).expect("serialize");
        assert!(
            value.get("max_quote_chars").is_none(),
            "None must be omitted, not serialized as null"
        );
        validate(&p).expect("default summary policy is schema-valid");
    }

    #[test]
    fn fully_populated_policy_validates() {
        let mut p = sample();
        p.space_exclude_ids = vec![SpaceId("space_B".into())];
        p.tag_include = vec!["spec".into()];
        p.tag_exclude = vec!["personal".into()];
        p.content_types = vec!["md".into()];
        p.allow_metadata = false;
        p.sensitivity_ceiling = Sensitivity::Confidential;
        p.approval_rule = ApprovalRule::Always;
        p.disclosure_mode = DisclosureMode::Full;
        validate(&p).expect("fully-populated policy is schema-valid");
    }
}
