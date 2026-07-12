//! The three lens-gated MCP tools: `vault_query`, `vault_get_item`, and
//! `vault_list_spaces`.
//!
//! Every tool is scoped to the session's lens. `vault_query` and
//! `vault_get_item` route through the recording [`Session`] so retrieval,
//! disclosure, and receipt journaling stay a single path — identical to the
//! CLI's `query --lens`. Tool descriptions surface the disclosure mode so the
//! model is told, up front, what it will NOT receive.

use serde_json::{json, Value};

use tessera_core::embed::EmbeddingProvider;
use tessera_core::lens::DisclosureMode;
use tessera_core::receipt::Session;
use tessera_core::space;
use tessera_core::{ArtifactId, Vault};

use crate::session::GuardianSession;

/// A tool dispatch failure. `UnknownTool` maps to a JSON-RPC error; `Failed`
/// maps to an MCP tool result with `isError: true` (the model sees the reason).
pub enum ToolError {
    UnknownTool(String),
    Failed(String),
}

fn fail(msg: impl Into<String>) -> ToolError {
    ToolError::Failed(msg.into())
}

/// One human-readable sentence describing what the lens's disclosure mode
/// withholds — embedded in every tool description.
fn disclosure_note(session: &GuardianSession) -> String {
    match session.lens.disclosure_mode {
        DisclosureMode::Summary => {
            "Returns ONE-SENTENCE SUMMARIES only — no verbatim source text is ever returned."
                .to_string()
        }
        DisclosureMode::Excerpt => format!(
            "Returns VERBATIM EXCERPTS truncated to {} characters — never whole documents.",
            session
                .lens
                .max_quote_chars
                .map(|n| n.to_string())
                .unwrap_or_else(|| "an unbounded number of".into())
        ),
        DisclosureMode::Full => "May return full document text.".to_string(),
    }
}

/// The `tools/list` payload for this session's lens.
pub fn definitions(session: &GuardianSession) -> Vec<Value> {
    let lens = &session.lens;
    let note = disclosure_note(session);
    vec![
        json!({
            "name": "vault_query",
            "description": format!(
                "Semantic search of the vault under the '{}' lens. {} You cannot \
                 retrieve anything outside this lens's spaces, tags, media types, or \
                 sensitivity ceiling; quarantined items are never returned.",
                lens.name, note
            ),
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "query": { "type": "string", "description": "natural-language question" },
                    "top_k": { "type": "integer", "description": "max results (default 5)" }
                },
                "required": ["query"]
            }
        }),
        json!({
            "name": "vault_get_item",
            "description": format!(
                "Fetch one artifact by id under the '{}' lens. {} An artifact the lens \
                 does not permit returns an error, never its content.",
                lens.name, note
            ),
            "inputSchema": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "artifact_id": { "type": "string", "description": "the artifact id (art_…)" }
                },
                "required": ["artifact_id"]
            }
        }),
        json!({
            "name": "vault_list_spaces",
            "description": if lens.allow_metadata {
                format!("List the spaces the '{}' lens grants access to.", lens.name)
            } else {
                "Unavailable: this lens does not permit metadata disclosure.".to_string()
            },
            "inputSchema": { "type": "object", "additionalProperties": false, "properties": {} }
        }),
    ]
}

/// Dispatch a `tools/call`. Returns the MCP tool-result object on success.
pub fn call(
    receipt: &mut Session<'_>,
    embedder: Option<&dyn EmbeddingProvider>,
    session: &GuardianSession,
    vault: &Vault,
    name: &str,
    args: &Value,
) -> Result<Value, ToolError> {
    match name {
        "vault_query" => {
            let query = args
                .get("query")
                .and_then(Value::as_str)
                .ok_or_else(|| fail("`query` (string) is required"))?;
            let top_k = args.get("top_k").and_then(Value::as_u64).unwrap_or(5) as usize;
            let embedder = embedder.ok_or_else(|| fail("embedding model is unavailable"))?;
            let rendered = receipt
                .query(embedder, query, top_k)
                .map_err(|e| fail(e.to_string()))?;
            Ok(text_result(format_results(&rendered)))
        }
        "vault_get_item" => {
            let id = args
                .get("artifact_id")
                .and_then(Value::as_str)
                .ok_or_else(|| fail("`artifact_id` (string) is required"))?;
            match receipt.get_item(&ArtifactId(id.to_string())) {
                Ok(rc) => Ok(text_result(format_item(&rc))),
                Err(e) => Ok(error_result(e.to_string())),
            }
        }
        "vault_list_spaces" => {
            if !session.lens.allow_metadata {
                return Ok(error_result(
                    "This lens does not permit metadata disclosure.",
                ));
            }
            Ok(text_result(
                list_spaces(vault, session).map_err(|e| fail(e.to_string()))?,
            ))
        }
        other => Err(ToolError::UnknownTool(other.to_string())),
    }
}

fn format_results(rendered: &[tessera_core::disclosure::RenderedContext]) -> String {
    if rendered.is_empty() {
        return "No results.".to_string();
    }
    let mut out = String::new();
    for (i, rc) in rendered.iter().enumerate() {
        let title = rc.title.as_deref().unwrap_or("(metadata withheld)");
        out.push_str(&format!("{}. {} [{}]\n", i + 1, title, rc.mode.as_str()));
        out.push_str(&format!("   {}\n", rc.body.replace('\n', "\n   ")));
        if let Some((s, e)) = rc.disclosed_range {
            out.push_str(&format!(
                "   (artifact {} bytes {s}..{e})\n",
                rc.artifact_id.0
            ));
        } else {
            out.push_str(&format!("   (artifact {})\n", rc.artifact_id.0));
        }
    }
    out
}

fn format_item(rc: &tessera_core::disclosure::RenderedContext) -> String {
    let title = rc.title.as_deref().unwrap_or("(metadata withheld)");
    format!(
        "{} [{}]\n{}\n(artifact {}, {} bytes disclosed)",
        title,
        rc.mode.as_str(),
        rc.body,
        rc.artifact_id.0,
        rc.bytes_disclosed
    )
}

/// The spaces a lens grants: its includes minus its excludes, with names.
fn list_spaces(vault: &Vault, session: &GuardianSession) -> anyhow::Result<String> {
    let lens = &session.lens;
    let excluded: std::collections::HashSet<&String> =
        lens.space_exclude_ids.iter().map(|s| &s.0).collect();
    let mut lines = Vec::new();
    for space_id in &lens.space_ids {
        if excluded.contains(&space_id.0) {
            continue;
        }
        match space::get(vault, space_id) {
            Ok(s) => lines.push(format!("{}  {}", s.id.0, s.name)),
            // A lens may reference a space that was deleted; skip it silently.
            Err(tessera_core::space::SpaceError::NotFound(_)) => {}
            Err(e) => return Err(e.into()),
        }
    }
    if lines.is_empty() {
        Ok("This lens grants no readable spaces.".to_string())
    } else {
        Ok(lines.join("\n"))
    }
}

fn text_result(text: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }] })
}

fn error_result(text: impl Into<String>) -> Value {
    json!({ "content": [{ "type": "text", "text": text.into() }], "isError": true })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tessera_core::artifact::{self, ArtifactState, Sensitivity};
    use tessera_core::crypto::KdfParams;
    use tessera_core::embed::EmbedError;
    use tessera_core::lens::LensPolicy;
    use tessera_core::pairing::Pairing;
    use tessera_core::receipt::AgentRef;
    use tessera_core::{chunk, extract, inbox, search, summary};

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    struct FakeEmbedder;
    impl EmbeddingProvider for FakeEmbedder {
        fn embed(&self, text: &str) -> Result<Vec<f32>, EmbedError> {
            let mut v = vec![0.0f32; 384];
            for w in text.to_lowercase().as_bytes().windows(3) {
                let h = (w[0] as usize * 961 + w[1] as usize * 31 + w[2] as usize) % 384;
                v[h] += 1.0;
            }
            let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 0.0 {
                v.iter_mut().for_each(|x| *x /= norm);
            }
            Ok(v)
        }
        fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, EmbedError> {
            texts.iter().map(|t| self.embed(t)).collect()
        }
        fn model_version(&self) -> &str {
            "fake-trigram@1"
        }
        fn dimensions(&self) -> usize {
            384
        }
        fn calibrated_relevance_floor(&self) -> Option<f32> {
            Some(0.0)
        }
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        vault: Vault,
        gsession: GuardianSession,
        art_id: ArtifactId,
    }

    fn fixture(mode: DisclosureMode) -> Fixture {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault = Vault::create_with_params(&dir.path().join("V.tessera"), "pass", &TEST_PARAMS)
            .expect("create");
        let space = space::create(&vault, "Docs", None).expect("space");

        let path = dir.path().join("fire.md");
        std::fs::write(
            &path,
            "Fire safety rating for corridor walls and fire doors.",
        )
        .expect("w");
        inbox::add(&vault, std::slice::from_ref(&path)).expect("add");
        let report = inbox::process(&vault, &space).expect("process");
        let art_id = report.ingested[0].1.clone();
        let derived = extract::extract_text(&vault, &art_id)
            .expect("extract")
            .expect("text");
        chunk::chunk_derived_text(&vault, &derived, &chunk::ChunkParams::default()).expect("chunk");
        summary::generate(&vault, &art_id, false).expect("summary");
        artifact::set_state(&vault, &art_id, ArtifactState::Live).expect("live");
        search::embed_missing(&vault, &FakeEmbedder).expect("embed");

        let mut lens = LensPolicy::new("reader", vec![space]);
        lens.disclosure_mode = mode;
        lens.sensitivity_ceiling = Sensitivity::Restricted;
        let pairing = Pairing {
            id: "pair_test".into(),
            lens_id: lens.id.0.clone(),
            purpose: "testing".into(),
            agent_name: "tester".into(),
            ttl_minutes: 60,
            approved_at: "2026-07-06T00:00:00Z".into(),
            revoked_at: None,
            oauth_client_id: None,
            lens_updated_at: Some(lens.updated_at.to_rfc3339()),
        };
        let gsession = GuardianSession { pairing, lens };
        Fixture {
            _dir: dir,
            vault,
            gsession,
            art_id,
        }
    }

    fn open_receipt<'v>(f: &'v Fixture) -> Session<'v> {
        Session::open(
            &f.vault,
            AgentRef {
                agent_id: "a".into(),
                name: "tester".into(),
            },
            &f.gsession.lens,
            "testing",
            false,
        )
        .expect("open receipt")
    }

    #[test]
    fn definitions_surface_the_disclosure_mode() {
        let f = fixture(DisclosureMode::Summary);
        let defs = definitions(&f.gsession);
        let query = defs.iter().find(|d| d["name"] == "vault_query").unwrap();
        let desc = query["description"].as_str().unwrap();
        assert!(
            desc.contains("SUMMARIES"),
            "summary mode is surfaced: {desc}"
        );
        assert!(desc.contains("outside this lens"), "scope limits surfaced");
    }

    #[test]
    fn vault_query_matches_the_shared_session_path() {
        let f = fixture(DisclosureMode::Summary);

        // The guardian tool's disclosed body must equal what Session::query —
        // the same path the CLI uses — produces.
        let mut expect_session = open_receipt(&f);
        let expected = expect_session
            .query(&FakeEmbedder, "fire corridor rating", 5)
            .expect("query");
        let expected_body = &expected[0].body;

        let mut receipt = open_receipt(&f);
        let result = call(
            &mut receipt,
            Some(&FakeEmbedder),
            &f.gsession,
            &f.vault,
            "vault_query",
            &json!({ "query": "fire corridor rating", "top_k": 5 }),
        )
        .unwrap_or_else(|_| panic!("vault_query failed"));
        let text = result["content"][0]["text"].as_str().unwrap();
        assert!(
            text.contains(expected_body.as_str()),
            "tool output must contain the shared-path disclosure:\n tool: {text}\n want: {expected_body}"
        );
        assert!(result.get("isError").is_none(), "not an error");
    }

    #[test]
    fn vault_get_item_enforces_the_lens() {
        let f = fixture(DisclosureMode::Summary);
        let mut receipt = open_receipt(&f);

        // In-scope item discloses its summary.
        let ok = call(
            &mut receipt,
            None,
            &f.gsession,
            &f.vault,
            "vault_get_item",
            &json!({ "artifact_id": f.art_id.0 }),
        )
        .unwrap_or_else(|_| panic!("get_item"));
        assert!(ok.get("isError").is_none());
        assert!(ok["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("summary"));

        // An unknown / out-of-scope id is refused as a tool error, not content.
        let refused = call(
            &mut receipt,
            None,
            &f.gsession,
            &f.vault,
            "vault_get_item",
            &json!({ "artifact_id": "art_DOESNOTEXIST" }),
        )
        .unwrap_or_else(|_| panic!("get_item"));
        assert_eq!(refused["isError"], true, "out-of-scope id refused");
    }

    #[test]
    fn vault_list_spaces_respects_allow_metadata() {
        let mut f = fixture(DisclosureMode::Summary);
        {
            let mut receipt = open_receipt(&f);
            let listed = call(
                &mut receipt,
                None,
                &f.gsession,
                &f.vault,
                "vault_list_spaces",
                &json!({}),
            )
            .unwrap_or_else(|_| panic!("list"));
            assert!(listed["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("Docs"));
        }

        // Forbid metadata → the tool refuses. (Receipt from the first block is
        // dropped, releasing the borrow so the lens can be mutated.)
        f.gsession.lens.allow_metadata = false;
        {
            let mut receipt = open_receipt(&f);
            let refused = call(
                &mut receipt,
                None,
                &f.gsession,
                &f.vault,
                "vault_list_spaces",
                &json!({}),
            )
            .unwrap_or_else(|_| panic!("list"));
            assert_eq!(refused["isError"], true);
        }
    }

    #[test]
    fn unknown_tool_is_a_protocol_error() {
        let f = fixture(DisclosureMode::Summary);
        let mut receipt = open_receipt(&f);
        let err = call(
            &mut receipt,
            None,
            &f.gsession,
            &f.vault,
            "rm_rf",
            &json!({}),
        );
        assert!(matches!(err.err(), Some(ToolError::UnknownTool(_))));
    }
}
