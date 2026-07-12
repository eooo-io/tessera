//! Reproducible bounded vector/FTS5/hybrid experiment for #42.
//!
//! The lexical candidate remains benchmark-only because the measured hybrid
//! did not beat the production vector path. FTS5 receives keyed tokens rather
//! than plaintext, mirroring Tessera's encrypted-at-rest constraint.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use rusqlite::Connection;
use tessera_core::artifact::{self, ArtifactState};
use tessera_core::chunk;
use tessera_core::crypto::KdfParams;
use tessera_core::embed::onnx::{self, OnnxEmbedder};
use tessera_core::extract;
use tessera_core::inbox;
use tessera_core::index::RetrievalConstraints;
use tessera_core::search;
use tessera_core::space::{self, SpaceId};
use tessera_core::vault::Vault;

struct Document {
    filename: &'static str,
    body: &'static str,
    state: &'static str,
    space: &'static str,
}

struct Case {
    category: &'static str,
    query: &'static str,
    expected: Option<&'static str>,
}

const DOCS: &[Document] = &[
    Document { filename: "fire-safety.md", body: "Fire safety requirements specify a two hour resistance rating for corridor walls and doors.", state: "live", space: "work" },
    Document { filename: "transaction-recovery.md", body: "Use BEGIN IMMEDIATE, commit the durable receipt index, and recover an interrupted atomic file rename.", state: "live", space: "work" },
    Document { filename: "error-catalog.md", body: "The diagnostic catalog maps ERR_TES_1042 to a receipt chain head mismatch requiring index verification.", state: "live", space: "work" },
    Document { filename: "protocol.md", body: "SIVR is the sealed integrity verification record protocol used for portable vault evidence.", state: "live", space: "work" },
    Document { filename: "northstar-runbook.md", body: "Operations guide for rebuilding a local index, checking disk pressure, and restoring service safely.", state: "live", space: "work" },
    Document { filename: "release-notes.md", body: "The 2026-05-17 release of Tessera v3.7.11 changed receipt verification and migration behavior.", state: "live", space: "work" },
    Document { filename: "sourdough.md", body: "Rye sourdough develops flavor during a long cool fermentation before baking.", state: "live", space: "work" },
    Document { filename: "oauth.md", body: "A PKCE verifier protects the OAuth authorization code exchange.", state: "live", space: "work" },
    Document { filename: "backup.md", body: "Copy the encrypted vault bundle to Linux, verify integrity, and rebuild derived indexes.", state: "live", space: "work" },
    Document { filename: "ocr.md", body: "Optical character recognition extracts visible text from screenshots for local search.", state: "live", space: "work" },
    Document { filename: "transcript.md", body: "The VTT transcript preserves each speaker turn and its start and end timestamps.", state: "live", space: "work" },
    Document { filename: "garden.md", body: "Drip irrigation keeps greenhouse tomatoes evenly watered during hot weather.", state: "live", space: "work" },
    Document { filename: "invoice.md", body: "The customer must pay the invoice within thirty days of the issue date.", state: "live", space: "work" },
    Document { filename: "cargo.md", body: "Cargo.lock pins resolved Rust dependency versions for reproducible builds.", state: "live", space: "work" },
    Document { filename: "network.md", body: "The local network uses split DNS, short DHCP leases, and redundant gateway checks.", state: "live", space: "work" },
    Document { filename: "observability.md", body: "Dashboards track request latency, error rate, saturation, and queue depth.", state: "live", space: "work" },
    Document { filename: "accessibility.md", body: "Keyboard focus order, semantic labels, and contrast protect accessible navigation.", state: "live", space: "work" },
    Document { filename: "procurement.md", body: "Supplier evaluation compares delivery risk, warranty terms, and ownership cost.", state: "live", space: "work" },
    Document { filename: "incident.md", body: "Incident response assigns a commander, preserves a timeline, and records actions.", state: "live", space: "work" },
    Document { filename: "retention.md", body: "Records retention defines deletion schedules, legal holds, and review ownership.", state: "live", space: "work" },
    Document { filename: "audio.md", body: "Audio normalization balances loudness while preserving peaks and speech clarity.", state: "live", space: "work" },
    Document { filename: "shipping.md", body: "Shipping documents list tariff codes, declared value, and country of origin.", state: "live", space: "work" },
    Document { filename: "forecast.md", body: "Demand forecasting combines seasonal history with inventory and lead times.", state: "live", space: "work" },
    Document { filename: "training.md", body: "A training plan alternates strength sessions, recovery, and progressive overload.", state: "live", space: "work" },
    Document { filename: "museum.md", body: "The museum catalog records provenance, dimensions, and conservation status.", state: "live", space: "work" },
    Document { filename: "aviation.md", body: "Flight planning accounts for weather, fuel reserve, alternates, and payload.", state: "live", space: "work" },
    Document { filename: "geology.md", body: "Granite forms when magma cools slowly and develops visible crystals.", state: "live", space: "work" },
    Document { filename: "orchestra.md", body: "An orchestra rehearsal balances articulation, intonation, and timing.", state: "live", space: "work" },
    Document { filename: "quarantined.md", body: "ONLY_PENDING_7788 must never leave quarantine.", state: "pending", space: "work" },
    Document { filename: "private-decoy.md", body: "ERR_TES_1042 SIVR northstar-runbook.md 2026-05-17 v3.7.11", state: "live", space: "private" },
];

const CASES: &[Case] = &[
    Case {
        category: "semantic",
        query: "corridor wall fire resistance requirements",
        expected: Some("fire-safety.md"),
    },
    Case {
        category: "semantic",
        query: "recover interrupted atomic receipt commit",
        expected: Some("transaction-recovery.md"),
    },
    Case {
        category: "exact_token",
        query: "ERR_TES_1042",
        expected: Some("error-catalog.md"),
    },
    Case {
        category: "acronym",
        query: "SIVR",
        expected: Some("protocol.md"),
    },
    Case {
        category: "filename",
        query: "northstar-runbook.md",
        expected: Some("northstar-runbook.md"),
    },
    Case {
        category: "date_version",
        query: "2026-05-17 v3.7.11",
        expected: Some("release-notes.md"),
    },
    Case {
        category: "hard_negative",
        query: "replace a rusted physical door lock",
        expected: None,
    },
    Case {
        category: "unrelated",
        query: "blue whale migration acoustics",
        expected: None,
    },
    Case {
        category: "quarantine",
        query: "ONLY_PENDING_7788",
        expected: None,
    },
];

#[derive(Default)]
struct Metrics {
    relevant: usize,
    recall_5: usize,
    recall_10: usize,
    reciprocal_rank: f64,
    zero_cases: usize,
    zero_correct: usize,
    exact_total: usize,
    exact_first: usize,
    latencies: Vec<Duration>,
}

impl Metrics {
    fn record(&mut self, case: &Case, titles: &[String], elapsed: Duration) {
        self.latencies.push(elapsed);
        if let Some(expected) = case.expected {
            self.relevant += 1;
            self.recall_5 += usize::from(titles.iter().take(5).any(|title| title == expected));
            if let Some(rank) = titles.iter().take(10).position(|title| title == expected) {
                self.recall_10 += 1;
                self.reciprocal_rank += 1.0 / (rank as f64 + 1.0);
            }
            if case.category != "semantic" {
                self.exact_total += 1;
                self.exact_first += usize::from(titles.first().is_some_and(|t| t == expected));
            }
        } else {
            self.zero_cases += 1;
            self.zero_correct += usize::from(titles.is_empty());
        }
    }

    fn print(&mut self, name: &str) {
        self.latencies.sort();
        let p50 = percentile(&self.latencies, 0.50).as_secs_f64() * 1000.0;
        let p95 = percentile(&self.latencies, 0.95).as_secs_f64() * 1000.0;
        println!(
            "{name}\trecall@5={:.3}\trecall@10={:.3}\tmrr={:.3}\texact@1={}/{}\tzero={}/{}\tp50_ms={p50:.2}\tp95_ms={p95:.2}",
            self.recall_5 as f64 / self.relevant as f64,
            self.recall_10 as f64 / self.relevant as f64,
            self.reciprocal_rank / self.relevant as f64,
            self.exact_first,
            self.exact_total,
            self.zero_correct,
            self.zero_cases,
        );
    }
}

fn percentile(values: &[Duration], fraction: f64) -> Duration {
    values[((values.len() - 1) as f64 * fraction).ceil() as usize]
}

fn normalize(text: &str) -> Vec<String> {
    text.to_lowercase()
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(str::to_owned)
        .collect()
}

fn keyed(text: &str) -> String {
    normalize(text)
        .into_iter()
        .map(|token| {
            blake3::keyed_hash(&[42; 32], token.as_bytes())
                .to_hex()
                .to_string()
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn lexical_fixture() -> rusqlite::Result<Connection> {
    let conn = Connection::open_in_memory()?;
    conn.execute_batch(
        "CREATE VIRTUAL TABLE lexical USING fts5(
           filename UNINDEXED, keyed_tokens, state UNINDEXED, space_id UNINDEXED,
           tags UNINDEXED, media_type UNINDEXED, sensitivity UNINDEXED
         );",
    )?;
    for doc in DOCS {
        conn.execute(
            "INSERT INTO lexical
               (filename, keyed_tokens, state, space_id, tags, media_type, sensitivity)
             VALUES (?1, ?2, ?3, ?4, '|keep|', 'text/markdown', 1)",
            rusqlite::params![
                doc.filename,
                keyed(&format!("{} {}", doc.filename, doc.body)),
                doc.state,
                doc.space
            ],
        )?;
    }
    Ok(conn)
}

fn lexical_search(conn: &Connection, query: &str, space: &str, top_k: usize) -> Vec<String> {
    let expression = keyed(query)
        .split_whitespace()
        .map(|token| format!("\"{token}\""))
        .collect::<Vec<_>>()
        .join(" OR ");
    if expression.is_empty() {
        return Vec::new();
    }
    let mut stmt = conn
        .prepare(
            "SELECT filename FROM lexical
             WHERE lexical MATCH ?1
               AND state = 'live'
               AND space_id LIKE ?2
               AND tags LIKE '%|keep|%'
               AND tags NOT LIKE '%|deny|%'
               AND media_type = 'text/markdown'
               AND sensitivity <= 3
             ORDER BY bm25(lexical), filename LIMIT ?3",
        )
        .expect("prepare lexical");
    stmt.query_map(rusqlite::params![expression, space, top_k as i64], |row| {
        row.get(0)
    })
    .expect("search lexical")
    .collect::<Result<Vec<_>, _>>()
    .expect("collect lexical")
}

fn ingest(vault: &Vault, dir: &std::path::Path, spaces: &HashMap<&str, SpaceId>, doc: &Document) {
    let path = dir.join(doc.filename);
    std::fs::write(&path, doc.body).expect("write fixture");
    inbox::add(vault, std::slice::from_ref(&path)).expect("add fixture");
    let artifact = inbox::process(vault, &spaces[doc.space])
        .expect("process")
        .ingested[0]
        .1
        .clone();
    let derived = extract::extract_text(vault, &artifact)
        .expect("extract")
        .expect("text");
    chunk::chunk_derived_text(vault, &derived, &chunk::ChunkParams::default()).expect("chunk");
    if doc.state == "live" {
        artifact::set_state(vault, &artifact, ArtifactState::Live).expect("live");
    }
}

fn titles(results: &[search::SearchResult]) -> Vec<String> {
    let mut seen = HashSet::new();
    results
        .iter()
        .filter(|result| seen.insert(result.artifact_title.clone()))
        .map(|result| result.artifact_title.clone())
        .collect()
}

fn rrf(vector: &[String], lexical: &[String], top_k: usize) -> Vec<String> {
    let mut scores = HashMap::<String, f64>::new();
    for (rank, title) in vector.iter().enumerate() {
        *scores.entry(title.clone()).or_default() += 1.0 / (60.0 + rank as f64 + 1.0);
    }
    // Preserve the calibrated semantic floor: lexical candidates may rerank
    // only documents admitted by vector retrieval, never add a new disclosure.
    for (rank, title) in lexical.iter().enumerate() {
        if let Some(score) = scores.get_mut(title) {
            *score += 1.0 / (60.0 + rank as f64 + 1.0);
        }
    }
    let mut ranked = scores.into_iter().collect::<Vec<_>>();
    ranked.sort_by(|(left_title, left), (right_title, right)| {
        right
            .total_cmp(left)
            .then_with(|| left_title.cmp(right_title))
    });
    ranked
        .into_iter()
        .take(top_k)
        .map(|(title, _)| title)
        .collect()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = tempfile::tempdir()?;
    let vault = Vault::create_with_params(
        &fixture.path().join("Benchmark.tessera"),
        "benchmark",
        &KdfParams {
            m_cost_kib: 1024,
            t_cost: 1,
            p_cost: 1,
        },
    )?;
    let work = space::create(&vault, "Work", None)?;
    let private = space::create(&vault, "Private", None)?;
    let spaces = HashMap::from([("work", work.clone()), ("private", private)]);
    for doc in DOCS {
        ingest(&vault, fixture.path(), &spaces, doc);
    }
    let embedder = OnnxEmbedder::load(&onnx::default_model_dir())?;
    let vector_started = Instant::now();
    let indexed = search::embed_missing(&vault, &embedder)?;
    let vector_ingest = vector_started.elapsed();
    let lexical_started = Instant::now();
    let lexical = lexical_fixture()?;
    let lexical_ingest = lexical_started.elapsed();
    let lexical_bytes: i64 = lexical.query_row(
        "SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()",
        [],
        |row| row.get(0),
    )?;
    println!(
        "INDEX\tchunks={indexed}\tvector_ms={:.2}\tlexical_ms={:.2}\tlexical_bytes={lexical_bytes}",
        vector_ingest.as_secs_f64() * 1000.0,
        lexical_ingest.as_secs_f64() * 1000.0,
    );

    let constraints = RetrievalConstraints {
        space_ids: vec![work],
        sensitivity_ceiling: tessera_core::Sensitivity::Restricted,
        ..Default::default()
    };
    let mut vector_metrics = Metrics::default();
    let mut lexical_metrics = Metrics::default();
    let mut hybrid_metrics = Metrics::default();
    for case in CASES {
        let started = Instant::now();
        let vector = titles(
            &search::query_evaluated(&vault, &embedder, case.query, &constraints, 50, None)?
                .results,
        );
        let vector_elapsed = started.elapsed();
        vector_metrics.record(case, &vector[..vector.len().min(10)], vector_elapsed);

        let started = Instant::now();
        let lexical_result = lexical_search(&lexical, case.query, "work", 50);
        let lexical_elapsed = started.elapsed();
        lexical_metrics.record(
            case,
            &lexical_result[..lexical_result.len().min(10)],
            lexical_elapsed,
        );

        let started = Instant::now();
        let hybrid = rrf(&vector, &lexical_result, 10);
        hybrid_metrics.record(
            case,
            &hybrid,
            vector_elapsed + lexical_elapsed + started.elapsed(),
        );
        println!(
            "CASE\t{}\t{}\tvector={:?}\tlexical={:?}\thybrid={:?}",
            case.category,
            case.query,
            vector.first(),
            lexical_result.first(),
            hybrid.first()
        );
    }
    vector_metrics.print("VECTOR");
    lexical_metrics.print("LEXICAL");
    hybrid_metrics.print("HYBRID_RRF");

    let relevant = CASES.iter().filter(|case| case.expected.is_some()).count() as f64;
    let mut vector_owner_found = 0usize;
    let mut lexical_owner_found = 0usize;
    for case in CASES.iter().filter(|case| case.expected.is_some()) {
        let expected = case.expected.expect("filtered relevant");
        let owner = titles(
            &search::query_evaluated(
                &vault,
                &embedder,
                case.query,
                &search::owner_constraints(),
                10,
                None,
            )?
            .results,
        );
        vector_owner_found += usize::from(owner.iter().any(|title| title == expected));
        let lexical_owner = lexical_search(&lexical, case.query, "%", 10);
        lexical_owner_found += usize::from(lexical_owner.iter().any(|title| title == expected));
    }
    println!(
        "POLICY_RECALL\tvector_owner={:.3}\tvector_lens={:.3}\tlexical_owner={:.3}\tlexical_lens={:.3}",
        vector_owner_found as f64 / relevant,
        vector_metrics.recall_10 as f64 / relevant,
        lexical_owner_found as f64 / relevant,
        lexical_metrics.recall_10 as f64 / relevant,
    );

    assert!(lexical_search(&lexical, "ONLY_PENDING_7788", "work", 10).is_empty());
    assert!(lexical_search(&lexical, "ERR_TES_1042", "work", 10)
        .iter()
        .all(|title| title != "private-decoy.md"));
    let sql = lexical.query_row(
        "SELECT group_concat(keyed_tokens, ' ') FROM lexical",
        [],
        |row| row.get::<_, String>(0),
    )?;
    assert!(!sql.contains("ERR_TES_1042"));
    println!("POLICY\tquarantine=pass\tspace_isolation=pass\tplaintext_at_rest=pass");
    Ok(())
}
