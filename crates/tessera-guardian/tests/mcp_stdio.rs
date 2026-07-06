//! End-to-end MCP-over-stdio tests: spawn the real guardian binary, drive the
//! JSON-RPC handshake, and verify that sessions are refused for bad pairings.

use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use serde_json::Value;
use tessera_core::artifact::ArtifactState;
use tessera_core::crypto::KdfParams;
use tessera_core::lens::{self, DisclosureMode, LensPolicy};
use tessera_core::session::{self, SessionStatus};
use tessera_core::space::{self, SpaceId};
use tessera_core::{chunk, extract, inbox, pairing, receipt, summary};
use tessera_core::{ArtifactId, LensId, Vault};

const TEST_PARAMS: KdfParams = KdfParams {
    m_cost_kib: 1024,
    t_cost: 1,
    p_cost: 1,
};

const GUARDIAN: &str = env!("CARGO_BIN_EXE_tessera-guardian");

/// A vault with one lens; returns (tempdir, vault path, lens id).
fn vault_with_lens() -> (tempfile::TempDir, std::path::PathBuf, LensId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("V.tessera");
    let vault = Vault::create_with_params(&path, "pass", &TEST_PARAMS).expect("create");
    let lens_id = lens::create(
        &vault,
        &LensPolicy::new("reader", vec![SpaceId("space_A".into())]),
    )
    .expect("lens");
    (dir, path, lens_id)
}

fn guardian(vault: &std::path::Path, pairing: &str) -> Command {
    let mut cmd = Command::new(GUARDIAN);
    cmd.arg("--vault")
        .arg(vault)
        .arg("--pairing")
        .arg(pairing)
        .env("TESSERA_PASSPHRASE", "pass")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

#[test]
fn initialize_handshake_succeeds_for_approved_pairing() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let p = pairing::approve(&vault, &lens_id, "answer questions", "Claude", 60).expect("approve");
    drop(vault);

    let mut child = guardian(&path, &p.id).spawn().expect("spawn guardian");
    let init = r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}"#;
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{init}\n").as_bytes())
        .expect("write init");
    // Dropping stdin sends EOF; the server responds then exits.
    let output = child.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "guardian exited non-zero: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8(output.stdout).expect("utf8");
    let first = stdout.lines().next().expect("a response line");
    let resp: Value = serde_json::from_str(first).expect("valid json-rpc");
    assert_eq!(resp["jsonrpc"], "2.0");
    assert_eq!(resp["id"], 1);
    assert_eq!(resp["result"]["serverInfo"]["name"], "tessera-guardian");
    assert_eq!(resp["result"]["protocolVersion"], "2025-06-18");
    assert!(
        resp["result"]["capabilities"]["tools"].is_object(),
        "advertises tools capability"
    );
}

#[test]
fn tools_list_and_ping_after_initialize() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let p = pairing::approve(&vault, &lens_id, "purpose", "agent", 60).expect("approve");
    drop(vault);

    let mut child = guardian(&path, &p.id).spawn().expect("spawn");
    let script = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"ping"}"#,
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/list"}"#,
    ]
    .join("\n");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{script}\n").as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("wait");
    assert!(output.status.success());

    let lines: Vec<Value> = String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    // initialize(1), ping(2), tools/list(3) — the notification gets no reply.
    assert_eq!(
        lines.len(),
        3,
        "one reply per request, none for the notification"
    );
    let by_id = |id: i64| lines.iter().find(|m| m["id"] == id).expect("response");
    assert!(by_id(2)["result"].is_object(), "ping ok");
    assert!(
        by_id(3)["result"]["tools"].is_array(),
        "tools/list returns an array"
    );
}

#[test]
fn session_refused_for_unknown_pairing() {
    let (_dir, path, _lens) = vault_with_lens();
    let output = guardian(&path, "pair_DOESNOTEXIST").output().expect("run");
    assert!(!output.status.success(), "must refuse unknown pairing");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not authorized") || stderr.contains("pair_DOESNOTEXIST"),
        "stderr should explain the refusal: {stderr}"
    );
}

#[test]
fn session_refused_for_revoked_pairing() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let p = pairing::approve(&vault, &lens_id, "purpose", "agent", 60).expect("approve");
    pairing::revoke(&vault, &p.id).expect("revoke");
    drop(vault);

    let output = guardian(&path, &p.id).output().expect("run");
    assert!(!output.status.success(), "must refuse revoked pairing");
    assert!(String::from_utf8_lossy(&output.stderr).contains("revoked"));
}

/// A vault with one live, summarized doc and a summary lens scoped to its
/// space. Returns (tempdir, vault path, lens id, artifact id).
fn vault_with_live_doc() -> (tempfile::TempDir, std::path::PathBuf, LensId, ArtifactId) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("V.tessera");
    let vault = Vault::create_with_params(&path, "pass", &TEST_PARAMS).expect("create");
    let space = space::create(&vault, "Docs", None).expect("space");

    let doc = dir.path().join("fire.md");
    std::fs::write(&doc, "Fire safety rating for corridor walls.").expect("write");
    inbox::add(&vault, std::slice::from_ref(&doc)).expect("add");
    let report = inbox::process(&vault, &space).expect("process");
    let art = report.ingested[0].1.clone();
    let derived = extract::extract_text(&vault, &art)
        .expect("extract")
        .expect("text");
    chunk::chunk_derived_text(&vault, &derived, &chunk::ChunkParams::default()).expect("chunk");
    summary::generate(&vault, &art, false).expect("summary");
    tessera_core::artifact::set_state(&vault, &art, ArtifactState::Live).expect("live");

    let mut lens = LensPolicy::new("reader", vec![space]);
    lens.disclosure_mode = DisclosureMode::Summary;
    lens.sensitivity_ceiling = tessera_core::artifact::Sensitivity::Restricted;
    let lens_id = lens::create(&vault, &lens).expect("lens");
    drop(vault);
    (dir, path, lens_id, art)
}

#[test]
fn expired_session_refuses_tool_calls() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    // TTL 0 ⇒ the session is expired the instant it starts.
    let p = pairing::approve(&vault, &lens_id, "purpose", "agent", 0).expect("approve");
    drop(vault);

    let mut child = guardian(&path, &p.id).spawn().expect("spawn");
    let script = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vault_list_spaces","arguments":{}}}"#,
    ]
    .join("\n");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{script}\n").as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("wait");
    let call = String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str::<Value>(l).expect("json"))
        .find(|m| m["id"] == 2)
        .expect("tool response");
    assert_eq!(call["result"]["isError"], true, "expired session refuses");
    assert!(call["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("expired"));
}

#[test]
fn revoked_session_refuses_next_call_and_finalizes_receipt() {
    let (_dir, path, lens_id, art) = vault_with_live_doc();
    let vault = Vault::open(&path, "pass").expect("open");
    let p = pairing::approve(&vault, &lens_id, "reading", "agent", 60).expect("approve");
    drop(vault);

    let mut child = guardian(&path, &p.id).spawn().expect("spawn");
    let mut cin = child.stdin.take().expect("stdin");
    let mut cout = BufReader::new(child.stdout.take().expect("stdout"));
    let mut read = || {
        let mut s = String::new();
        cout.read_line(&mut s).expect("read");
        serde_json::from_str::<Value>(&s).expect("json")
    };

    writeln!(
        cin,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .unwrap();
    cin.flush().unwrap();
    let _init = read();

    // A successful get_item records one access into the open receipt.
    writeln!(
        cin,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"vault_get_item","arguments":{{"artifact_id":"{art}"}}}}}}"#,
        art = art.0
    )
    .unwrap();
    cin.flush().unwrap();
    let ok = read();
    assert!(
        ok["result"]["isError"].is_null(),
        "get_item succeeded: {ok}"
    );

    // The owner revokes the live session out of band (as the CLI would).
    let vault = Vault::open(&path, "pass").expect("open");
    let live = session::list(&vault)
        .expect("list")
        .into_iter()
        .find(|s| s.effective_status() == SessionStatus::Active)
        .expect("an active session");
    session::revoke(&vault, &live.id).expect("revoke");
    drop(vault);

    // The very next tool call is refused with a clear error.
    writeln!(
        cin,
        r#"{{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{{"name":"vault_get_item","arguments":{{"artifact_id":"{art}"}}}}}}"#,
        art = art.0
    )
    .unwrap();
    cin.flush().unwrap();
    let refused = read();
    assert_eq!(refused["result"]["isError"], true, "revoked call refused");
    assert!(refused["result"]["content"][0]["text"]
        .as_str()
        .unwrap()
        .contains("revoked"));

    drop(cin);
    let _ = child.wait();

    // The receipt (with the pre-revocation access) was finalized and verifies.
    let vault = Vault::open(&path, "pass").expect("open");
    assert_eq!(
        receipt::verify(&vault).expect("verify"),
        1,
        "receipt finalized"
    );
    assert_eq!(
        receipt::list(&vault).expect("list")[0]
            .summary
            .total_queries,
        1
    );
}

#[test]
fn session_refused_when_lens_deleted() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let p = pairing::approve(&vault, &lens_id, "purpose", "agent", 60).expect("approve");
    // The owner deletes the lens after approving the pairing.
    lens::delete(&vault, &lens_id).expect("delete lens");
    drop(vault);

    let output = guardian(&path, &p.id).output().expect("run");
    assert!(!output.status.success(), "must refuse missing lens");
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown lens"));
}
