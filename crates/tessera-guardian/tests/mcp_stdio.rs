//! End-to-end MCP-over-stdio tests: spawn the real guardian binary, drive the
//! JSON-RPC handshake, and verify that sessions are refused for bad pairings.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

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
    let passphrase_file = vault
        .parent()
        .expect("vault parent")
        .join("guardian-passphrase");
    std::fs::write(&passphrase_file, "pass\n").expect("write passphrase file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&passphrase_file, std::fs::Permissions::from_mode(0o600))
            .expect("private passphrase permissions");
    }
    let mut cmd = Command::new(GUARDIAN);
    cmd.arg("--vault")
        .arg(vault)
        .arg("--pairing")
        .arg(pairing)
        .arg("--passphrase-file")
        .arg(passphrase_file)
        .env_remove("TESSERA_PASSPHRASE")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn guardian_without_model(vault: &std::path::Path, pairing: &str) -> Command {
    let mut command = guardian(vault, pairing);
    command.env(
        "TESSERA_MODEL_DIR",
        vault
            .parent()
            .expect("vault parent")
            .join("missing-model-root"),
    );
    command
}

struct StdioClient {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl StdioClient {
    fn start(vault: &std::path::Path, pairing_id: &str) -> Self {
        Self::from_command(guardian(vault, pairing_id))
    }

    fn start_without_model(vault: &std::path::Path, pairing_id: &str) -> Self {
        Self::from_command(guardian_without_model(vault, pairing_id))
    }

    fn from_command(mut command: Command) -> Self {
        let mut child = command.spawn().expect("spawn guardian");
        let input = child.stdin.take().expect("stdin");
        let output = BufReader::new(child.stdout.take().expect("stdout"));
        Self {
            child,
            input,
            output,
        }
    }

    fn request(&mut self, request: Value) -> Value {
        writeln!(self.input, "{request}").expect("request");
        self.input.flush().expect("flush");
        let mut line = String::new();
        self.output.read_line(&mut line).expect("response");
        serde_json::from_str(&line).expect("json-rpc response")
    }

    fn close(mut self) -> std::process::ExitStatus {
        drop(self.input);
        self.child.wait().expect("guardian exit")
    }
}

fn tool_call(id: u64, name: &str, arguments: Value) -> Value {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "method": "tools/call",
        "params": { "name": name, "arguments": arguments }
    })
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
    assert_eq!(resp["result"]["protocolVersion"], "2025-11-25");
    assert_eq!(
        resp["result"]["capabilities"]["experimental"]["tessera.guardian"]["contractVersion"],
        "tessera.guardian.v1"
    );
    assert!(
        resp["result"]["capabilities"]["tools"].is_object(),
        "advertises tools capability"
    );
}

#[test]
fn incompatible_consumer_contract_fails_initialize_cleanly() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let pairing =
        pairing::approve(&vault, &lens_id, "contract test", "agent", 60).expect("approve");
    drop(vault);
    let mut client = StdioClient::start(&path, &pairing.id);
    let response = client.request(serde_json::json!({
        "jsonrpc":"2.0", "id":1, "method":"initialize",
        "params": {"capabilities": {"experimental": {
            "tessera.guardian": {"contractVersion":"tessera.guardian.v999"}
        }}}
    }));
    assert_eq!(response["error"]["code"], -32602);
    assert_eq!(
        response["error"]["data"]["requested"],
        "tessera.guardian.v999"
    );
    assert_eq!(
        response["error"]["data"]["supported"],
        serde_json::json!(["tessera.guardian.v1"])
    );
    assert!(client.close().success());
}

#[test]
fn checked_in_stdio_reference_client_passes_against_real_guardian() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let pairing =
        pairing::approve(&vault, &lens_id, "reference client", "consumer", 60).expect("approve");
    drop(vault);
    let passphrase_file = path.parent().unwrap().join("reference-client-passphrase");
    std::fs::write(&passphrase_file, "pass\n").expect("passphrase");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&passphrase_file, std::fs::Permissions::from_mode(0o600))
            .expect("private passphrase");
    }
    let client = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/guardian-v1/clients/stdio_client.py");
    let output = Command::new("python3")
        .arg(client)
        .args(["--guardian", GUARDIAN, "--vault"])
        .arg(&path)
        .args(["--pairing", &pairing.id, "--passphrase-file"])
        .arg(&passphrase_file)
        .output()
        .expect("run checked-in stdio client");
    assert!(
        output.status.success(),
        "reference client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf8");
    assert!(stdout.contains("tessera.guardian.v1"));
    assert!(stdout.contains("vault_query"));
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
fn malformed_and_oversized_requests_fail_cleanly_without_killing_stdio_session() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let pairing =
        pairing::approve(&vault, &lens_id, "protocol test", "agent", 60).expect("approve");
    drop(vault);

    let mut child = guardian(&path, &pairing.id).spawn().expect("spawn");
    let mut input = child.stdin.take().expect("stdin");
    input.write_all(b"{not-json}\n").expect("malformed");
    input
        .write_all(&vec![b'x'; 1024 * 1024 + 1])
        .expect("oversized body");
    input.write_all(b"\n").expect("oversized delimiter");
    input
        .write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{}}\n\
              {\"jsonrpc\":\"2.0\",\"method\":\"notifications/unknown\"}\n\
              {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n",
        )
        .expect("valid continuation");
    drop(input);
    let output = child.wait_with_output().expect("wait");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let messages: Vec<Value> = String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .map(|line| serde_json::from_str(line).expect("json-rpc"))
        .collect();
    assert_eq!(messages.len(), 4, "two errors and two request responses");
    assert_eq!(messages[0]["error"]["code"], -32700);
    assert_eq!(messages[1]["error"]["code"], -32600);
    assert!(messages[1]["error"]["message"]
        .as_str()
        .unwrap()
        .contains("1048576 byte limit"));
    assert_eq!(messages[2]["id"], 1);
    assert_eq!(messages[3]["id"], 2);
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
fn http_non_loopback_bind_requires_explicit_owner_opt_in() {
    let (_dir, path, _lens) = vault_with_lens();
    let mut command = guardian(&path, "unused-for-http");
    let output = command
        .args([
            "--http",
            "--bind",
            "0.0.0.0:0",
            "--public-url",
            "https://tessera.example",
        ])
        .output()
        .expect("guardian");
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("pass --allow-non-loopback explicitly")
    );
}

#[test]
fn guardian_ignores_environment_passphrase_and_never_prints_secret_input() {
    let (dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let pairing = pairing::approve(&vault, &lens_id, "test", "agent", 60).expect("pairing");
    drop(vault);
    let marker = "WRONG-SECRET-MUST-NEVER-APPEAR-49";
    let secret = dir.path().join("wrong-passphrase");
    std::fs::write(&secret, marker).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret, std::fs::Permissions::from_mode(0o600))
            .expect("permissions");
    }
    let output = Command::new(GUARDIAN)
        .arg("--vault")
        .arg(&path)
        .arg("--pairing")
        .arg(&pairing.id)
        .arg("--passphrase-file")
        .arg(&secret)
        .env("TESSERA_PASSPHRASE", "pass")
        .output()
        .expect("guardian");
    assert!(
        !output.status.success(),
        "environment must not unlock Guardian"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains(marker));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(marker));
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

fn assert_owner_change_blocks_next_call(
    change: impl FnOnce(&Vault, &LensId, &str),
    expected: &str,
) {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let pairing =
        pairing::approve(&vault, &lens_id, "declared task", "local config", 60).expect("approve");
    drop(vault);

    let mut child = guardian(&path, &pairing.id).spawn().expect("spawn");
    let mut input = child.stdin.take().expect("stdin");
    let mut output = BufReader::new(child.stdout.take().expect("stdout"));
    writeln!(
        input,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .expect("initialize");
    input.flush().expect("flush");
    let mut line = String::new();
    output.read_line(&mut line).expect("read initialize");

    let vault = Vault::open(&path, "pass").expect("reopen");
    change(&vault, &lens_id, &pairing.id);
    drop(vault);

    writeln!(
        input,
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"vault_list_spaces","arguments":{{}}}}}}"#
    )
    .expect("call");
    input.flush().expect("flush");
    line.clear();
    output.read_line(&mut line).expect("read refusal");
    let refusal: Value = serde_json::from_str(&line).expect("json");
    assert_eq!(refusal["result"]["isError"], true);
    let message = refusal["result"]["content"][0]["text"]
        .as_str()
        .expect("message");
    assert!(message.contains(expected), "unexpected refusal: {message}");

    drop(input);
    assert!(child.wait().expect("wait").success());
}

#[test]
fn pairing_revocation_blocks_an_existing_stdio_session_on_next_call() {
    assert_owner_change_blocks_next_call(
        |vault, _lens, pairing_id| pairing::revoke(vault, pairing_id).expect("revoke"),
        "pairing",
    );
}

#[test]
fn lens_change_makes_existing_stdio_credential_stale_on_next_call() {
    assert_owner_change_blocks_next_call(
        |vault, lens_id, _pairing_id| {
            let mut policy = lens::get(vault, lens_id).expect("lens");
            policy.allow_metadata = false;
            lens::update(vault, &policy).expect("update");
        },
        "changed after pairing approval",
    );
}

#[test]
fn explicit_guardian_lock_exits_stdio_without_waiting_for_another_call() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let pairing =
        pairing::approve(&vault, &lens_id, "declared task", "local config", 60).expect("approve");
    drop(vault);

    let mut child = guardian(&path, &pairing.id).spawn().expect("spawn");
    let mut input = child.stdin.take().expect("stdin");
    let mut output = BufReader::new(child.stdout.take().expect("stdout"));
    writeln!(
        input,
        r#"{{"jsonrpc":"2.0","id":1,"method":"initialize","params":{{}}}}"#
    )
    .expect("initialize");
    input.flush().expect("flush");
    let mut line = String::new();
    output.read_line(&mut line).expect("read initialize");

    let vault = Vault::open(&path, "pass").expect("reopen");
    assert_eq!(session::lock_all(&vault).expect("lock"), 1);
    drop(vault);
    let started = std::time::Instant::now();
    let status = child.wait().expect("guardian exits");
    assert!(status.success());
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    drop(input);
    drop(output);

    let mut restarted = guardian(&path, &pairing.id).spawn().expect("restart");
    restarted
        .stdin
        .take()
        .expect("stdin")
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"initialize\",\"params\":{}}\n")
        .expect("initialize after unlock");
    let restarted_output = restarted.wait_with_output().expect("restarted output");
    assert!(restarted_output.status.success());
    assert!(String::from_utf8_lossy(&restarted_output.stdout).contains("\"id\":9"));
}

#[test]
fn stdio_idle_timeout_exits_and_drops_the_unlocked_vault() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let pairing =
        pairing::approve(&vault, &lens_id, "idle test", "local config", 60).expect("approve");
    drop(vault);

    let started = std::time::Instant::now();
    let mut command = guardian(&path, &pairing.id);
    command.arg("--idle-lock-seconds").arg("1");
    let mut child = command.spawn().expect("guardian");
    let input = child.stdin.take().expect("keep stdin open");
    let output = child.wait_with_output().expect("wait");
    drop(input);
    assert!(output.status.success());
    assert!(started.elapsed() >= std::time::Duration::from_secs(1));
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
}

/// A vault with one live, summarized doc and a summary lens scoped to its
/// space (with an optional per-session rate cap). Returns
/// (tempdir, vault path, lens id, artifact id).
fn vault_with_live_doc(
    max_qpm: Option<u32>,
) -> (tempfile::TempDir, std::path::PathBuf, LensId, ArtifactId) {
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
    lens.max_queries_per_min = max_qpm;
    let lens_id = lens::create(&vault, &lens).expect("lens");
    drop(vault);
    (dir, path, lens_id, art)
}

fn vault_with_isolated_lenses() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    LensId,
    ArtifactId,
    LensId,
    ArtifactId,
) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("Isolated.tessera");
    let vault = Vault::create_with_params(&path, "pass", &TEST_PARAMS).expect("create");
    let alpha = space::create(&vault, "Alpha Private", None).expect("alpha");
    let beta = space::create(&vault, "Beta Private", None).expect("beta");
    let ingest = |space_id: &SpaceId, filename: &str, body: &str| {
        let source = dir.path().join(filename);
        std::fs::write(&source, body).expect("write");
        inbox::add(&vault, std::slice::from_ref(&source)).expect("add");
        let artifact = inbox::process(&vault, space_id).expect("process").ingested[0]
            .1
            .clone();
        let derived = extract::extract_text(&vault, &artifact)
            .expect("extract")
            .expect("text");
        chunk::chunk_derived_text(&vault, &derived, &chunk::ChunkParams::default()).expect("chunk");
        summary::generate(&vault, &artifact, false).expect("summary");
        tessera_core::artifact::set_state(&vault, &artifact, ArtifactState::Live).expect("live");
        artifact
    };
    let alpha_artifact = ingest(&alpha, "alpha.md", "ALPHA-ONLY-EVIDENCE-714");
    let beta_artifact = ingest(&beta, "beta.md", "BETA-ONLY-EVIDENCE-928");
    let embedder =
        tessera_core::embed::OnnxEmbedder::load(&tessera_core::embed::onnx::default_model_dir())
            .expect("pinned integration model; run `tessera model fetch`");
    tessera_core::search::embed_missing(&vault, &embedder).expect("embed corpus");
    let make_lens = |name: &str, space_id: SpaceId, max_qpm: u32| {
        let mut policy = LensPolicy::new(name, vec![space_id]);
        policy.disclosure_mode = DisclosureMode::Excerpt;
        policy.max_quote_chars = Some(500);
        policy.sensitivity_ceiling = tessera_core::Sensitivity::Restricted;
        policy.max_queries_per_min = Some(max_qpm);
        lens::create(&vault, &policy).expect("lens")
    };
    let alpha_lens = make_lens("Alpha lens", alpha, 3);
    let beta_lens = make_lens("Beta lens", beta, 5);
    drop(vault);
    (
        dir,
        path,
        alpha_lens,
        alpha_artifact,
        beta_lens,
        beta_artifact,
    )
}

#[test]
fn concurrent_stdio_clients_preserve_two_lens_isolation_and_reverse_finalization() {
    let (_dir, path, alpha_lens, alpha_artifact, beta_lens, beta_artifact) =
        vault_with_isolated_lenses();
    let vault = Vault::open(&path, "pass").expect("open");
    let alpha_pairing = pairing::approve(&vault, &alpha_lens, "alpha purpose", "Alpha Agent", 60)
        .expect("alpha pairing");
    let beta_pairing = pairing::approve(&vault, &beta_lens, "beta purpose", "Beta Agent", 30)
        .expect("beta pairing");
    drop(vault);

    let mut alpha = StdioClient::start(&path, &alpha_pairing.id);
    let alpha_init = alpha.request(serde_json::json!({
        "jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}
    }));
    let mut beta = StdioClient::start(&path, &beta_pairing.id);
    let beta_init = beta.request(serde_json::json!({
        "jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}
    }));
    assert!(alpha_init["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("Alpha lens"));
    assert!(beta_init["result"]["instructions"]
        .as_str()
        .unwrap()
        .contains("Beta lens"));

    let alpha_spaces = alpha.request(tool_call(2, "vault_list_spaces", serde_json::json!({})));
    let beta_spaces = beta.request(tool_call(2, "vault_list_spaces", serde_json::json!({})));
    let alpha_spaces = alpha_spaces.to_string();
    let beta_spaces = beta_spaces.to_string();
    assert!(alpha_spaces.contains("Alpha Private"));
    assert!(!alpha_spaces.contains("Beta Private"));
    assert!(beta_spaces.contains("Beta Private"));
    assert!(!beta_spaces.contains("Alpha Private"));

    let alpha_allowed = alpha.request(tool_call(
        3,
        "vault_get_item",
        serde_json::json!({"artifact_id": &alpha_artifact.0}),
    ));
    assert!(alpha_allowed
        .to_string()
        .contains("ALPHA-ONLY-EVIDENCE-714"));
    let alpha_guess = alpha.request(tool_call(
        4,
        "vault_get_item",
        serde_json::json!({"artifact_id": &beta_artifact.0}),
    ));
    assert_eq!(alpha_guess["result"]["isError"], true);
    assert!(!alpha_guess.to_string().contains("BETA-ONLY-EVIDENCE-928"));
    let alpha_semantic = alpha.request(tool_call(
        5,
        "vault_query",
        serde_json::json!({"query":"ALPHA-ONLY-EVIDENCE-714"}),
    ));
    assert!(alpha_semantic
        .to_string()
        .contains("ALPHA-ONLY-EVIDENCE-714"));
    assert!(!alpha_semantic
        .to_string()
        .contains("BETA-ONLY-EVIDENCE-928"));
    let alpha_limited = alpha.request(tool_call(
        6,
        "vault_get_item",
        serde_json::json!({"artifact_id": &alpha_artifact.0}),
    ));
    assert!(alpha_limited.to_string().contains("rate_limited"));

    let beta_allowed = beta.request(tool_call(
        3,
        "vault_get_item",
        serde_json::json!({"artifact_id": &beta_artifact.0}),
    ));
    assert!(beta_allowed.to_string().contains("BETA-ONLY-EVIDENCE-928"));
    let beta_guess = beta.request(tool_call(
        4,
        "vault_get_item",
        serde_json::json!({"artifact_id": &alpha_artifact.0}),
    ));
    assert_eq!(beta_guess["result"]["isError"], true);
    assert!(!beta_guess.to_string().contains("ALPHA-ONLY-EVIDENCE-714"));
    let beta_semantic = beta.request(tool_call(
        5,
        "vault_query",
        serde_json::json!({"query":"BETA-ONLY-EVIDENCE-928"}),
    ));
    assert!(beta_semantic.to_string().contains("BETA-ONLY-EVIDENCE-928"));
    assert!(!beta_semantic
        .to_string()
        .contains("ALPHA-ONLY-EVIDENCE-714"));
    let beta_still_allowed = beta.request(tool_call(
        6,
        "vault_get_item",
        serde_json::json!({"artifact_id": &beta_artifact.0}),
    ));
    assert!(beta_still_allowed
        .to_string()
        .contains("BETA-ONLY-EVIDENCE-928"));

    // Open order was Alpha then Beta; close in reverse order.
    assert!(beta.close().success());
    assert!(alpha.close().success());

    let vault = Vault::open(&path, "pass").expect("verify");
    assert_eq!(receipt::verify(&vault).expect("chain"), 2);
    let receipts = receipt::list(&vault).expect("receipts");
    assert_eq!(receipts[0].lens.lens_id, beta_lens.0);
    assert_eq!(receipts[0].purpose, "beta purpose");
    assert_eq!(receipts[0].summary.total_queries, 3);
    assert_eq!(receipts[1].lens.lens_id, alpha_lens.0);
    assert_eq!(receipts[1].purpose, "alpha purpose");
    assert_eq!(receipts[1].summary.total_queries, 2);
    assert_eq!(receipts[1].rate_limit_events.len(), 1);
    let sessions = session::list(&vault).expect("sessions");
    assert_eq!(sessions.len(), 2);
    assert!(sessions.iter().all(|record| record.receipt_id.is_some()));
}

#[test]
fn unavailable_model_is_a_bounded_tool_error_and_session_can_disconnect_cleanly() {
    let (_dir, path, lens_id) = vault_with_lens();
    let vault = Vault::open(&path, "pass").expect("open");
    let pairing =
        pairing::approve(&vault, &lens_id, "model failure", "agent", 60).expect("pairing");
    drop(vault);
    let mut client = StdioClient::start_without_model(&path, &pairing.id);
    client.request(serde_json::json!({
        "jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}
    }));
    let response = client.request(tool_call(
        2,
        "vault_query",
        serde_json::json!({"query":"anything"}),
    ));
    assert_eq!(response["result"]["isError"], true);
    assert!(response.to_string().contains("model_unavailable"));
    assert!(client.close().success());
    let vault = Vault::open(&path, "pass").expect("verify");
    assert_eq!(receipt::verify(&vault).expect("no disclosure receipt"), 0);
    assert_eq!(session::list(&vault).expect("session").len(), 1);
}

#[cfg(unix)]
#[test]
fn receipt_finalization_permission_failure_closes_session_and_preserves_valid_chain() {
    use std::os::unix::fs::PermissionsExt;

    let (_dir, path, lens_id, artifact) = vault_with_live_doc(None);
    let vault = Vault::open(&path, "pass").expect("open");
    let pairing = pairing::approve(&vault, &lens_id, "failure path", "agent", 60).expect("pairing");
    drop(vault);
    let mut client = StdioClient::start(&path, &pairing.id);
    client.request(serde_json::json!({
        "jsonrpc":"2.0", "id":1, "method":"initialize", "params":{}
    }));
    let disclosed = client.request(tool_call(
        2,
        "vault_get_item",
        serde_json::json!({"artifact_id": &artifact.0}),
    ));
    assert!(disclosed["result"]["isError"].is_null());

    let receipts_dir = path.join("receipts");
    std::fs::set_permissions(&receipts_dir, std::fs::Permissions::from_mode(0o500))
        .expect("deny receipt write");
    let status = client.close();
    std::fs::set_permissions(&receipts_dir, std::fs::Permissions::from_mode(0o700))
        .expect("restore receipt permissions");
    assert!(!status.success(), "receipt write failure must be loud");

    let vault = Vault::open(&path, "pass").expect("verify");
    assert_eq!(receipt::verify(&vault).expect("chain remains valid"), 0);
    let sessions = session::list(&vault).expect("sessions");
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].effective_status(), SessionStatus::Closed);
    assert!(sessions[0].receipt_id.is_none());
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
    let (_dir, path, lens_id, art) = vault_with_live_doc(None);
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
        r#"{{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{{"name":"vault_get_item","arguments":{{"artifact_id":"{art}","purpose":"different task","agent_name":"attacker","lens_id":"lens_OTHER","ttl_minutes":9999,"disclosure_mode":"full"}}}}}}"#,
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
    let finalized = receipt::list(&vault).expect("list");
    assert_eq!(finalized[0].summary.total_queries, 1);
    assert_eq!(
        finalized[0].session_id, live.id,
        "receipt must use the persisted Guardian live-session identity"
    );
    assert_eq!(
        finalized[0].pairing_id.as_deref(),
        Some(p.id.as_str()),
        "receipt must bind the owner-approved pairing"
    );
    assert_eq!(finalized[0].purpose, p.purpose);
    assert_eq!(finalized[0].agent.name, p.agent_name);
    assert_eq!(finalized[0].lens.lens_id, p.lens_id);
    assert_ne!(finalized[0].purpose, "different task");
    assert_ne!(finalized[0].agent.name, "attacker");
}

#[test]
fn exceeding_rate_limit_returns_retryable_error_and_records_event() {
    // A 2-queries/min lens: the third disclosing call in the window is refused.
    let (_dir, path, lens_id, art) = vault_with_live_doc(Some(2));
    let vault = Vault::open(&path, "pass").expect("open");
    let p = pairing::approve(&vault, &lens_id, "reading", "agent", 60).expect("approve");
    drop(vault);

    let get_item = |id: i32| {
        format!(
            r#"{{"jsonrpc":"2.0","id":{id},"method":"tools/call","params":{{"name":"vault_get_item","arguments":{{"artifact_id":"{art}"}}}}}}"#,
            art = art.0
        )
    };
    let script = [
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.to_string(),
        get_item(2),
        get_item(3),
        get_item(4),
    ]
    .join("\n");

    let mut child = guardian(&path, &p.id).spawn().expect("spawn");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(format!("{script}\n").as_bytes())
        .expect("write");
    let output = child.wait_with_output().expect("wait");
    let lines: Vec<Value> = String::from_utf8(output.stdout)
        .expect("utf8")
        .lines()
        .map(|l| serde_json::from_str(l).expect("json"))
        .collect();
    let by_id = |id: i64| lines.iter().find(|m| m["id"] == id).expect("response");

    assert!(by_id(2)["result"]["isError"].is_null(), "1st call ok");
    assert!(by_id(3)["result"]["isError"].is_null(), "2nd call ok");
    assert_eq!(by_id(4)["result"]["isError"], true, "3rd call rate-limited");
    let text = by_id(4)["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("rate limit") && text.contains("retry"),
        "error is retryable: {text}"
    );

    // The receipt records the rate-limit event; only accepted calls counted.
    let vault = Vault::open(&path, "pass").expect("open");
    let receipts = receipt::list(&vault).expect("list");
    assert_eq!(receipts.len(), 1);
    assert_eq!(
        receipts[0].rate_limit_events.len(),
        1,
        "rate-limit event visible in receipt"
    );
    assert_eq!(receipts[0].summary.total_queries, 2, "only accepted calls");
    assert_eq!(receipt::verify(&vault).expect("verify"), 1);
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
