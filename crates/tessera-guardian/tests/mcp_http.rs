//! Real-binary Streamable HTTP/OAuth integration client.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::Engine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tessera_core::artifact::{self, ArtifactState, Sensitivity};
use tessera_core::crypto::KdfParams;
use tessera_core::lens::{self, DisclosureMode, LensPolicy};
use tessera_core::{chunk, extract, inbox, pairing, receipt, space, Vault};

const GUARDIAN: &str = env!("CARGO_BIN_EXE_tessera-guardian");
const TEST_PARAMS: KdfParams = KdfParams {
    m_cost_kib: 1024,
    t_cost: 1,
    p_cost: 1,
};

fn curl(args: &[String]) -> std::process::Output {
    Command::new("curl")
        .args(args)
        .output()
        .expect("run curl scripted client")
}

fn curl_json(args: &[String]) -> Value {
    let output = curl(args);
    assert!(
        output.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON response")
}

fn wait_until_listening(base_url: &str, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            child.try_wait().expect("child status").is_none(),
            "Guardian exited early"
        );
        let output = curl(&[
            "-sS".into(),
            "--fail".into(),
            format!("{base_url}/.well-known/oauth-protected-resource"),
        ]);
        if output.status.success() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "Guardian did not start listening"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn real_http_binary_runs_pkce_lens_revocation_and_receipt_lifecycle() {
    let dir = tempfile::tempdir().expect("tempdir");
    let vault_path = dir.path().join("Http.tessera");
    let vault = Vault::create_with_params(&vault_path, "pass", &TEST_PARAMS).expect("vault");
    let allowed_space = space::create(&vault, "Remote Allowed", None).expect("space");
    let blocked_space = space::create(&vault, "Remote Blocked", None).expect("space");
    let ingest = |space_id: &tessera_core::SpaceId, filename: &str, body: &str| {
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
        artifact::set_state(&vault, &artifact, ArtifactState::Live).expect("live");
        artifact
    };
    let allowed_artifact = ingest(
        &allowed_space,
        "remote-allowed.md",
        "HTTP-ALLOWED-EVIDENCE-302",
    );
    let blocked_artifact = ingest(
        &blocked_space,
        "remote-blocked.md",
        "HTTP-BLOCKED-EVIDENCE-881",
    );
    let mut policy = LensPolicy::new("HTTP allowed lens", vec![allowed_space]);
    policy.disclosure_mode = DisclosureMode::Excerpt;
    policy.max_quote_chars = Some(500);
    policy.sensitivity_ceiling = Sensitivity::Restricted;
    let lens_id = lens::create(&vault, &policy).expect("lens");
    drop(vault);

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("reserve port");
    let port = listener.local_addr().expect("address").port();
    drop(listener);
    let base_url = format!("http://127.0.0.1:{port}");
    let passphrase_file = dir.path().join("guardian-passphrase");
    std::fs::write(&passphrase_file, "pass\n").expect("passphrase");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&passphrase_file, std::fs::Permissions::from_mode(0o600))
            .expect("private passphrase");
    }
    let mut guardian = Command::new(GUARDIAN)
        .args(["--vault", vault_path.to_str().unwrap(), "--http"])
        .arg("--bind")
        .arg(format!("127.0.0.1:{port}"))
        .args(["--public-url", "https://tessera.example"])
        .args(["--allow-origin", "https://client.example"])
        .arg("--passphrase-file")
        .arg(&passphrase_file)
        .args(["--idle-lock-seconds", "30"])
        .env_remove("TESSERA_PASSPHRASE")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Guardian HTTP binary");
    wait_until_listening(&base_url, &mut guardian);

    let registration = curl_json(&[
        "-sS".into(),
        "-X".into(),
        "POST".into(),
        "-H".into(),
        "Content-Type: application/json".into(),
        "--data".into(),
        json!({
            "client_name":"Real HTTP integration client",
            "redirect_uris":["http://127.0.0.1:9911/callback"]
        })
        .to_string(),
        format!("{base_url}/register"),
    ]);
    let client_id = registration["client_id"].as_str().expect("client id");
    let vault = Vault::open(&vault_path, "pass").expect("approve");
    let remote_pairing = pairing::approve_remote(
        &vault,
        &lens_id,
        "real HTTP lifecycle",
        "HTTP integration agent",
        10,
        client_id,
    )
    .expect("remote pairing");
    drop(vault);

    let verifier = "a-standards-compliant-pkce-verifier-with-more-than-forty-three-chars";
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(Sha256::digest(verifier.as_bytes()));
    let mut authorization = url::Url::parse(&format!("{base_url}/authorize")).expect("URL");
    authorization
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", client_id)
        .append_pair("redirect_uri", "http://127.0.0.1:9911/callback")
        .append_pair("code_challenge", &challenge)
        .append_pair("code_challenge_method", "S256")
        .append_pair("scope", &format!("lens:{}", lens_id.0))
        .append_pair("state", "real-client-state")
        .append_pair("resource", "https://tessera.example/mcp");
    let authorization_response = curl(&[
        "-sS".into(),
        "-D".into(),
        "-".into(),
        "-o".into(),
        "/dev/null".into(),
        authorization.to_string(),
    ]);
    assert!(authorization_response.status.success());
    let headers = String::from_utf8(authorization_response.stdout).expect("headers");
    let location = headers
        .lines()
        .find_map(|line| {
            line.strip_prefix("location: ")
                .or_else(|| line.strip_prefix("Location: "))
        })
        .expect("authorization redirect")
        .trim();
    let redirect = url::Url::parse(location).expect("redirect URL");
    assert_eq!(
        redirect
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned()),
        Some("real-client-state".into())
    );
    let code = redirect
        .query_pairs()
        .find(|(key, _)| key == "code")
        .map(|(_, value)| value.into_owned())
        .expect("code");

    let token = curl_json(&[
        "-sS".into(),
        "-X".into(),
        "POST".into(),
        "-H".into(),
        "Content-Type: application/x-www-form-urlencoded".into(),
        "--data-urlencode".into(),
        "grant_type=authorization_code".into(),
        "--data-urlencode".into(),
        format!("code={code}"),
        "--data-urlencode".into(),
        "redirect_uri=http://127.0.0.1:9911/callback".into(),
        "--data-urlencode".into(),
        format!("client_id={client_id}"),
        "--data-urlencode".into(),
        format!("code_verifier={verifier}"),
        "--data-urlencode".into(),
        "resource=https://tessera.example/mcp".into(),
        format!("{base_url}/token"),
    ]);
    let access_token = token["access_token"].as_str().expect("access token");
    let token_file = dir.path().join("reference-client-token");
    std::fs::write(&token_file, format!("{access_token}\n")).expect("token file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o600))
            .expect("private token file");
    }
    let reference_client = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/guardian-v1/clients/http_client.py");
    let reference_output = Command::new("python3")
        .arg(reference_client)
        .args(["--url", &format!("{base_url}/mcp"), "--token-file"])
        .arg(&token_file)
        .args(["--origin", "https://client.example"])
        .output()
        .expect("run checked-in HTTP reference client");
    assert!(
        reference_output.status.success(),
        "HTTP reference client failed: {}",
        String::from_utf8_lossy(&reference_output.stderr)
    );
    let reference_stdout = String::from_utf8(reference_output.stdout).expect("client utf8");
    assert!(reference_stdout.contains("tessera.guardian.v1"));
    assert!(reference_stdout.contains("vault_query"));
    let mcp_call = |message: Value| {
        curl_json(&[
            "-sS".into(),
            "-X".into(),
            "POST".into(),
            "-H".into(),
            format!("Authorization: Bearer {access_token}"),
            "-H".into(),
            "Origin: https://client.example".into(),
            "-H".into(),
            "Accept: application/json, text/event-stream".into(),
            "-H".into(),
            "MCP-Protocol-Version: 2025-11-25".into(),
            "-H".into(),
            "Content-Type: application/json".into(),
            "--data".into(),
            message.to_string(),
            format!("{base_url}/mcp"),
        ])
    };
    assert_eq!(
        mcp_call(json!({"jsonrpc":"2.0","id":1,"method":"initialize"}))["result"]
            ["protocolVersion"],
        "2025-11-25"
    );
    let allowed = mcp_call(json!({
        "jsonrpc":"2.0","id":2,"method":"tools/call",
        "params":{"name":"vault_get_item","arguments":{"artifact_id":allowed_artifact.0}}
    }));
    assert!(allowed.to_string().contains("HTTP-ALLOWED-EVIDENCE-302"));
    let blocked = mcp_call(json!({
        "jsonrpc":"2.0","id":3,"method":"tools/call",
        "params":{"name":"vault_get_item","arguments":{"artifact_id":blocked_artifact.0}}
    }));
    assert_eq!(blocked["result"]["isError"], true);
    assert!(!blocked.to_string().contains("HTTP-BLOCKED-EVIDENCE-881"));

    let vault = Vault::open(&vault_path, "pass").expect("revoke");
    pairing::revoke(&vault, &remote_pairing.id).expect("revoke pairing");
    drop(vault);
    let revoked = curl(&[
        "-sS".into(),
        "-o".into(),
        "/dev/null".into(),
        "-w".into(),
        "%{http_code}".into(),
        "-X".into(),
        "POST".into(),
        "-H".into(),
        format!("Authorization: Bearer {access_token}"),
        "-H".into(),
        "Origin: https://client.example".into(),
        "-H".into(),
        "Accept: application/json, text/event-stream".into(),
        "-H".into(),
        "MCP-Protocol-Version: 2025-11-25".into(),
        "-H".into(),
        "Content-Type: application/json".into(),
        "--data".into(),
        json!({"jsonrpc":"2.0","id":4,"method":"ping"}).to_string(),
        format!("{base_url}/mcp"),
    ]);
    assert!(revoked.status.success());
    assert_eq!(String::from_utf8(revoked.stdout).unwrap(), "401");

    let vault = Vault::open(&vault_path, "pass").expect("lock");
    tessera_core::session::lock_all(&vault).expect("lock signal");
    assert_eq!(receipt::verify(&vault).expect("receipt chain"), 1);
    drop(vault);
    let status = guardian.wait().expect("Guardian graceful shutdown");
    assert!(status.success());
}
