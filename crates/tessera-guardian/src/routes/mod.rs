//! Streamable HTTP + OAuth 2.1 endpoints for remote MCP clients.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tessera_core::oauth::{self, AuthorizationCodeRequest};

use crate::mcp;
use crate::session::GuardianSession;

#[derive(Clone)]
pub struct HttpState {
    vault_path: Arc<PathBuf>,
    passphrase: Arc<str>,
    public_url: Arc<str>,
    resource: Arc<str>,
    allowed_origins: Arc<Vec<String>>,
}

impl HttpState {
    pub fn new(
        vault_path: PathBuf,
        passphrase: String,
        public_url: String,
        allowed_origins: Vec<String>,
    ) -> anyhow::Result<Self> {
        let parsed = url::Url::parse(&public_url)?;
        if parsed.scheme() != "https" {
            anyhow::bail!("--public-url must use https (terminate TLS at this process or a proxy)");
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || !matches!(parsed.path(), "" | "/")
        {
            anyhow::bail!("--public-url must be an HTTPS origin without credentials or a path");
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            anyhow::bail!("--public-url must not contain a query or fragment");
        }
        let public_url = public_url.trim_end_matches('/').to_owned();
        let resource = format!("{public_url}/mcp");
        let origin = format!(
            "{}://{}{}",
            parsed.scheme(),
            parsed.host_str().unwrap_or_default(),
            parsed
                .port()
                .map(|port| format!(":{port}"))
                .unwrap_or_default()
        );
        let mut origins = allowed_origins;
        if !origins.contains(&origin) {
            origins.push(origin);
        }
        Ok(Self {
            vault_path: Arc::new(vault_path),
            passphrase: Arc::from(passphrase),
            public_url: Arc::from(public_url),
            resource: Arc::from(resource),
            allowed_origins: Arc::new(origins),
        })
    }

    fn open_vault(&self) -> anyhow::Result<tessera_core::Vault> {
        Ok(tessera_core::Vault::open(
            self.vault_path.as_ref(),
            self.passphrase.as_ref(),
        )?)
    }
}

pub fn router(state: HttpState) -> Router {
    Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(authorization_server_metadata),
        )
        .route("/register", post(register))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .route("/mcp", post(mcp_post).get(mcp_get))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .with_state(state)
}

pub async fn serve(state: HttpState, bind: SocketAddr) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!(%bind, resource = %state.resource, "serving MCP Streamable HTTP");
    axum::serve(listener, router(state)).await?;
    Ok(())
}

async fn protected_resource_metadata(State(state): State<HttpState>) -> Json<Value> {
    Json(json!({
        "resource": state.resource.as_ref(),
        "authorization_servers": [state.public_url.as_ref()],
        "bearer_methods_supported": ["header"],
    }))
}

async fn authorization_server_metadata(State(state): State<HttpState>) -> Json<Value> {
    Json(json!({
        "issuer": state.public_url.as_ref(),
        "authorization_endpoint": format!("{}/authorize", state.public_url),
        "token_endpoint": format!("{}/token", state.public_url),
        "registration_endpoint": format!("{}/register", state.public_url),
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],
        "protected_resources": [state.resource.as_ref()],
    }))
}

#[derive(Deserialize)]
struct RegistrationRequest {
    client_name: String,
    redirect_uris: Vec<String>,
}

async fn register(
    State(state): State<HttpState>,
    Json(request): Json<RegistrationRequest>,
) -> Response {
    if request.client_name.trim().is_empty()
        || request.redirect_uris.is_empty()
        || request.redirect_uris.iter().any(|uri| !valid_redirect(uri))
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_client_metadata");
    }
    let vault = match state.open_vault() {
        Ok(vault) => vault,
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    match oauth::register_client(&vault, &request.client_name, &request.redirect_uris) {
        Ok(client) => (
            StatusCode::CREATED,
            Json(json!({
                "client_id": client.client_id,
                "client_name": client.client_name,
                "redirect_uris": client.redirect_uris,
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
                "token_endpoint_auth_method": "none",
            })),
        )
            .into_response(),
        Err(_) => oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    }
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    code_challenge: String,
    code_challenge_method: String,
    scope: String,
    state: String,
    resource: String,
}

async fn authorize(
    State(state): State<HttpState>,
    Query(request): Query<AuthorizeQuery>,
) -> Response {
    if request.response_type != "code"
        || request.code_challenge_method != "S256"
        || request.state.is_empty()
        || request.resource != state.resource.as_ref()
        || request.code_challenge.len() != 43
        || !request
            .code_challenge
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let Some(lens_id) = one_lens_scope(&request.scope) else {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_scope");
    };
    let vault = match state.open_vault() {
        Ok(vault) => vault,
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let client = match oauth::get_client(&vault, &request.client_id) {
        Ok(client) => client,
        Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "unauthorized_client"),
    };
    if !client.redirect_uris.contains(&request.redirect_uri) {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_request");
    }
    let pairing = match tessera_core::pairing::find_remote(&vault, &request.client_id, lens_id) {
        Ok(pairing) => pairing,
        Err(_) => return oauth_error(StatusCode::FORBIDDEN, "access_denied"),
    };
    let code = match oauth::issue_code(
        &vault,
        &AuthorizationCodeRequest {
            client_id: &request.client_id,
            pairing_id: &pairing.id,
            redirect_uri: &request.redirect_uri,
            code_challenge: &request.code_challenge,
            resource: &request.resource,
        },
    ) {
        Ok(code) => code,
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    let mut redirect = match url::Url::parse(&request.redirect_uri) {
        Ok(url) => url,
        Err(_) => return oauth_error(StatusCode::BAD_REQUEST, "invalid_request"),
    };
    redirect
        .query_pairs_mut()
        .append_pair("code", &code)
        .append_pair("state", &request.state);
    Redirect::to(redirect.as_str()).into_response()
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: String,
    client_id: String,
    code_verifier: String,
    resource: String,
}

async fn token(State(state): State<HttpState>, Form(form): Form<TokenForm>) -> Response {
    if form.grant_type != "authorization_code"
        || form.resource != state.resource.as_ref()
        || !(43..=128).contains(&form.code_verifier.len())
        || !form
            .code_verifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'))
    {
        return oauth_error(StatusCode::BAD_REQUEST, "invalid_grant");
    }
    let vault = match state.open_vault() {
        Ok(vault) => vault,
        Err(_) => return oauth_error(StatusCode::INTERNAL_SERVER_ERROR, "server_error"),
    };
    match oauth::exchange_code(
        &vault,
        &form.code,
        &form.client_id,
        &form.redirect_uri,
        &pkce_challenge(&form.code_verifier),
        &form.resource,
    ) {
        Ok(grant) => no_store(
            Json(json!({
                "access_token": grant.access_token,
                "token_type": "Bearer",
                "expires_in": grant.expires_in,
                "scope": grant.scope,
            }))
            .into_response(),
        ),
        Err(_) => oauth_error(StatusCode::BAD_REQUEST, "invalid_grant"),
    }
}

async fn mcp_post(
    State(state): State<HttpState>,
    headers: HeaderMap,
    Json(message): Json<Value>,
) -> Response {
    if !origin_allowed(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let accept = headers
        .get(header::ACCEPT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    if !accept.contains("application/json") || !accept.contains("text/event-stream") {
        return StatusCode::NOT_ACCEPTABLE.into_response();
    }
    if message.get("method").and_then(Value::as_str) != Some("initialize")
        && headers
            .get("mcp-protocol-version")
            .and_then(|value| value.to_str().ok())
            != Some(mcp::PROTOCOL_VERSION)
    {
        return StatusCode::BAD_REQUEST.into_response();
    }
    let vault = match state.open_vault() {
        Ok(vault) => vault,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let token = match bearer(&headers) {
        Some(token) => token,
        None => return unauthorized(&state, None),
    };
    let binding = match oauth::validate_token(&vault, token, state.resource.as_ref()) {
        Ok(binding) => binding,
        Err(_) => return unauthorized(&state, None),
    };
    let session = match GuardianSession::bind(&vault, &binding.pairing_id) {
        Ok(session) if session.lens.id.0 == binding.lens_id => session,
        _ => return unauthorized(&state, Some(&format!("lens:{}", binding.lens_id))),
    };
    match mcp::handle_http_message(&vault, &session, &message) {
        Ok(Some(value)) => Json(value).into_response(),
        Ok(None) => StatusCode::ACCEPTED.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn mcp_get(State(state): State<HttpState>, headers: HeaderMap) -> Response {
    if !origin_allowed(&state, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let vault = match state.open_vault() {
        Ok(vault) => vault,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    match bearer(&headers)
        .and_then(|token| oauth::validate_token(&vault, token, state.resource.as_ref()).ok())
    {
        Some(_) => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        None => unauthorized(&state, None),
    }
}

fn valid_redirect(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    if url.fragment().is_some() {
        return false;
    }
    url.scheme() == "https"
        || (url.scheme() == "http"
            && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1")))
}

fn one_lens_scope(scope: &str) -> Option<&str> {
    let scopes = scope.split_whitespace().collect::<Vec<_>>();
    match scopes.as_slice() {
        [scope] => scope
            .strip_prefix("lens:")
            .filter(|lens| lens.starts_with("lens_")),
        _ => None,
    }
}

fn pkce_challenge(verifier: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
}

fn origin_allowed(state: &HttpState, headers: &HeaderMap) -> bool {
    headers
        .get(header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .is_none_or(|origin| {
            state
                .allowed_origins
                .iter()
                .any(|allowed| allowed == origin)
        })
}

fn unauthorized(state: &HttpState, scope: Option<&str>) -> Response {
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    let scope = scope
        .map(|scope| format!(", scope=\"{scope}\""))
        .unwrap_or_default();
    let challenge = format!(
        "Bearer resource_metadata=\"{}/.well-known/oauth-protected-resource\"{}",
        state.public_url, scope
    );
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_str(&challenge).expect("static challenge is a valid header"),
    );
    response
}

fn oauth_error(status: StatusCode, error: &str) -> Response {
    no_store((status, Json(json!({ "error": error }))).into_response())
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use tessera_core::artifact::{self, ArtifactState, Sensitivity};
    use tessera_core::crypto::KdfParams;
    use tessera_core::lens::{self, DisclosureMode, LensPolicy};
    use tessera_core::space;
    use tessera_core::{chunk, extract, inbox};
    use tower::ServiceExt;

    const TEST_PARAMS: KdfParams = KdfParams {
        m_cost_kib: 1024,
        t_cost: 1,
        p_cost: 1,
    };

    async fn json_body(response: Response) -> Value {
        let bytes = to_bytes(response.into_body(), 1024 * 1024)
            .await
            .expect("body");
        serde_json::from_slice(&bytes).expect("json")
    }

    fn fixture() -> (tempfile::TempDir, HttpState, String, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let vault_path = dir.path().join("Remote.tessera");
        let vault = tessera_core::Vault::create_with_params(&vault_path, "pass", &TEST_PARAMS)
            .expect("vault");
        let allowed = space::create(&vault, "Allowed", None).expect("allowed");
        let blocked = space::create(&vault, "Blocked", None).expect("blocked");
        let ingest = |space_id: &tessera_core::SpaceId, name: &str, body: &str| {
            let path = dir.path().join(name);
            std::fs::write(&path, body).expect("write");
            inbox::add(&vault, std::slice::from_ref(&path)).expect("add");
            let artifact = inbox::process(&vault, space_id).expect("process").ingested[0]
                .1
                .clone();
            let derived = extract::extract_text(&vault, &artifact)
                .expect("extract")
                .expect("text");
            chunk::chunk_derived_text(&vault, &derived, &chunk::ChunkParams::default())
                .expect("chunk");
            artifact::set_state(&vault, &artifact, ArtifactState::Live).expect("live");
            artifact
        };
        let allowed_artifact = ingest(&allowed, "allowed.md", "Allowed remote evidence body.");
        let blocked_artifact = ingest(&blocked, "blocked.md", "Blocked remote evidence body.");
        let mut policy = LensPolicy::new("Remote Allowed", vec![allowed]);
        policy.disclosure_mode = DisclosureMode::Excerpt;
        policy.max_quote_chars = Some(500);
        policy.sensitivity_ceiling = Sensitivity::Restricted;
        lens::create(&vault, &policy).expect("lens");
        let mut blocked_policy = LensPolicy::new("Remote Blocked", vec![blocked]);
        blocked_policy.disclosure_mode = DisclosureMode::Excerpt;
        blocked_policy.max_quote_chars = Some(500);
        blocked_policy.sensitivity_ceiling = Sensitivity::Restricted;
        lens::create(&vault, &blocked_policy).expect("blocked lens");
        drop(vault);
        let state = HttpState::new(
            vault_path,
            "pass".to_owned(),
            "https://tessera.example".to_owned(),
            Vec::new(),
        )
        .expect("state");
        (dir, state, allowed_artifact.0, blocked_artifact.0)
    }

    #[tokio::test]
    async fn oauth_pkce_client_is_lens_bound_and_queries_over_streamable_http() {
        let (_dir, state, allowed_artifact, blocked_artifact) = fixture();
        let app = router(state.clone());
        let register_request = Request::builder()
            .method("POST")
            .uri("/register")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                json!({
                    "client_name": "Remote Test Agent",
                    "redirect_uris": ["http://127.0.0.1:9911/callback"]
                })
                .to_string(),
            ))
            .expect("request");
        let registered = app
            .clone()
            .oneshot(register_request)
            .await
            .expect("register");
        assert_eq!(registered.status(), StatusCode::CREATED);
        let client_id = json_body(registered).await["client_id"]
            .as_str()
            .expect("client id")
            .to_owned();

        let vault = state.open_vault().expect("vault");
        let lenses = lens::list(&vault).expect("lenses");
        let allowed_lens = lenses
            .iter()
            .find(|lens| lens.name == "Remote Allowed")
            .expect("allowed lens");
        let blocked_lens = lenses
            .iter()
            .find(|lens| lens.name == "Remote Blocked")
            .expect("blocked lens");
        tessera_core::pairing::approve_remote(
            &vault,
            &allowed_lens.id,
            "remote integration test",
            "Remote Test Agent",
            10,
            &client_id,
        )
        .expect("remote approval");
        drop(vault);

        let verifier = "a-standards-compliant-pkce-verifier-with-more-than-forty-three-chars";
        let challenge = pkce_challenge(verifier);
        let mut authorization = url::Url::parse("https://tessera.example/authorize").unwrap();
        authorization
            .query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", "http://127.0.0.1:9911/callback")
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("scope", &format!("lens:{}", allowed_lens.id.0))
            .append_pair("state", "csrf-state")
            .append_pair("resource", "https://tessera.example/mcp");
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(authorization.path().to_owned() + "?" + authorization.query().unwrap())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("authorize");
        assert!(response.status().is_redirection());
        let location = response.headers()[header::LOCATION].to_str().unwrap();
        let redirect = url::Url::parse(location).expect("redirect");
        assert_eq!(
            redirect
                .query_pairs()
                .find(|(key, _)| key == "state")
                .map(|(_, value)| value.into_owned()),
            Some("csrf-state".to_owned())
        );
        let code = redirect
            .query_pairs()
            .find(|(key, _)| key == "code")
            .map(|(_, value)| value.into_owned())
            .expect("code");

        let form = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("redirect_uri", "http://127.0.0.1:9911/callback")
            .append_pair("client_id", &client_id)
            .append_pair("code_verifier", verifier)
            .append_pair("resource", "https://tessera.example/mcp")
            .finish();
        let token_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/token")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form))
                    .unwrap(),
            )
            .await
            .expect("token");
        assert_eq!(token_response.status(), StatusCode::OK);
        let access_token = json_body(token_response).await["access_token"]
            .as_str()
            .expect("access token")
            .to_owned();

        let initialize = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .header(header::ORIGIN, "https://tessera.example")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":0,"method":"initialize"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("initialize");
        assert_eq!(initialize.status(), StatusCode::OK);
        assert_eq!(
            json_body(initialize).await["result"]["protocolVersion"],
            mcp::PROTOCOL_VERSION
        );

        let call = |artifact_id: &str, id: u64| {
            Request::builder()
                .method("POST")
                .uri("/mcp")
                .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                .header(header::ORIGIN, "https://tessera.example")
                .header(header::ACCEPT, "application/json, text/event-stream")
                .header("mcp-protocol-version", mcp::PROTOCOL_VERSION)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({
                        "jsonrpc": "2.0",
                        "id": id,
                        "method": "tools/call",
                        "params": {
                            "name": "vault_get_item",
                            "arguments": { "artifact_id": artifact_id }
                        }
                    })
                    .to_string(),
                ))
                .unwrap()
        };
        let allowed = app
            .clone()
            .oneshot(call(&allowed_artifact, 1))
            .await
            .expect("allowed call");
        assert_eq!(allowed.status(), StatusCode::OK);
        let allowed_json = json_body(allowed).await;
        assert!(allowed_json.to_string().contains("Allowed remote evidence"));

        let blocked = app
            .clone()
            .oneshot(call(&blocked_artifact, 2))
            .await
            .expect("blocked call");
        assert!(json_body(blocked).await["result"]["isError"]
            .as_bool()
            .unwrap_or(false));

        let mut escalation = authorization.clone();
        escalation
            .query_pairs_mut()
            .clear()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", "http://127.0.0.1:9911/callback")
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .append_pair("scope", &format!("lens:{}", blocked_lens.id.0))
            .append_pair("state", "new-consent")
            .append_pair("resource", "https://tessera.example/mcp");
        let escalated = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(escalation.path().to_owned() + "?" + escalation.query().unwrap())
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("escalation");
        assert_eq!(escalated.status(), StatusCode::FORBIDDEN);

        let bad_origin = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .header(header::ORIGIN, "https://evil.example")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":3,"method":"initialize"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("origin");
        assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);

        let unauthenticated = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/mcp")
                    .header(header::ACCEPT, "application/json, text/event-stream")
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Body::from(
                        json!({"jsonrpc":"2.0","id":4,"method":"initialize"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .expect("unauthenticated");
        assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);
        assert!(unauthenticated
            .headers()
            .contains_key(header::WWW_AUTHENTICATE));

        let get_without_sse = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/mcp")
                    .header(header::AUTHORIZATION, format!("Bearer {access_token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .expect("get");
        assert_eq!(get_without_sse.status(), StatusCode::METHOD_NOT_ALLOWED);

        let vault = state.open_vault().expect("verify vault");
        assert_eq!(tessera_core::receipt::verify(&vault).expect("receipts"), 1);
        let receipts = tessera_core::receipt::list(&vault).expect("list receipts");
        assert_eq!(
            receipts[0].pairing_id.as_deref(),
            Some(receipts[0].agent.agent_id.as_str())
        );
        drop(receipts);
        let mut changed_lens = lens::get(&vault, &allowed_lens.id).expect("lens");
        changed_lens.allow_metadata = false;
        lens::update(&vault, &changed_lens).expect("change lens");
        drop(vault);

        let stale = app
            .oneshot(call(&allowed_artifact, 5))
            .await
            .expect("stale token call");
        assert_eq!(
            stale.status(),
            StatusCode::UNAUTHORIZED,
            "a token never inherits a changed lens policy"
        );
    }
}
