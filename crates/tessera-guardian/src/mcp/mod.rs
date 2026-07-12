//! Model Context Protocol server over stdio.
//!
//! MCP stdio framing is newline-delimited JSON-RPC 2.0: one JSON message per
//! line on stdin, one per line on stdout. All logging must go to stderr —
//! stdout is the protocol channel and any stray byte corrupts it.
//!
//! The connection runs inside a recording [`receipt::Session`]: `vault_query`
//! and `vault_get_item` journal every disclosure, and the receipt is finalized
//! when the client disconnects. The embedding model is loaded lazily, on the
//! first `vault_query`, so a client that only lists tools never pays for it.

mod tools;

use std::io::{BufRead, Write};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use tessera_core::embed::EmbeddingProvider;
use tessera_core::session::{self as live_session, SessionStatus};
use tessera_core::{receipt, Vault};

use crate::session::GuardianSession;

/// MCP protocol revision this server speaks.
pub const PROTOCOL_VERSION: &str = "2025-11-25";

/// Handle one authenticated Streamable HTTP JSON-RPC message. HTTP requests
/// are stateless at the transport layer; each disclosing tool call receives a
/// persisted live session and exact finalized receipt.
pub fn handle_http_message(
    vault: &Vault,
    session: &GuardianSession,
    msg: &Value,
) -> anyhow::Result<Option<Value>> {
    let id = msg.get("id").cloned();
    let method = msg
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(id) = id else {
        return Ok(None);
    };
    let response = match method {
        "initialize" => result(id, initialize_result(session)),
        "ping" => result(id, json!({})),
        "tools/list" => result(id, json!({ "tools": tools::definitions(session) })),
        "tools/call" => handle_http_tool(vault, session, msg, id)?,
        other => error(id, -32601, &format!("method not found: {other}")),
    };
    Ok(Some(response))
}

fn handle_http_tool(
    vault: &Vault,
    session: &GuardianSession,
    msg: &Value,
    id: Value,
) -> anyhow::Result<Value> {
    let live = live_session::start(vault, &session.pairing)?;
    let session_id = live.id.clone();
    let mut receipt_session = match receipt::Session::open_bound(
        vault,
        receipt::AgentRef {
            agent_id: session.pairing.id.clone(),
            name: session.pairing.agent_name.clone(),
        },
        &session.lens,
        session.pairing.purpose.clone(),
        false,
        receipt::SessionBinding {
            session_id: session_id.clone(),
            pairing_id: Some(session.pairing.id.clone()),
        },
    ) {
        Ok(receipt_session) => receipt_session,
        Err(error) => {
            let _ = live_session::close(vault, &session_id, None);
            return Err(error.into());
        }
    };
    let params = msg.get("params");
    let name = params
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args = params
        .and_then(|value| value.get("arguments"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    let embedder = if name == "vault_query" {
        let dir = tessera_core::embed::onnx::default_model_dir();
        Some(tessera_core::embed::OnnxEmbedder::load(&dir))
    } else {
        None
    };
    let response = if let Some(Err(error)) = &embedder {
        result(
            id,
            tool_error(&format!("embedding model unavailable: {error}")),
        )
    } else {
        let provider = embedder
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .map(|model| model as &dyn EmbeddingProvider);
        match tools::call(&mut receipt_session, provider, session, vault, name, &args) {
            Ok(value) => result(id, value),
            Err(tools::ToolError::UnknownTool(name)) => {
                error(id, -32601, &format!("unknown tool: {name}"))
            }
            Err(tools::ToolError::Failed(message)) => result(id, tool_error(&message)),
        }
    };
    let finalized = if receipt_session.has_activity() {
        receipt_session.finalize().map(|receipt| receipt.receipt_id)
    } else {
        Ok(String::new())
    };
    let receipt_id = finalized.as_ref().ok().filter(|id| !id.is_empty());
    let _ = live_session::close(vault, &session_id, receipt_id.map(String::as_str));
    finalized?;
    Ok(response)
}

/// Serve MCP over stdin/stdout until the client closes the stream (EOF).
///
/// `load_embedder` is invoked at most once, the first time a query needs it.
pub fn serve_stdio(
    vault: &Vault,
    session: &GuardianSession,
    load_embedder: impl Fn() -> anyhow::Result<Box<dyn EmbeddingProvider>>,
) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

    // Register the persisted live session first. The receipt is bound to this
    // exact identity; generating a second synthetic session id would make the
    // audit record impossible to correlate with revocation and expiry state.
    let live = live_session::start(vault, &session.pairing)
        .map_err(|e| anyhow::anyhow!("starting session: {e}"))?;
    let session_id = live.id.clone();

    // The connection IS a receipt session; every disclosure is journaled.
    let agent = receipt::AgentRef {
        agent_id: session.pairing.id.clone(),
        name: session.pairing.agent_name.clone(),
    };
    let mut receipt = receipt::Session::open_bound(
        vault,
        agent,
        &session.lens,
        session.pairing.purpose.clone(),
        false, // full disclosure stays disabled over stdio (M6 #32/#34 may gate it)
        receipt::SessionBinding {
            session_id: session_id.clone(),
            pairing_id: Some(session.pairing.id.clone()),
        },
    )
    .map_err(|e| {
        let _ = live_session::close(vault, &session_id, None);
        anyhow::anyhow!("opening receipt session: {e}")
    })?;

    let mut embedder: Option<Box<dyn EmbeddingProvider>> = None;
    // Timestamps of accepted disclosing calls, for the rolling-window limiter.
    let mut query_times: Vec<Instant> = Vec::new();

    tracing::info!(
        session = %session_id,
        pairing = %session.pairing.id,
        lens = %session.lens.name,
        purpose = %session.pairing.purpose,
        expires = %live.expires_at,
        "guardian session bound; serving MCP over stdio"
    );

    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                write_message(
                    &mut out,
                    error(Value::Null, -32700, &format!("parse error: {e}")),
                )?;
                continue;
            }
        };

        // Requests carry an `id`; notifications do not (and get no response).
        let id = msg.get("id").cloned();
        let method = msg
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or_default();

        match (method, id) {
            ("initialize", Some(id)) => {
                write_message(&mut out, result(id, initialize_result(session)))?;
            }
            ("ping", Some(id)) => {
                write_message(&mut out, result(id, json!({})))?;
            }
            ("tools/list", Some(id)) => {
                write_message(
                    &mut out,
                    result(id, json!({ "tools": tools::definitions(session) })),
                )?;
            }
            ("tools/call", Some(id)) => {
                // Enforce the session lifecycle before any disclosure: a
                // revoked or expired session ends here, and the refused call is
                // NOT recorded. Effect is immediate on the next call.
                match live_session::status(vault, &session_id) {
                    Ok(SessionStatus::Active) => {}
                    Ok(other) => {
                        write_message(
                            &mut out,
                            result(
                                id.clone(),
                                tool_error(&format!(
                                    "session {} — access has ended",
                                    other.as_str()
                                )),
                            ),
                        )?;
                        break;
                    }
                    Err(e) => {
                        write_message(
                            &mut out,
                            result(id.clone(), tool_error(&format!("session unavailable: {e}"))),
                        )?;
                        break;
                    }
                }

                let params = msg.get("params");
                let name = params
                    .and_then(|p| p.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned();
                let args = params
                    .and_then(|p| p.get("arguments"))
                    .cloned()
                    .unwrap_or_else(|| json!({}));

                // Per-session rate limit over a rolling 60s window (disclosing
                // tools only). Exceeding it returns a retryable error, records a
                // rate-limit event in the receipt, and does NOT dispatch.
                if matches!(name.as_str(), "vault_query" | "vault_get_item") {
                    let limit = session.lens.max_queries_per_min();
                    let now = Instant::now();
                    query_times.retain(|t| now.duration_since(*t) < Duration::from_secs(60));
                    if query_times.len() as u32 >= limit {
                        let retry_after = query_times
                            .first()
                            .map(|t| 60u64.saturating_sub(now.duration_since(*t).as_secs()))
                            .unwrap_or(60);
                        receipt.record_rate_limit(&name, &format!("{limit} queries/min exceeded"));
                        write_message(
                            &mut out,
                            result(
                                id,
                                tool_error(&format!(
                                    "rate limit exceeded ({limit} queries/min) — retryable; \
                                     retry in ~{retry_after}s"
                                )),
                            ),
                        )?;
                        continue;
                    }
                    query_times.push(now);
                }

                // Lazily load the model the first time a query needs it.
                if name == "vault_query" && embedder.is_none() {
                    match load_embedder() {
                        Ok(e) => embedder = Some(e),
                        Err(e) => {
                            write_message(
                                &mut out,
                                result(
                                    id,
                                    tool_error(&format!("embedding model unavailable: {e}")),
                                ),
                            )?;
                            continue;
                        }
                    }
                }

                let response = match tools::call(
                    &mut receipt,
                    embedder.as_deref(),
                    session,
                    vault,
                    &name,
                    &args,
                ) {
                    Ok(res) => result(id, res),
                    Err(tools::ToolError::UnknownTool(n)) => {
                        error(id, -32601, &format!("unknown tool: {n}"))
                    }
                    Err(tools::ToolError::Failed(m)) => result(id, tool_error(&m)),
                };
                write_message(&mut out, response)?;
            }
            // Notifications (no id): acknowledge nothing, per JSON-RPC.
            ("notifications/initialized", None) => {}
            (other, Some(id)) => {
                write_message(
                    &mut out,
                    error(id, -32601, &format!("method not found: {other}")),
                )?;
            }
            (_, None) => { /* unknown notification: ignore */ }
        }
    }

    // On any exit — EOF, revocation, or expiry — finalize the receipt (if
    // anything worth recording happened, incl. rate-limit events) and seal it.
    let receipt_id = if receipt.has_activity() {
        let finalized = receipt
            .finalize()
            .map_err(|e| anyhow::anyhow!("finalizing receipt: {e}"))?;
        tracing::info!(receipt = %finalized.receipt_id, "receipt finalized");
        Some(finalized.receipt_id)
    } else {
        None
    };
    // Best-effort close (a no-op if already revoked — that status is preserved).
    let _ = live_session::close(vault, &session_id, receipt_id.as_deref());
    tracing::info!(session = %session_id, "guardian session ended");
    Ok(())
}

fn initialize_result(session: &GuardianSession) -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": {
            "name": "tessera-guardian",
            "version": env!("CARGO_PKG_VERSION"),
        },
        "instructions": format!(
            "This vault is exposed through the lens '{}' for the purpose '{}'. \
             You can only see what that lens permits; every query is recorded to \
             a tamper-evident receipt.",
            session.lens.name, session.pairing.purpose
        ),
    })
}

fn result(id: Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

/// An MCP tool result flagged as an execution error (distinct from a JSON-RPC
/// protocol error) — the model sees the message and can adapt.
fn tool_error(message: &str) -> Value {
    json!({ "content": [{ "type": "text", "text": message }], "isError": true })
}

fn write_message(out: &mut impl Write, message: Value) -> std::io::Result<()> {
    writeln!(
        out,
        "{}",
        serde_json::to_string(&message).expect("serialize json-rpc")
    )?;
    out.flush()
}
