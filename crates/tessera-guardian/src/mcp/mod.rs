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

use serde_json::{json, Value};

use tessera_core::embed::EmbeddingProvider;
use tessera_core::{receipt, Vault};

use crate::session::GuardianSession;

/// MCP protocol revision this server speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

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

    // The connection IS a receipt session; every disclosure is journaled.
    let agent = receipt::AgentRef {
        agent_id: session.pairing.id.clone(),
        name: session.pairing.agent_name.clone(),
    };
    let mut receipt = receipt::Session::open(
        vault,
        agent,
        &session.lens,
        session.pairing.purpose.clone(),
        false, // full disclosure stays disabled over stdio (M6 #32/#34 may gate it)
    )
    .map_err(|e| anyhow::anyhow!("opening receipt session: {e}"))?;

    let mut embedder: Option<Box<dyn EmbeddingProvider>> = None;

    tracing::info!(
        pairing = %session.pairing.id,
        lens = %session.lens.name,
        purpose = %session.pairing.purpose,
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

    // Finalize the receipt only if the agent actually accessed anything, so a
    // client that merely lists tools does not spawn an empty receipt.
    if receipt.query_count() > 0 {
        let finalized = receipt
            .finalize()
            .map_err(|e| anyhow::anyhow!("finalizing receipt: {e}"))?;
        tracing::info!(receipt = %finalized.receipt_id, "receipt finalized");
    }
    tracing::info!("client disconnected; guardian session ending");
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
