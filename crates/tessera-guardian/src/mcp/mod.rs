//! Model Context Protocol server over stdio.
//!
//! MCP stdio framing is newline-delimited JSON-RPC 2.0: one JSON message per
//! line on stdin, one per line on stdout. All logging must go to stderr —
//! stdout is the protocol channel and any stray byte corrupts it.
//!
//! This module implements the base protocol (`initialize`, `initialized`,
//! `ping`, `tools/list`) and the session binding advertised to the client.
//! The vault tools themselves land in #31; until then `tools/list` is empty
//! and `tools/call` reports that no tools are available.

use std::io::{BufRead, Write};

use serde_json::{json, Value};

use crate::session::GuardianSession;

/// MCP protocol revision this server speaks.
pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Serve MCP over stdin/stdout until the client closes the stream (EOF).
pub fn serve_stdio(session: &GuardianSession) -> anyhow::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();

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
                // A parse error has no request id to correlate against.
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
                write_message(&mut out, result(id, json!({ "tools": [] })))?;
            }
            ("tools/call", Some(id)) => {
                write_message(
                    &mut out,
                    error(id, -32601, "no tools available yet (M6 #31)"),
                )?;
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

fn write_message(out: &mut impl Write, message: Value) -> std::io::Result<()> {
    writeln!(
        out,
        "{}",
        serde_json::to_string(&message).expect("serialize json-rpc")
    )?;
    out.flush()
}
