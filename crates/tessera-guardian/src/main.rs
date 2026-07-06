//! tessera-guardian — the vault's enforcement point: MCP server for agent access.
//!
//! Launched by an MCP client (Claude Desktop / Claude Code) with a `--pairing`
//! the owner approved via `tessera pair add`. The pairing binds a lens and a
//! purpose; the guardian refuses to serve any pairing that is unknown, revoked,
//! or references a missing lens. It then speaks MCP over stdio.

mod mcp;
mod session;

// Retained for the HTTP transport + OAuth work (M6 #34).
mod agent;
mod auth;
mod routes;
mod stream;

use anyhow::{Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use session::GuardianSession;

#[derive(Parser)]
#[command(name = "tessera-guardian")]
#[command(about = "Tessera vault guardian — MCP server, the only agent-facing entry to a vault")]
#[command(version)]
struct Cli {
    /// Path to the vault bundle
    #[arg(long)]
    vault: std::path::PathBuf,

    /// Owner-approved pairing id (from `tessera pair add`)
    #[arg(long)]
    pairing: String,
}

fn main() -> Result<()> {
    // IMPORTANT: logs go to stderr — stdout is the MCP JSON-RPC channel.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let passphrase = std::env::var("TESSERA_PASSPHRASE")
        .context("TESSERA_PASSPHRASE must be set to unlock the vault")?;
    let vault = tessera_core::Vault::open(&cli.vault, &passphrase)
        .with_context(|| format!("opening vault at {}", cli.vault.display()))?;

    // Construction validates the pairing; a refusal exits non-zero with a
    // clear message on stderr and never starts serving.
    let session = GuardianSession::bind(&vault, &cli.pairing)?;

    mcp::serve_stdio(&session)
}
