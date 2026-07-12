//! tessera-guardian — the vault's enforcement point: MCP server for agent access.
//!
//! Stdio clients present an owner-approved `--pairing`; HTTP clients use OAuth
//! with a pairing bound to their registered client id. The immutable grant
//! binds an exact lens revision, declared audit purpose, agent label, and TTL.
//! Unknown, revoked, deleted-lens, or stale-lens grants fail closed.

mod mcp;
mod session;

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
    #[arg(long, required_unless_present = "http")]
    pairing: Option<String>,

    /// Serve MCP Streamable HTTP + OAuth instead of stdio
    #[arg(long)]
    http: bool,

    /// HTTP listen address (loopback by default)
    #[arg(long, default_value = "127.0.0.1:8787")]
    bind: std::net::SocketAddr,

    /// Canonical external HTTPS origin used for OAuth metadata/audience
    #[arg(long, requires = "http")]
    public_url: Option<String>,

    /// Explicitly permit binding a non-loopback interface
    #[arg(long, requires = "http")]
    allow_non_loopback: bool,

    /// Additional exact browser Origin allowed to call /mcp
    #[arg(long, requires = "http")]
    allow_origin: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // IMPORTANT: logs go to stderr — stdout is the MCP JSON-RPC channel.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let passphrase = std::env::var("TESSERA_PASSPHRASE")
        .context("TESSERA_PASSPHRASE must be set to unlock the vault")?;
    if cli.http {
        if !cli.bind.ip().is_loopback() && !cli.allow_non_loopback {
            anyhow::bail!(
                "refusing non-loopback bind {}; pass --allow-non-loopback explicitly",
                cli.bind
            );
        }
        let public_url = cli
            .public_url
            .context("--public-url is required with --http")?;
        let state = routes::HttpState::new(cli.vault, passphrase, public_url, cli.allow_origin)?;
        return routes::serve(state, cli.bind).await;
    }

    let vault = tessera_core::Vault::open(&cli.vault, &passphrase)
        .with_context(|| format!("opening vault at {}", cli.vault.display()))?;

    // Construction validates the pairing; a refusal exits non-zero with a
    // clear message on stderr and never starts serving.
    let pairing = cli.pairing.context("--pairing is required for stdio")?;
    let session = GuardianSession::bind(&vault, &pairing)?;

    // The embedding model is loaded lazily on the first vault_query.
    mcp::serve_stdio(&vault, &session, || {
        let dir = tessera_core::embed::onnx::default_model_dir();
        let embedder = tessera_core::embed::OnnxEmbedder::load(&dir)
            .context("loading embedding model (run `tessera model fetch`)")?;
        Ok(Box::new(embedder) as Box<dyn tessera_core::embed::EmbeddingProvider>)
    })
}
