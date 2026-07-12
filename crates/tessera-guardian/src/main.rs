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
mod unlock;

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

    /// Read the passphrase once from an inherited descriptor (recommended)
    #[arg(
        long,
        value_name = "FD",
        conflicts_with_all = ["passphrase_file", "prompt_passphrase"]
    )]
    passphrase_fd: Option<i32>,

    /// Read the passphrase once from a private regular file (mode 0600)
    #[arg(long, conflicts_with = "prompt_passphrase")]
    passphrase_file: Option<std::path::PathBuf>,

    /// Prompt on the controlling terminal with input echo disabled
    #[arg(long)]
    prompt_passphrase: bool,

    /// Exit and drop the unlocked DEK after this many idle seconds
    #[arg(long, default_value_t = 900, value_parser = clap::value_parser!(u64).range(1..))]
    idle_lock_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    // IMPORTANT: logs go to stderr — stdout is the MCP JSON-RPC channel.
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let passphrase = unlock::acquire(
        cli.passphrase_fd,
        cli.passphrase_file.as_deref(),
        cli.prompt_passphrase,
    )?;
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
        let state =
            routes::HttpState::new(cli.vault, passphrase.as_str(), public_url, cli.allow_origin)?;
        drop(passphrase);
        return routes::serve(
            state,
            cli.bind,
            std::time::Duration::from_secs(cli.idle_lock_seconds),
        )
        .await;
    }

    let vault = tessera_core::Vault::open(&cli.vault, passphrase.as_str())
        .with_context(|| format!("opening vault at {}", cli.vault.display()))?;
    drop(passphrase);

    // Construction validates the pairing; a refusal exits non-zero with a
    // clear message on stderr and never starts serving.
    let pairing = cli.pairing.context("--pairing is required for stdio")?;
    let session = GuardianSession::bind(&vault, &pairing)?;

    // The embedding model is loaded lazily on the first vault_query.
    mcp::serve_stdio(
        &vault,
        &session,
        std::time::Duration::from_secs(cli.idle_lock_seconds),
        || {
            let dir = tessera_core::embed::onnx::default_model_dir();
            let embedder = tessera_core::embed::OnnxEmbedder::load(&dir)
                .context("loading embedding model (run `tessera model fetch`)")?;
            Ok(Box::new(embedder) as Box<dyn tessera_core::embed::EmbeddingProvider>)
        },
    )
}
