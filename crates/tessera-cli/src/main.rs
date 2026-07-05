//! tessera-cli — Command-line interface for vault operations.

mod commands;

use clap::Parser;

#[derive(Parser)]
#[command(name = "tessera")]
#[command(about = "Personal context vault with policy-gated retrieval")]
#[command(version)]
struct Cli {
    /// Vault bundle path (default: $TESSERA_VAULT or ./vault.tessera)
    #[arg(long, global = true)]
    vault: Option<std::path::PathBuf>,

    #[command(subcommand)]
    command: commands::Command,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let vault_path = commands::resolve_vault_path(cli.vault);
    commands::execute(vault_path, cli.command)
}
