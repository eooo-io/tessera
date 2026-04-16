//! tessera-cli — Command-line interface for vault operations.

mod commands;

use clap::Parser;

#[derive(Parser)]
#[command(name = "tessera")]
#[command(about = "Personal context vault with policy-gated retrieval")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: commands::Command,
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    commands::execute(cli.command)
}
