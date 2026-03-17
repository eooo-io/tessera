//! semblance-gateway — Localhost API daemon for agent access.

mod agent;
mod auth;
mod routes;
mod stream;

use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    tracing::info!("semblance-gateway starting");

    // TODO(Iteration 6): Build router, bind to 127.0.0.1, serve.
    println!("semblance-gateway is not yet implemented. See PLAN.md Iteration 6.");
    Ok(())
}
