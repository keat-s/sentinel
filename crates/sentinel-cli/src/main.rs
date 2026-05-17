//! `sentinel` — CLI entrypoint.

mod commands;
mod config;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "sentinel", version, about = "Observability engine for ML inference services")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the HTTP ingestion + query server.
    Serve(commands::serve::Args),
    /// Generate synthetic ML inference traffic against a running server.
    Simulate(commands::simulate::Args),
    /// Run a one-shot query against the server.
    Query(commands::query::Args),
    /// Launch the live terminal dashboard.
    Dashboard(commands::dashboard::Args),
    /// Benchmark in-process ingestion throughput.
    Bench(commands::bench::Args),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Serve(a) => commands::serve::run(a).await,
        Cmd::Simulate(a) => commands::simulate::run(a).await,
        Cmd::Query(a) => commands::query::run(a).await,
        Cmd::Dashboard(a) => commands::dashboard::run(a).await,
        Cmd::Bench(a) => commands::bench::run(a).await,
    }
}
