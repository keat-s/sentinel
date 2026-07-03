//! `sentinel-gateway` — the trust layer for AI agents.
//!
//! A governance proxy that sits between an MCP client (Claude Code, Cursor,
//! any agent) and an MCP server, enforcing least-privilege policy on every
//! tool call, routing high-risk actions to human approval, and writing a
//! cryptographically signed, tamper-evident audit log of everything.

mod approvals;
mod commands;
mod config;
mod provenance;
mod proxy;
mod util;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "sentinel-gateway",
    version,
    about = "Least-privilege policy, human approvals, and signed audit for MCP tool calls"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Run the gateway, wrapping an MCP server command.
    ///
    /// Point your MCP client at this instead of the real server:
    ///   sentinel-gateway wrap --config sentinel-gateway.yaml -- npx my-mcp-server
    Wrap(commands::wrap::Args),
    /// Scaffold a config, starter policy, and signing keys in a directory.
    Init(commands::init::Args),
    /// Pin an MCP server's provenance: executable hash + tool-surface digests.
    ///
    /// The gateway then verifies the server against the lockfile and catches
    /// "rug pull" tool mutations at runtime:
    ///   sentinel-gateway pin --out server.lock.yaml -- npx my-mcp-server
    Pin(commands::pin::Args),
    /// Generate an ed25519 audit signing keypair.
    Keygen(commands::keygen::Args),
    /// Validate or dry-run a policy file.
    #[command(subcommand)]
    Policy(commands::policy_cmd::Cmd),
    /// Verify or inspect the signed audit log.
    #[command(subcommand)]
    Audit(commands::audit_cmd::Cmd),
    /// List and resolve pending human approvals.
    #[command(subcommand)]
    Approvals(commands::approvals_cmd::Cmd),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The gateway's own stdout is the MCP wire; all diagnostics go to stderr.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Wrap(a) => commands::wrap::run(a).await,
        Cmd::Init(a) => commands::init::run(a),
        Cmd::Pin(a) => commands::pin::run(a).await,
        Cmd::Keygen(a) => commands::keygen::run(a),
        Cmd::Policy(c) => commands::policy_cmd::run(c),
        Cmd::Audit(c) => commands::audit_cmd::run(c),
        Cmd::Approvals(c) => commands::approvals_cmd::run(c).await,
    }
}
