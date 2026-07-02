use std::path::PathBuf;

use crate::config::GatewayConfig;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Gateway config file.
    #[arg(long, short = 'c', default_value = "sentinel-gateway.yaml")]
    config: PathBuf,
    /// The real MCP server command (after `--`).
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    let cfg = GatewayConfig::load(&args.config)?;
    crate::proxy::run(cfg, args.command).await
}
