use std::path::PathBuf;

use crate::config::GatewayConfig;
use crate::provenance;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Gateway config; if it has a `provenance.lock` path, that's the
    /// default output location.
    #[arg(long, short = 'c')]
    config: Option<PathBuf>,
    /// Where to write the lockfile.
    #[arg(long)]
    out: Option<PathBuf>,
    /// The MCP server command to pin (after `--`).
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    let out = match (args.out, &args.config) {
        (Some(out), _) => out,
        (None, Some(cfg_path)) => {
            let cfg = GatewayConfig::load(cfg_path)?;
            cfg.provenance
                .map(|p| p.lock)
                .unwrap_or_else(|| PathBuf::from("sentinel-server.lock.yaml"))
        }
        (None, None) => PathBuf::from("sentinel-server.lock.yaml"),
    };

    let lock = provenance::pin(&args.command).await?;
    lock.save(&out)?;

    println!("pinned `{}`", args.command.join(" "));
    println!("  executable: {}", lock.executable.path);
    println!("  sha256:     {}", lock.executable.sha256);
    if let Some(info) = &lock.server_info {
        println!("  server:     {info}");
    }
    println!("  tools:      {} definition(s) digested", lock.tools.len());
    println!("wrote {}", out.display());
    println!();
    println!("Enable enforcement in your gateway config:");
    println!("  provenance:");
    println!("    lock: {}", out.display());
    println!("    enforce: block   # or `warn`");
    Ok(())
}
