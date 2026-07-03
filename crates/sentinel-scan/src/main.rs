//! `sentinel-scan` — MCP security scanner.
//!
//! Finds MCP client configs (Claude Code, Claude Desktop, Cursor, VS Code),
//! flags shadow / unpinned / ungoverned servers and inline secrets, optionally
//! live-probes servers for prompt-injected tool metadata, and can generate a
//! starter least-privilege Sentinel policy from what it saw.

mod checks;
mod configs;
mod model;
mod policy_gen;
mod probe;
mod report;

use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;

use model::{Finding, Severity, Transport};
use report::Report;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum FailOn {
    Never,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Parser)]
#[command(
    name = "sentinel-scan",
    version,
    about = "Scan MCP client configs for shadow, unpinned, and ungoverned servers; probe for poisoned tool metadata"
)]
struct Cli {
    /// Files or directories to scan (directories are walked for MCP configs).
    #[arg(default_value = ".")]
    paths: Vec<PathBuf>,
    /// Also check well-known per-user config locations (~/.cursor, Claude Desktop).
    #[arg(long)]
    home: bool,
    /// Launch each stdio server and analyze its live tool surface.
    /// This EXECUTES the configured commands — only use on configs you trust
    /// enough to run.
    #[arg(long)]
    probe: bool,
    /// Per-server probe timeout in seconds.
    #[arg(long, default_value_t = 10)]
    probe_timeout_secs: u64,
    /// Write a starter least-privilege policy generated from probed tool
    /// surfaces (requires --probe).
    #[arg(long)]
    emit_policy: Option<PathBuf>,
    #[arg(long, value_enum, default_value_t = Format::Text)]
    format: Format,
    /// Exit non-zero if any finding is at or above this severity.
    #[arg(long, value_enum, default_value_t = FailOn::High)]
    fail_on: FailOn,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    anyhow::ensure!(
        cli.emit_policy.is_none() || cli.probe,
        "--emit-policy requires --probe (the policy is generated from the live tool surface)"
    );

    let config_paths = configs::discover(&cli.paths, cli.home);
    let mut findings: Vec<Finding> = Vec::new();
    let mut servers = Vec::new();
    for path in &config_paths {
        match configs::parse_config(path) {
            Ok(mut parsed) => servers.append(&mut parsed),
            Err(e) => findings.push(Finding {
                check: "SENTINEL-000".into(),
                severity: Severity::Low,
                server: None,
                source: path.clone(),
                title: "unparseable MCP config".into(),
                detail: e.to_string(),
                recommendation: "fix or remove the file; unparseable configs hide what agents can reach".into(),
            }),
        }
    }

    findings.extend(checks::run_static_checks(&servers));

    let mut probed = Vec::new();
    if cli.probe {
        let timeout = Duration::from_secs(cli.probe_timeout_secs);
        for server in servers.iter().filter(|s| s.transport == Transport::Stdio) {
            // Probing a governed entry would launch the gateway (and the real
            // server behind it); scan the underlying surface separately.
            if server.is_governed() {
                continue;
            }
            match probe::probe(server, timeout).await {
                Ok(result) => {
                    findings.extend(probe::analyze(server, &result));
                    probed.push(result);
                }
                Err(e) => findings.push(Finding {
                    check: "SENTINEL-100".into(),
                    severity: Severity::Info,
                    server: Some(server.name.clone()),
                    source: server.source.clone(),
                    title: "probe failed".into(),
                    detail: format!("{e:#}"),
                    recommendation: "verify the command runs; a server that won't start can't be assessed".into(),
                }),
            }
        }
    }

    if let Some(out) = &cli.emit_policy {
        let doc = policy_gen::generate(&probed);
        std::fs::write(out, policy_gen::render(&doc)?)?;
        eprintln!("wrote starter policy to {}", out.display());
    }

    let report = Report {
        configs_scanned: config_paths,
        servers_found: servers.len(),
        servers_governed: servers.iter().filter(|s| s.is_governed()).count(),
        servers_probed: probed.len(),
        probed,
        findings,
    };

    match cli.format {
        Format::Text => print!("{}", report.render_text()),
        Format::Json => println!("{}", report.render_json()),
    }

    let threshold = match cli.fail_on {
        FailOn::Never => None,
        FailOn::Low => Some(Severity::Low),
        FailOn::Medium => Some(Severity::Medium),
        FailOn::High => Some(Severity::High),
        FailOn::Critical => Some(Severity::Critical),
    };
    if let (Some(threshold), Some(max)) = (threshold, report.max_severity()) {
        if max >= threshold {
            std::process::exit(1);
        }
    }
    Ok(())
}
