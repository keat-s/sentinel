use std::path::PathBuf;

use anyhow::Context as _;
use sentinel_audit::{load_verifying_key, verify_file, Entry, Event};

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    /// Verify the hash chain and signatures of an audit log.
    Verify {
        /// Audit log (JSONL).
        #[arg(long, default_value = "sentinel-audit.jsonl")]
        log: PathBuf,
        /// Public key file (from `sentinel-gateway keygen`).
        #[arg(long = "pub")]
        public: PathBuf,
    },
    /// Pretty-print the most recent entries.
    Tail {
        /// Audit log (JSONL).
        #[arg(long, default_value = "sentinel-audit.jsonl")]
        log: PathBuf,
        /// How many entries to show.
        #[arg(long, short = 'n', default_value_t = 20)]
        count: usize,
    },
}

pub fn run(cmd: Cmd) -> anyhow::Result<()> {
    match cmd {
        Cmd::Verify { log, public } => {
            let vk = load_verifying_key(&public)?;
            match verify_file(&log, &vk) {
                Ok(report) => {
                    println!(
                        "OK: {} entries verified; chain head {}",
                        report.entries, report.head
                    );
                    Ok(())
                }
                Err(e) => {
                    eprintln!("AUDIT LOG FAILED VERIFICATION: {e}");
                    std::process::exit(1);
                }
            }
        }
        Cmd::Tail { log, count } => {
            let text = std::fs::read_to_string(&log)
                .with_context(|| format!("reading {}", log.display()))?;
            let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
            let start = lines.len().saturating_sub(count);
            for line in &lines[start..] {
                match serde_json::from_str::<Entry>(line) {
                    Ok(entry) => println!("{}", summarize(&entry)),
                    Err(_) => println!("<malformed entry>"),
                }
            }
            Ok(())
        }
    }
}

fn summarize(entry: &Entry) -> String {
    let r = &entry.record;
    let what = match &r.event {
        Event::GatewayStarted { server, .. } => format!("gateway started for `{server}`"),
        Event::ToolCallEvaluated {
            tool,
            decision,
            rule_id,
            risk,
            ..
        } => format!(
            "{} {tool} (rule {rule_id}{})",
            decision.to_uppercase(),
            risk.as_deref()
                .map(|r| format!(", risk {r}"))
                .unwrap_or_default()
        ),
        Event::ApprovalRequested {
            approval_id, tool, ..
        } => format!("approval requested for {tool} [{approval_id}]"),
        Event::ApprovalResolved {
            approval_id,
            resolution,
            resolved_by,
        } => format!(
            "approval {approval_id} {resolution}{}",
            resolved_by
                .as_deref()
                .map(|b| format!(" by {b}"))
                .unwrap_or_default()
        ),
        Event::ToolsFiltered { hidden, .. } => {
            format!("hid {} denied tool(s): {}", hidden.len(), hidden.join(", "))
        }
        Event::ProvenanceViolation {
            kind,
            subject,
            enforced,
            ..
        } => format!("PROVENANCE {kind} on `{subject}` ({enforced})"),
    };
    format!(
        "#{:<5} {}  {} <- {}/{}",
        r.seq, r.ts_ms, what, r.actor.principal, r.actor.agent
    )
}
