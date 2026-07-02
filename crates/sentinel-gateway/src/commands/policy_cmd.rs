use std::path::PathBuf;

use anyhow::Context as _;
use sentinel_policy::{CallCtx, Effect, Policy};

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    /// Parse and validate a policy file.
    Check {
        /// Policy YAML file.
        #[arg(long, short = 'p', default_value = "policy.yaml")]
        policy: PathBuf,
    },
    /// Evaluate a hypothetical tool call and print the decision.
    ///
    /// Exit code: 0 = allow, 1 = deny, 2 = approve.
    Eval {
        #[arg(long, short = 'p', default_value = "policy.yaml")]
        policy: PathBuf,
        /// Logical MCP server name.
        #[arg(long)]
        server: String,
        /// Tool name.
        #[arg(long)]
        tool: String,
        /// Agent identity.
        #[arg(long, default_value = "unknown-agent")]
        agent: String,
        /// Human principal.
        #[arg(long, default_value = "unknown-principal")]
        principal: String,
        /// Tool-call arguments as JSON.
        #[arg(long, default_value = "{}")]
        args: String,
    },
}

pub fn run(cmd: Cmd) -> anyhow::Result<()> {
    match cmd {
        Cmd::Check { policy } => {
            let text = std::fs::read_to_string(&policy)
                .with_context(|| format!("reading {}", policy.display()))?;
            let parsed = Policy::from_yaml(&text)?;
            println!(
                "policy OK: {} rule(s), default action `{}`",
                parsed.rules().len(),
                parsed.default_action().as_str()
            );
            Ok(())
        }
        Cmd::Eval {
            policy,
            server,
            tool,
            agent,
            principal,
            args,
        } => {
            let text = std::fs::read_to_string(&policy)
                .with_context(|| format!("reading {}", policy.display()))?;
            let parsed = Policy::from_yaml(&text)?;
            let args: serde_json::Value =
                serde_json::from_str(&args).context("parsing --args as JSON")?;
            let decision = parsed.evaluate(&CallCtx {
                server: &server,
                tool: &tool,
                agent: &agent,
                principal: &principal,
                args: &args,
            });
            println!(
                "{}",
                serde_json::json!({
                    "effect": decision.effect.as_str(),
                    "rule_id": decision.rule_id,
                    "risk": decision.risk.map(|r| r.as_str()),
                    "reason": decision.reason,
                })
            );
            std::process::exit(match decision.effect {
                Effect::Allow => 0,
                Effect::Deny => 1,
                Effect::Approve => 2,
            });
        }
    }
}
