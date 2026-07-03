use std::path::PathBuf;

#[derive(Debug, clap::Args)]
pub struct Args {
    /// Directory to scaffold into.
    #[arg(long, default_value = ".")]
    dir: PathBuf,
}

const CONFIG_TEMPLATE: &str = r#"# Sentinel gateway configuration.
# Run:  sentinel-gateway wrap --config sentinel-gateway.yaml -- <mcp-server-command>

server:
  # Logical name used by policy `match.server`.
  name: my-server

identity:
  # Who this agent session acts for; recorded on every audit entry.
  agent: claude-code
  principal: you@example.com

policy:
  path: policy.yaml

audit:
  path: sentinel-audit.jsonl
  key_path: sentinel-audit.key
  # How tool-call arguments are recorded: omit | hash (default) | full.
  log_args: hash

approvals:
  # Slack incoming webhook (or any endpoint accepting {"text": ...}).
  # webhook_url: https://hooks.slack.com/services/T000/B000/XXXX
  timeout_secs: 300
  include_args: false

control:
  # Local API used by `sentinel-gateway approvals ...`
  listen: 127.0.0.1:9944

# Provenance pinning — catch "rug pull" server/tool mutations.
# Create the lockfile once:  sentinel-gateway pin --out server.lock.yaml -- <command>
# provenance:
#   lock: server.lock.yaml
#   enforce: block
"#;

const POLICY_TEMPLATE: &str = r#"# Sentinel policy — least privilege for AI agent tool calls.
# Rules are evaluated top to bottom; first match wins.
version: 1
default_action: deny

rules:
  # The postmark-mcp lesson: an agent tricked by prompt injection quietly
  # BCCs your mail to an attacker. Kill the whole vector.
  - id: block-bcc
    description: Never allow BCC on agent-sent email
    match:
      tools: ["send_email", "send_message"]
      args:
        - path: bcc
          exists: true
    action: deny
    risk: critical
    reason: Hidden BCC on agent-sent email is a data-exfiltration vector

  # Destructive operations are never agent-callable.
  - id: block-destructive
    match:
      tools: ["delete_*", "drop_*", "remove_all_*"]
    action: deny
    risk: high
    reason: Destructive operations require a human at the keyboard

  # Anything outward-facing needs a human sign-off first.
  - id: approve-outbound
    match:
      tools: ["send_*", "post_*", "publish_*"]
    action: approve
    risk: high
    reason: Outward-facing actions require pre-action approval

  # Read-only operations are fine.
  - id: allow-reads
    match:
      tools: ["get_*", "list_*", "search_*", "read_*"]
    action: allow
    risk: low

# Everything else falls through to default_action: deny.
"#;

pub fn run(args: Args) -> anyhow::Result<()> {
    std::fs::create_dir_all(&args.dir)?;
    let config = args.dir.join("sentinel-gateway.yaml");
    let policy = args.dir.join("policy.yaml");
    let key = args.dir.join("sentinel-audit.key");
    let public = args.dir.join("sentinel-audit.key.pub");

    for (path, content) in [(&config, CONFIG_TEMPLATE), (&policy, POLICY_TEMPLATE)] {
        if path.exists() {
            println!("skipping {} (already exists)", path.display());
        } else {
            std::fs::write(path, content)?;
            println!("wrote {}", path.display());
        }
    }

    if key.exists() {
        println!("skipping {} (already exists)", key.display());
    } else {
        let signing = sentinel_audit::generate_signing_key();
        sentinel_audit::save_keypair(&signing, &key, &public)?;
        println!("wrote {} and {}", key.display(), public.display());
    }

    println!();
    println!("Next steps:");
    println!("  1. Edit policy.yaml for your tools (validate: sentinel-gateway policy check)");
    println!("  2. Point your MCP client at:");
    println!("       sentinel-gateway wrap --config {} -- <your-mcp-server-command>", config.display());
    println!("  3. Verify the audit trail any time:");
    println!("       sentinel-gateway audit verify --log sentinel-audit.jsonl --pub {}", public.display());
    Ok(())
}
