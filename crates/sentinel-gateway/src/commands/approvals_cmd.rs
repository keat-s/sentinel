use anyhow::Context as _;

use crate::config::DEFAULT_CONTROL_ADDR;

fn default_addr() -> String {
    format!("http://{DEFAULT_CONTROL_ADDR}")
}

#[derive(Debug, clap::Subcommand)]
pub enum Cmd {
    /// List pending approvals.
    List {
        /// Control API base URL of the running gateway.
        #[arg(long, default_value_t = default_addr())]
        addr: String,
    },
    /// Approve a pending call; the gateway forwards it to the MCP server.
    Approve {
        /// Approval id (from the notification or `approvals list`).
        id: String,
        #[arg(long, default_value_t = default_addr())]
        addr: String,
        /// Who is approving (recorded in the audit log).
        #[arg(long)]
        by: Option<String>,
    },
    /// Deny a pending call; the agent receives a policy denial.
    Deny {
        id: String,
        #[arg(long, default_value_t = default_addr())]
        addr: String,
        #[arg(long)]
        by: Option<String>,
    },
}

pub async fn run(cmd: Cmd) -> anyhow::Result<()> {
    let client = reqwest::Client::new();
    match cmd {
        Cmd::List { addr } => {
            let body: serde_json::Value = client
                .get(format!("{addr}/v1/approvals"))
                .send()
                .await
                .with_context(|| format!("is a gateway running at {addr}?"))?
                .error_for_status()?
                .json()
                .await?;
            let approvals = body["approvals"].as_array().cloned().unwrap_or_default();
            if approvals.is_empty() {
                println!("no pending approvals");
            } else {
                for a in approvals {
                    println!(
                        "{}  {}.{}  rule={}  risk={}  reason={}",
                        a["id"].as_str().unwrap_or("?"),
                        a["server"].as_str().unwrap_or("?"),
                        a["tool"].as_str().unwrap_or("?"),
                        a["rule_id"].as_str().unwrap_or("?"),
                        a["risk"].as_str().unwrap_or("-"),
                        a["reason"].as_str().unwrap_or("-"),
                    );
                }
            }
            Ok(())
        }
        Cmd::Approve { id, addr, by } => resolve(&client, &addr, &id, true, by).await,
        Cmd::Deny { id, addr, by } => resolve(&client, &addr, &id, false, by).await,
    }
}

async fn resolve(
    client: &reqwest::Client,
    addr: &str,
    id: &str,
    approve: bool,
    by: Option<String>,
) -> anyhow::Result<()> {
    let verb = if approve { "approve" } else { "deny" };
    let resp = client
        .post(format!("{addr}/v1/approvals/{id}/{verb}"))
        .json(&serde_json::json!({ "by": by }))
        .send()
        .await
        .with_context(|| format!("is a gateway running at {addr}?"))?;
    if resp.status().is_success() {
        println!("{verb}d {id}");
        Ok(())
    } else {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("{verb} failed ({status}): {body}");
    }
}
