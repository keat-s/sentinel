//! `sentinel query` — one-shot query against a running server.

use clap::Args as ClapArgs;

/// `sentinel query` arguments.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Target Sentinel server URL.
    #[arg(long, default_value = "http://127.0.0.1:9090")]
    pub url: String,
    /// Model label to query.
    #[arg(long)]
    pub model: String,
    /// Rolling window (e.g. `"1h"`, `"30m"`, `"7d"`).
    #[arg(long, default_value = "1h")]
    pub window: String,
    /// Latency quantile to compute.
    #[arg(long, default_value_t = 0.95)]
    pub quantile: f64,
}

/// Entrypoint for `sentinel query`.
pub async fn run(args: Args) -> anyhow::Result<()> {
    let url = format!(
        "{}/v1/query?model={}&window={}&quantile={}",
        args.url.trim_end_matches('/'),
        urlencode(&args.model),
        urlencode(&args.window),
        args.quantile
    );
    let resp = reqwest::get(url).await?;
    let status = resp.status();
    let body: serde_json::Value = resp.json().await?;
    if !status.is_success() {
        anyhow::bail!("non-2xx: {} {}", status, body);
    }
    println!("{}", serde_json::to_string_pretty(&body)?);
    Ok(())
}

fn urlencode(s: &str) -> String {
    // Tiny inline urlencode for the few chars we actually pass.
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' | '~' => out.push(c),
            _ => {
                for b in c.to_string().as_bytes() {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
    }
    out
}
