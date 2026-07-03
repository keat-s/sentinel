//! Gateway configuration file (YAML).

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Deserialize;

use sentinel_audit::ArgsMode;

/// Top-level gateway config.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayConfig {
    pub server: ServerCfg,
    #[serde(default)]
    pub identity: IdentityCfg,
    pub policy: PolicyCfg,
    pub audit: AuditCfg,
    #[serde(default)]
    pub approvals: Option<ApprovalsCfg>,
    #[serde(default)]
    pub control: ControlCfg,
    #[serde(default)]
    pub provenance: Option<ProvenanceCfg>,
}

/// The wrapped MCP server, as policy sees it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerCfg {
    /// Logical name used in policy `match.server` (not read from the wire).
    pub name: String,
}

/// Who this gateway instance acts for. Recorded on every audit entry and
/// matchable in policy (`match.agents` / `match.principals`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityCfg {
    #[serde(default = "default_agent")]
    pub agent: String,
    #[serde(default = "default_principal")]
    pub principal: String,
}

impl Default for IdentityCfg {
    fn default() -> Self {
        Self {
            agent: default_agent(),
            principal: default_principal(),
        }
    }
}

fn default_agent() -> String {
    "unknown-agent".to_string()
}

fn default_principal() -> String {
    "unknown-principal".to_string()
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyCfg {
    /// Path to the policy YAML (relative paths resolve against the config file).
    pub path: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCfg {
    /// Append-only JSONL log path.
    pub path: PathBuf,
    /// Hex ed25519 seed file (create with `sentinel-gateway keygen`).
    pub key_path: PathBuf,
    /// How tool-call arguments are captured: `omit` | `hash` (default) | `full`.
    #[serde(default)]
    pub log_args: ArgsMode,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalsCfg {
    /// Slack incoming-webhook URL (or any endpoint accepting `{"text": ...}`).
    #[serde(default)]
    pub webhook_url: Option<String>,
    /// How long a parked call waits before timing out (denied).
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    /// Include an argument preview in notifications and the approvals API.
    /// Off by default: approvers see metadata, not content.
    #[serde(default)]
    pub include_args: bool,
}

fn default_timeout() -> u64 {
    300
}

/// Provenance pinning: verify the wrapped server against a lockfile
/// created by `sentinel-gateway pin`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProvenanceCfg {
    /// Lockfile path (from `sentinel-gateway pin`).
    pub lock: PathBuf,
    /// What to do on divergence: `block` (default) refuses the executable /
    /// strips drifted tools and denies calls to them; `warn` records the
    /// violation in the audit log but lets traffic through.
    #[serde(default)]
    pub enforce: EnforceMode,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforceMode {
    Warn,
    #[default]
    Block,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlCfg {
    /// Bind address for the local approvals API (e.g. `127.0.0.1:9944`).
    /// Defaults to `127.0.0.1:9944` when approvals are configured; use port
    /// `0` to let the OS pick.
    #[serde(default)]
    pub listen: Option<String>,
}

/// Default control-API address, shared with the `approvals` CLI subcommands.
pub const DEFAULT_CONTROL_ADDR: &str = "127.0.0.1:9944";

impl GatewayConfig {
    /// Load from a YAML file, resolving relative paths against its directory.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("reading gateway config {}", path.display()))?;
        let mut cfg: GatewayConfig = serde_yaml::from_str(&text)
            .with_context(|| format!("parsing gateway config {}", path.display()))?;
        let base = path.parent().unwrap_or_else(|| Path::new("."));
        cfg.policy.path = absolutize(base, &cfg.policy.path);
        cfg.audit.path = absolutize(base, &cfg.audit.path);
        cfg.audit.key_path = absolutize(base, &cfg.audit.key_path);
        if let Some(prov) = &mut cfg.provenance {
            prov.lock = absolutize(base, &prov.lock);
        }
        Ok(cfg)
    }

    /// Control-API bind address to use, if the control plane should run.
    pub fn control_listen(&self) -> Option<String> {
        match (&self.control.listen, &self.approvals) {
            (Some(addr), _) => Some(addr.clone()),
            (None, Some(_)) => Some(DEFAULT_CONTROL_ADDR.to_string()),
            (None, None) => None,
        }
    }
}

fn absolutize(base: &Path, p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}
