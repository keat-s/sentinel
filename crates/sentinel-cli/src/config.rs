//! Server configuration loaded from YAML.

use std::path::Path;

use serde::Deserialize;

use sentinel_core::slo::SloConfig;

/// Top-level server config.
#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Address to bind the HTTP server to (e.g. `"0.0.0.0:9090"`).
    #[serde(default = "default_listen")]
    pub listen: String,
    /// Path to the WAL file. Pass an empty string to disable durability.
    #[serde(default)]
    pub wal_path: String,
    /// Per-series retention in minutes.
    #[serde(default = "default_retention")]
    pub retention_minutes: usize,
    /// SLOs to evaluate every cycle.
    #[serde(default)]
    pub slos: Vec<SloConfig>,
    /// SLO evaluation cadence in seconds.
    #[serde(default = "default_eval_secs")]
    pub eval_interval_secs: u64,
}

fn default_listen() -> String {
    "127.0.0.1:9090".to_string()
}
fn default_retention() -> usize {
    60 * 24
}
fn default_eval_secs() -> u64 {
    10
}

impl ServerConfig {
    /// Load from a YAML file. Returns a default config if the path is empty.
    pub fn from_yaml_path(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if path.as_os_str().is_empty() {
            return Ok(Self {
                listen: default_listen(),
                wal_path: String::new(),
                retention_minutes: default_retention(),
                slos: Vec::new(),
                eval_interval_secs: default_eval_secs(),
            });
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: ServerConfig = serde_yaml::from_str(&text)?;
        Ok(cfg)
    }
}
