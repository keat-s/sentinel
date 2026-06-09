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

#[cfg(test)]
mod tests {
    use super::*;

    use sentinel_core::slo::Sli;

    /// Temp file that cleans up after itself.
    struct TempYaml(std::path::PathBuf);

    impl TempYaml {
        fn new(name: &str, contents: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "sentinel-config-test-{}-{name}.yaml",
                std::process::id()
            ));
            std::fs::write(&path, contents).unwrap();
            Self(path)
        }
    }

    impl Drop for TempYaml {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    #[test]
    fn empty_path_yields_defaults() {
        let cfg = ServerConfig::from_yaml_path("").unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:9090");
        assert_eq!(cfg.wal_path, "");
        assert_eq!(cfg.retention_minutes, 60 * 24);
        assert_eq!(cfg.eval_interval_secs, 10);
        assert!(cfg.slos.is_empty());
    }

    #[test]
    fn full_yaml_parses() {
        let tmp = TempYaml::new(
            "full",
            r#"
listen: "0.0.0.0:8080"
wal_path: "/tmp/sentinel.wal"
retention_minutes: 120
eval_interval_secs: 5
slos:
  - name: avail
    model: gpt-4o
    sli:
      kind: success_ratio
    objective: 0.999
    window: 30d
  - name: p95
    model: gpt-4o
    sli:
      kind: latency_threshold
      threshold_ms: 500.0
    objective: 0.99
    window: 7d
"#,
        );
        let cfg = ServerConfig::from_yaml_path(&tmp.0).unwrap();
        assert_eq!(cfg.listen, "0.0.0.0:8080");
        assert_eq!(cfg.wal_path, "/tmp/sentinel.wal");
        assert_eq!(cfg.retention_minutes, 120);
        assert_eq!(cfg.eval_interval_secs, 5);
        assert_eq!(cfg.slos.len(), 2);
        assert!(matches!(cfg.slos[0].sli, Sli::SuccessRatio));
        assert!(matches!(
            cfg.slos[1].sli,
            Sli::LatencyThreshold { threshold_ms, .. } if threshold_ms == 500.0
        ));
    }

    #[test]
    fn minimal_yaml_fills_serde_defaults() {
        let tmp = TempYaml::new("minimal", "listen: \"127.0.0.1:7777\"\n");
        let cfg = ServerConfig::from_yaml_path(&tmp.0).unwrap();
        assert_eq!(cfg.listen, "127.0.0.1:7777");
        // Everything else falls back to defaults.
        assert_eq!(cfg.wal_path, "");
        assert_eq!(cfg.retention_minutes, 60 * 24);
        assert_eq!(cfg.eval_interval_secs, 10);
        assert!(cfg.slos.is_empty());
    }

    #[test]
    fn malformed_yaml_is_an_error() {
        let tmp = TempYaml::new("malformed", "listen: [unclosed\n");
        assert!(ServerConfig::from_yaml_path(&tmp.0).is_err());
    }

    #[test]
    fn missing_file_is_an_error() {
        let err = ServerConfig::from_yaml_path("/nonexistent/sentinel-test.yaml");
        assert!(err.is_err());
    }
}
