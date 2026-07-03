//! Shared data model: discovered servers and findings.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Serialize;

/// Finding severity, ordered from least to most severe.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, clap::ValueEnum, Default,
)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    #[default]
    High,
    Critical,
}

impl Severity {
    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }
}

/// One issue the scanner surfaced.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// Stable check id, e.g. `SENTINEL-002`.
    pub check: String,
    pub severity: Severity,
    /// Server the finding is about, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Config file the server came from.
    pub source: PathBuf,
    pub title: String,
    pub detail: String,
    pub recommendation: String,
}

/// How an MCP server is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Stdio,
    Remote,
}

/// A server entry from any supported MCP client config.
#[derive(Debug, Clone, Serialize)]
pub struct McpServer {
    pub name: String,
    pub source: PathBuf,
    pub transport: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl McpServer {
    /// Basename of the launch command, if any.
    pub fn command_base(&self) -> Option<&str> {
        self.command
            .as_deref()
            .map(|c| c.rsplit(['/', '\\']).next().unwrap_or(c))
    }

    /// Whether the server is already wrapped by sentinel-gateway.
    pub fn is_governed(&self) -> bool {
        self.command_base()
            .map(|b| b == "sentinel-gateway" || b == "sentinel-gateway.exe")
            .unwrap_or(false)
    }
}
