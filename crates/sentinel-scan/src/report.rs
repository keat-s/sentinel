//! Report rendering: human text and machine JSON.

use std::path::PathBuf;

use serde::Serialize;

use crate::model::{Finding, Severity};
use crate::probe::ProbedServer;

#[derive(Debug, Serialize)]
pub struct Report {
    pub configs_scanned: Vec<PathBuf>,
    pub servers_found: usize,
    pub servers_governed: usize,
    pub servers_probed: usize,
    /// Identity each probed server reported about itself.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub probed: Vec<ProbedServer>,
    pub findings: Vec<Finding>,
}

impl Report {
    /// Most severe finding, if any.
    pub fn max_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn render_json(&self) -> String {
        serde_json::to_string_pretty(self).expect("report serializes")
    }

    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str("sentinel-scan report\n");
        out.push_str("====================\n");
        out.push_str(&format!(
            "Scanned {} config file(s); {} server(s) found, {} governed by sentinel-gateway, {} probed live.\n\n",
            self.configs_scanned.len(),
            self.servers_found,
            self.servers_governed,
            self.servers_probed,
        ));

        if self.findings.is_empty() {
            out.push_str("No findings.\n");
            return out;
        }

        let mut sorted: Vec<&Finding> = self.findings.iter().collect();
        sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then(a.check.cmp(&b.check)));
        for f in &sorted {
            out.push_str(&format!(
                "[{:<8}] {} — {}{}\n",
                f.severity.label(),
                f.check,
                f.title,
                f.server
                    .as_deref()
                    .map(|s| format!(" (server `{s}`)"))
                    .unwrap_or_default(),
            ));
            out.push_str(&format!("           {}\n", f.detail));
            out.push_str(&format!("           fix: {}\n", f.recommendation));
            out.push_str(&format!("           in:  {}\n\n", f.source.display()));
        }

        let count = |s: Severity| self.findings.iter().filter(|f| f.severity == s).count();
        out.push_str(&format!(
            "Summary: {} critical, {} high, {} medium, {} low, {} info\n",
            count(Severity::Critical),
            count(Severity::High),
            count(Severity::Medium),
            count(Severity::Low),
            count(Severity::Info),
        ));
        out
    }
}
