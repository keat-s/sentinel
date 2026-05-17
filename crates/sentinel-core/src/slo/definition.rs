//! SLO configuration: how to describe an SLO in YAML.
//!
//! Example:
//!
//! ```yaml
//! - name: inference-availability
//!   model: text-embedding-3
//!   sli:
//!     kind: success_ratio
//!   objective: 0.999
//!   window: 30d
//! - name: inference-p95-latency
//!   model: text-embedding-3
//!   sli:
//!     kind: latency_threshold
//!     threshold_ms: 500.0
//!   objective: 0.99
//!   window: 7d
//! ```

use serde::{Deserialize, Serialize};

use crate::time::{DAY, HOUR};

/// Service Level Indicator — the *thing being measured*.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Sli {
    /// Fraction of successful calls. "good" = `Status::Success`.
    SuccessRatio,
    /// Fraction of calls below a latency threshold.
    LatencyThreshold {
        /// Latency P-value to compare against (e.g. 0.95 → P95).
        #[serde(default = "default_quantile")]
        quantile: f64,
        /// Latency in milliseconds; events above this are "bad".
        threshold_ms: f64,
    },
}

fn default_quantile() -> f64 {
    0.95
}

/// SLO window expressed as a human-friendly duration string.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SloWindow(pub String);

impl SloWindow {
    /// Parse the window string into nanoseconds.
    ///
    /// Supported suffixes: `s`, `m`, `h`, `d`. Examples: `30d`, `12h`, `45m`.
    ///
    /// Returns `None` for invalid input (unknown unit, non-numeric prefix,
    /// or arithmetic overflow). Callers should reject invalid SLO windows
    /// at config-load time rather than silently treating them as zero.
    pub fn as_nanos_checked(&self) -> Option<u64> {
        let s = self.0.trim();
        if s.len() < 2 {
            return None;
        }
        let (num, unit) = s.split_at(s.len() - 1);
        let n: u64 = num.parse().ok()?;
        let mul = match unit {
            "s" => crate::time::SECOND,
            "m" => crate::time::MINUTE,
            "h" => HOUR,
            "d" => DAY,
            _ => return None,
        };
        n.checked_mul(mul)
    }

    /// Lossy parse: returns 0 for invalid input. Prefer [`as_nanos_checked`].
    ///
    /// Retained for backward-compat callers; new code should use
    /// [`as_nanos_checked`](Self::as_nanos_checked) and report errors.
    pub fn as_nanos(&self) -> u64 {
        self.as_nanos_checked().unwrap_or(0)
    }
}

/// One SLO definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SloConfig {
    /// Human-readable identifier.
    pub name: String,
    /// Which model (label `model=`) this SLO is about.
    pub model: String,
    /// What is being measured.
    pub sli: Sli,
    /// Target ratio in `(0, 1)`. E.g. `0.999` = three nines.
    pub objective: f64,
    /// Rolling window. The burn-rate computation derives a budget from this.
    pub window: SloWindow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_roundtrip() {
        let yaml = r#"
- name: avail
  model: gpt-4
  sli:
    kind: success_ratio
  objective: 0.999
  window: 30d
- name: lat
  model: gpt-4
  sli:
    kind: latency_threshold
    threshold_ms: 500.0
    quantile: 0.95
  objective: 0.99
  window: 7d
"#;
        let slos: Vec<SloConfig> = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(slos.len(), 2);
        assert_eq!(slos[0].name, "avail");
        match &slos[1].sli {
            Sli::LatencyThreshold { threshold_ms, quantile } => {
                assert_eq!(*threshold_ms, 500.0);
                assert!((*quantile - 0.95).abs() < 1e-9);
            }
            _ => panic!("expected latency threshold"),
        }
    }

    #[test]
    fn window_parses_units() {
        assert_eq!(SloWindow("30d".into()).as_nanos(), 30 * DAY);
        assert_eq!(SloWindow("12h".into()).as_nanos(), 12 * HOUR);
        assert_eq!(SloWindow("90m".into()).as_nanos(), 90 * crate::time::MINUTE);
    }

    #[test]
    fn window_rejects_invalid_input() {
        assert!(SloWindow("".into()).as_nanos_checked().is_none());
        assert!(SloWindow("foo".into()).as_nanos_checked().is_none());
        assert!(SloWindow("30y".into()).as_nanos_checked().is_none());
        assert!(SloWindow("xd".into()).as_nanos_checked().is_none());
    }

    #[test]
    fn window_rejects_overflow() {
        // 30 huge_value × DAY would overflow u64
        let huge = format!("{}d", u64::MAX);
        assert!(SloWindow(huge).as_nanos_checked().is_none());
    }
}
