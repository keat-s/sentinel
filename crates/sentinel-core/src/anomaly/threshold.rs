//! Static threshold detector — the boring-but-essential baseline.
//!
//! Use this when the SLA is contractual: "P99 latency must be < 300 ms".
//! Threshold detectors complement statistical detectors (which catch
//! *unexpected* deviations) by catching *known unacceptable* values.

use crate::time::TimestampNanos;
use crate::tsdb::SeriesId;

use super::detector::{Anomaly, Detector, Severity};

/// Fire when `value` crosses `threshold` in the specified direction.
pub struct ThresholdDetector {
    name: String,
    series: SeriesId,
    threshold: f64,
    direction: Direction,
    severity: Severity,
}

/// Comparison direction for [`ThresholdDetector`].
#[derive(Debug, Clone, Copy)]
pub enum Direction {
    /// Fire when `value > threshold`.
    Above,
    /// Fire when `value < threshold`.
    Below,
}

impl ThresholdDetector {
    /// Construct a threshold detector.
    #[must_use]
    pub fn new(series: SeriesId, threshold: f64, direction: Direction, severity: Severity) -> Self {
        Self {
            name: "threshold".to_string(),
            series,
            threshold,
            direction,
            severity,
        }
    }
}

impl Detector for ThresholdDetector {
    fn name(&self) -> &str {
        &self.name
    }

    fn observe(&mut self, ts: TimestampNanos, value: f64) -> Option<Anomaly> {
        let trigger = match self.direction {
            Direction::Above => value > self.threshold,
            Direction::Below => value < self.threshold,
        };
        if !trigger {
            return None;
        }
        Some(Anomaly {
            timestamp: ts,
            series: self.series,
            source: self.name.clone(),
            value,
            score: (value - self.threshold).abs(),
            severity: self.severity,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn above_fires_when_value_exceeds() {
        let mut d = ThresholdDetector::new(SeriesId(7), 500.0, Direction::Above, Severity::Warning);
        assert!(d.observe(TimestampNanos(0), 600.0).is_some());
        assert!(d.observe(TimestampNanos(0), 400.0).is_none());
    }
}
