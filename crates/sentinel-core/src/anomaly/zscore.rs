//! Streaming z-score detector.
//!
//! Uses an EWMA mean + variance (Welford-style) to maintain a rolling
//! baseline and emits an anomaly when `|z| > threshold`. The detector
//! has a short warmup before it will emit anything to avoid firing on
//! the first observation.

use crate::sketches::EwmaVariance;
use crate::time::TimestampNanos;
use crate::tsdb::SeriesId;

use super::detector::{Anomaly, Detector, Severity};

/// EWMA-based streaming z-score detector.
pub struct ZScoreDetector {
    name: String,
    series: SeriesId,
    stats: EwmaVariance,
    threshold: f64,
    warmup: u64,
}

impl ZScoreDetector {
    /// Construct a detector.
    ///
    /// - `alpha`: smoothing factor for EWMA (e.g. `0.05` → ~40-sample EMA)
    /// - `threshold`: z-score above which to fire (typical: `3.0`)
    /// - `warmup`: number of observations before the detector will fire
    ///
    /// # Panics
    /// Panics if `alpha` is outside `(0, 1]` or NaN.
    #[must_use]
    pub fn new(series: SeriesId, alpha: f64, threshold: f64, warmup: u64) -> Self {
        Self {
            name: "zscore".to_string(),
            series,
            stats: EwmaVariance::new(alpha),
            threshold,
            warmup,
        }
    }

    fn severity(z: f64) -> Severity {
        let a = z.abs();
        if a >= 6.0 {
            Severity::Critical
        } else if a >= 4.0 {
            Severity::Warning
        } else {
            Severity::Info
        }
    }
}

impl Detector for ZScoreDetector {
    fn name(&self) -> &str {
        &self.name
    }

    fn observe(&mut self, ts: TimestampNanos, value: f64) -> Option<Anomaly> {
        // We need the prior baseline *before* incorporating the value, so
        // we compute z first and then update.
        let z_pre = self.stats.z_score(value);
        self.stats.observe(value);

        if self.stats.count() < self.warmup {
            return None;
        }
        let z = z_pre?;
        if z.abs() < self.threshold {
            return None;
        }
        Some(Anomaly {
            timestamp: ts,
            series: self.series,
            source: self.name.clone(),
            value,
            score: z,
            severity: Self::severity(z),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::TimestampNanos;

    #[test]
    fn flat_stream_with_one_spike_fires_once() {
        let mut d = ZScoreDetector::new(SeriesId(1), 0.1, 3.0, 30);
        let mut fired = 0;
        // 200 noisy baseline observations
        let mut state: u64 = 0xabc;
        for i in 0..200 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let noise = ((state >> 11) as f64 / (1u64 << 53) as f64) - 0.5;
            let v = if i == 150 { 1000.0 } else { 50.0 + noise };
            if let Some(_a) = d.observe(TimestampNanos(i as u64), v) {
                fired += 1;
            }
        }
        assert_eq!(fired, 1, "expected exactly one anomaly");
    }

    #[test]
    fn slow_drift_does_not_fire() {
        let mut d = ZScoreDetector::new(SeriesId(1), 0.1, 3.0, 30);
        let mut fired = 0;
        for i in 0..500 {
            let v = 100.0 + (i as f64) * 0.01;
            if d.observe(TimestampNanos(i as u64), v).is_some() {
                fired += 1;
            }
        }
        // EWMA tracks the drift; a small constant slope shouldn't fire.
        assert!(fired <= 3, "expected near-zero alarms, got {fired}");
    }
}
