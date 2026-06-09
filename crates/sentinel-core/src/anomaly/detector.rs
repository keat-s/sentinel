//! Anomaly-detector trait and a thread-safe registry.

use std::sync::Arc;

use ahash::AHashMap;
use parking_lot::{Mutex, RwLock};
use serde::Serialize;

use crate::time::TimestampNanos;
use crate::tsdb::SeriesId;

/// Severity classification for emitted anomalies.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    /// Worth noting but not paging.
    Info,
    /// Likely problem.
    Warning,
    /// Almost certainly a problem.
    Critical,
}

/// One anomaly emitted by a detector.
#[derive(Debug, Clone, Serialize)]
pub struct Anomaly {
    /// Wall-clock time the anomaly was detected.
    pub timestamp: TimestampNanos,
    /// Series the anomaly relates to.
    pub series: SeriesId,
    /// Detector that produced it (used to disambiguate registered detectors).
    pub source: String,
    /// Observed value at the time of detection.
    pub value: f64,
    /// Detector-specific score (e.g. z-score). Higher = more anomalous.
    pub score: f64,
    /// Severity classification.
    pub severity: Severity,
}

/// Streaming anomaly detector.
///
/// Implementations are stateful: they're updated with each observation
/// and may emit an [`Anomaly`] from the same call.
pub trait Detector: Send + Sync {
    /// A short identifier for the kind of detector (`"zscore"`, etc.).
    fn name(&self) -> &str;

    /// Observe one value at `ts` and optionally emit an anomaly.
    fn observe(&mut self, ts: TimestampNanos, value: f64) -> Option<Anomaly>;
}

/// One detector handle.
type DetectorHandle = Arc<Mutex<dyn Detector>>;

/// Thread-safe registry mapping `SeriesId` → set of detectors.
///
/// Indexed by series so `observe()` is O(detectors-for-this-series),
/// not O(total-detectors). The outer `RwLock` is only held briefly
/// to clone out per-series detector handles; per-detector state is
/// protected by per-detector `Mutex`.
#[derive(Default)]
pub struct DetectorRegistry {
    by_series: RwLock<AHashMap<SeriesId, Vec<DetectorHandle>>>,
}

impl std::fmt::Debug for DetectorRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let g = self.by_series.read();
        let detector_total: usize = g.values().map(Vec::len).sum();
        f.debug_struct("DetectorRegistry")
            .field("series_count", &g.len())
            .field("detector_count", &detector_total)
            .finish()
    }
}

impl DetectorRegistry {
    /// Create an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a detector for one series.
    pub fn register<D: Detector + 'static>(&self, series: SeriesId, detector: D) {
        let mut g = self.by_series.write();
        g.entry(series)
            .or_default()
            .push(Arc::new(Mutex::new(detector)));
    }

    /// Feed an observation; collects any emitted anomalies across all
    /// detectors registered for `series`.
    pub fn observe(&self, series: SeriesId, ts: TimestampNanos, value: f64) -> Vec<Anomaly> {
        // Briefly take a read-lock on the index, clone handles out, drop.
        let handles: Vec<DetectorHandle> = {
            let g = self.by_series.read();
            match g.get(&series) {
                Some(v) => v.clone(),
                None => return Vec::new(),
            }
        };
        let mut out = Vec::new();
        for h in handles {
            let mut d = h.lock();
            if let Some(a) = d.observe(ts, value) {
                out.push(a);
            }
        }
        out
    }

    /// Total registered detectors across all series.
    pub fn len(&self) -> usize {
        self.by_series.read().values().map(Vec::len).sum()
    }

    /// Whether the registry is empty.
    pub fn is_empty(&self) -> bool {
        self.by_series.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test detector that fires (Info) whenever the value exceeds a fixed
    /// limit.
    struct FireAbove {
        name: String,
        series: SeriesId,
        limit: f64,
    }

    impl FireAbove {
        fn new(series: SeriesId, limit: f64) -> Self {
            Self {
                name: "fire_above".to_string(),
                series,
                limit,
            }
        }
    }

    impl Detector for FireAbove {
        fn name(&self) -> &str {
            &self.name
        }

        fn observe(&mut self, ts: TimestampNanos, value: f64) -> Option<Anomaly> {
            (value > self.limit).then(|| Anomaly {
                timestamp: ts,
                series: self.series,
                source: self.name.clone(),
                value,
                score: value - self.limit,
                severity: Severity::Info,
            })
        }
    }

    #[test]
    fn empty_registry_reports_empty_and_emits_nothing() {
        let reg = DetectorRegistry::new();
        assert!(reg.is_empty());
        assert_eq!(reg.len(), 0);
        let out = reg.observe(SeriesId(1), TimestampNanos(0), 1e9);
        assert!(out.is_empty(), "unregistered series must emit nothing");
    }

    #[test]
    fn observe_routes_only_to_registered_series() {
        let reg = DetectorRegistry::new();
        reg.register(SeriesId(1), FireAbove::new(SeriesId(1), 10.0));

        assert!(reg.observe(SeriesId(2), TimestampNanos(0), 100.0).is_empty());
        let fired = reg.observe(SeriesId(1), TimestampNanos(0), 100.0);
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].series, SeriesId(1));
        assert_eq!(fired[0].source, "fire_above");
    }

    #[test]
    fn value_below_limit_does_not_fire() {
        let reg = DetectorRegistry::new();
        reg.register(SeriesId(1), FireAbove::new(SeriesId(1), 10.0));
        assert!(reg.observe(SeriesId(1), TimestampNanos(0), 5.0).is_empty());
    }

    #[test]
    fn multiple_detectors_on_one_series_all_fire() {
        let reg = DetectorRegistry::new();
        reg.register(SeriesId(1), FireAbove::new(SeriesId(1), 10.0));
        reg.register(SeriesId(1), FireAbove::new(SeriesId(1), 20.0));
        reg.register(SeriesId(1), FireAbove::new(SeriesId(1), 1000.0));

        let fired = reg.observe(SeriesId(1), TimestampNanos(0), 50.0);
        assert_eq!(fired.len(), 2, "the two detectors with limit < 50 fire");
    }

    #[test]
    fn len_counts_detectors_across_series() {
        let reg = DetectorRegistry::new();
        reg.register(SeriesId(1), FireAbove::new(SeriesId(1), 1.0));
        reg.register(SeriesId(1), FireAbove::new(SeriesId(1), 2.0));
        reg.register(SeriesId(2), FireAbove::new(SeriesId(2), 3.0));
        assert_eq!(reg.len(), 3);
        assert!(!reg.is_empty());
    }

    #[test]
    fn detector_state_persists_across_observations() {
        // The registry must route every observation to the same underlying
        // detector instance (stateful contract of the Detector trait).
        struct CountToThree {
            seen: u64,
        }
        impl Detector for CountToThree {
            fn name(&self) -> &str {
                "count_to_three"
            }
            fn observe(&mut self, ts: TimestampNanos, value: f64) -> Option<Anomaly> {
                self.seen += 1;
                (self.seen == 3).then(|| Anomaly {
                    timestamp: ts,
                    series: SeriesId(1),
                    source: "count_to_three".to_string(),
                    value,
                    score: 1.0,
                    severity: Severity::Warning,
                })
            }
        }

        let reg = DetectorRegistry::new();
        reg.register(SeriesId(1), CountToThree { seen: 0 });
        assert!(reg.observe(SeriesId(1), TimestampNanos(0), 0.0).is_empty());
        assert!(reg.observe(SeriesId(1), TimestampNanos(1), 0.0).is_empty());
        assert_eq!(reg.observe(SeriesId(1), TimestampNanos(2), 0.0).len(), 1);
        assert!(reg.observe(SeriesId(1), TimestampNanos(3), 0.0).is_empty());
    }

    #[test]
    fn concurrent_observe_does_not_lose_observations() {
        // A detector with limit 0 fires on every observation, so the sum of
        // anomalies returned across threads counts deliveries exactly.
        let reg = std::sync::Arc::new(DetectorRegistry::new());
        reg.register(SeriesId(1), FireAbove::new(SeriesId(1), 0.0));

        let threads = 8;
        let per_thread = 1000u64;
        let mut handles = Vec::new();
        for _ in 0..threads {
            let reg = reg.clone();
            handles.push(std::thread::spawn(move || {
                let mut fired = 0u64;
                for i in 0..per_thread {
                    fired += reg.observe(SeriesId(1), TimestampNanos(i), 1.0).len() as u64;
                }
                fired
            }));
        }
        let total_fired: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(
            total_fired,
            threads * per_thread,
            "every concurrent observation must reach the detector exactly once"
        );
    }
}
