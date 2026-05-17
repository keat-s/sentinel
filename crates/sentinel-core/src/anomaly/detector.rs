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
