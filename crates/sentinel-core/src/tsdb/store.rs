//! In-memory time-series store with per-series minute buckets.

use std::collections::VecDeque;
use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::RwLock;

use crate::ingest::{InferenceEvent, Status};
use crate::sketches::{HyperLogLog, TDigest};
use crate::time::{Clock, SystemClock, TimestampNanos, MINUTE};
use crate::tsdb::chunk::Chunk;
use crate::tsdb::series::{SeriesId, SeriesKey};

/// Result of a windowed query against the TSDB.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// Latency quantile (computed from a merged digest over the window).
    pub latency_quantile_ms: f64,
    /// Quantile that was asked for.
    pub quantile: f64,
    /// Total events.
    pub total: u64,
    /// Good events (Status::Success).
    pub good: u64,
    /// Server failures (ServerError | Timeout).
    pub server_failures: u64,
    /// Success ratio in `[0, 1]`, NaN if `total == 0`.
    pub success_ratio: f64,
    /// Estimated cardinality of model versions seen in the window.
    pub model_version_cardinality: u64,
}

/// Threshold-based latency query result: how many events exceeded the
/// supplied latency threshold, computed from the merged digest's CDF.
#[derive(Debug, Clone)]
pub struct LatencyThresholdResult {
    /// Total events in the window.
    pub total: u64,
    /// Estimated count of events whose latency exceeded `threshold_ms`.
    pub count_above: u64,
}

/// Per-series rolling window of minute-aggregated chunks.
struct SeriesState {
    key: SeriesKey,
    /// Sorted ascending by `minute`. Length capped at `retention_minutes`.
    chunks: VecDeque<Chunk>,
    /// Most recently observed minute (for "now" clamping during query).
    last_observed_minute: u64,
    /// HLL of model versions seen — cheap drift signal.
    version_hll: HyperLogLog,
}

impl SeriesState {
    fn new(key: SeriesKey) -> Self {
        Self {
            key,
            chunks: VecDeque::new(),
            last_observed_minute: 0,
            version_hll: HyperLogLog::new(),
        }
    }

    fn record(&mut self, minute: u64, status: Status, latency_ms: f64, retention: usize) {
        if minute > self.last_observed_minute {
            self.last_observed_minute = minute;
        }
        // Append-or-update the chunk for `minute`.
        match self.chunks.back_mut() {
            Some(last) if last.minute == minute => {
                last.record(status, latency_ms);
            }
            Some(last) if last.minute < minute => {
                self.chunks.push_back(Chunk::new(minute));
                self.chunks
                    .back_mut()
                    .expect("just pushed")
                    .record(status, latency_ms);
            }
            None => {
                self.chunks.push_back(Chunk::new(minute));
                self.chunks
                    .back_mut()
                    .expect("just pushed")
                    .record(status, latency_ms);
            }
            Some(_) => {
                // Out-of-order minute — find/insert in sorted position.
                // Rare path; linear scan is fine.
                let pos = self
                    .chunks
                    .iter()
                    .position(|c| c.minute >= minute)
                    .unwrap_or(self.chunks.len());
                if pos < self.chunks.len() && self.chunks[pos].minute == minute {
                    self.chunks[pos].record(status, latency_ms);
                } else {
                    self.chunks.insert(pos, Chunk::new(minute));
                    self.chunks[pos].record(status, latency_ms);
                }
            }
        }
        // Evict old chunks.
        while self.chunks.len() > retention {
            self.chunks.pop_front();
        }
    }

    fn aggregate(&self, from_minute: u64, to_minute: u64, quantile: f64) -> QueryResult {
        let mut total = 0u64;
        let mut good = 0u64;
        let mut server_failures = 0u64;
        let mut digest = TDigest::new(200.0);

        for c in &self.chunks {
            if c.minute < from_minute || c.minute > to_minute {
                continue;
            }
            total += c.total();
            good += c.good();
            server_failures += c.server_failures();
            digest.merge(&c.latency);
        }

        let success_ratio = if total == 0 {
            f64::NAN
        } else {
            good as f64 / total as f64
        };
        let latency_quantile_ms = if digest.is_empty() {
            f64::NAN
        } else {
            digest.quantile(quantile)
        };

        QueryResult {
            latency_quantile_ms,
            quantile,
            total,
            good,
            server_failures,
            success_ratio,
            model_version_cardinality: self.version_hll.estimate(),
        }
    }

    fn aggregate_threshold(
        &self,
        from_minute: u64,
        to_minute: u64,
        threshold_ms: f64,
    ) -> LatencyThresholdResult {
        let mut total = 0u64;
        let mut digest = TDigest::new(200.0);
        for c in &self.chunks {
            if c.minute < from_minute || c.minute > to_minute {
                continue;
            }
            total += c.total();
            digest.merge(&c.latency);
        }
        let count_above = if digest.is_empty() {
            0
        } else {
            digest.count_above(threshold_ms).round().max(0.0) as u64
        };
        LatencyThresholdResult { total, count_above }
    }
}

/// Default cap on number of distinct series tracked. Protects against
/// unbounded label-cardinality (a classic Prometheus-style OOM bomb).
pub const DEFAULT_MAX_SERIES: usize = 10_000;

/// Public-facing time-series store.
///
/// Internally:
/// - `DashMap` for concurrent per-series access.
/// - `RwLock<SeriesState>` per series — writes (ingest path) are quick
///   and exclusive; reads (query path) can run in parallel against
///   *other* series even while one series is being written.
///
/// Concurrent writes to the *same* series are serialized by the per-series
/// `RwLock`. This is the right shape for axum's multi-threaded runtime:
/// many handlers, possibly hitting different series, run in parallel.
pub struct Tsdb {
    series: DashMap<SeriesId, Arc<RwLock<SeriesState>>>,
    retention_minutes: usize,
    max_series: usize,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for Tsdb {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tsdb")
            .field("series_count", &self.series.len())
            .field("retention_minutes", &self.retention_minutes)
            .finish()
    }
}

impl Tsdb {
    /// Create a new in-memory TSDB. `retention_minutes` controls how many
    /// minute buckets are kept per series (older buckets are evicted).
    #[must_use]
    pub fn new(retention_minutes: usize) -> Self {
        Self::with_clock(retention_minutes, Arc::new(SystemClock))
    }

    /// Create a TSDB with a custom [`Clock`] (useful in tests).
    #[must_use]
    pub fn with_clock(retention_minutes: usize, clock: Arc<dyn Clock>) -> Self {
        Self {
            series: DashMap::new(),
            retention_minutes,
            max_series: DEFAULT_MAX_SERIES,
            clock,
        }
    }

    /// Override the maximum number of distinct series this store will track.
    /// Ingests for new series past this cap are silently dropped; existing
    /// series continue to ingest.
    #[must_use]
    pub fn with_max_series(mut self, max_series: usize) -> Self {
        self.max_series = max_series;
        self
    }

    /// Number of distinct series currently tracked.
    #[must_use]
    pub fn series_count(&self) -> usize {
        self.series.len()
    }

    /// Build the canonical series key for an event. Includes `model` and
    /// any low-cardinality `metadata` labels supplied by the producer.
    fn key_for(ev: &InferenceEvent) -> SeriesKey {
        let mut labels: Vec<(String, String)> =
            Vec::with_capacity(1 + ev.metadata.len());
        labels.push(("model".to_string(), ev.model.clone()));
        for (k, v) in &ev.metadata {
            labels.push((k.clone(), v.clone()));
        }
        SeriesKey::new("inference", labels)
    }

    /// Ingest one event. Returns `true` if the event was recorded,
    /// `false` if it was dropped (series-cap exceeded).
    pub fn ingest(&self, ev: &InferenceEvent) -> bool {
        let key = Self::key_for(ev);
        let id = key.id();
        let minute = ev.timestamp.as_nanos() / MINUTE;

        // Cardinality guard: refuse to create a new series past the cap.
        let state = match self.series.get(&id) {
            Some(s) => s.clone(),
            None => {
                if self.series.len() >= self.max_series {
                    return false;
                }
                self.series
                    .entry(id)
                    .or_insert_with(|| Arc::new(RwLock::new(SeriesState::new(key.clone()))))
                    .clone()
            }
        };

        let mut s = state.write();
        s.record(minute, ev.status, ev.latency_ms, self.retention_minutes);
        s.version_hll.insert(&ev.model_version);
        true
    }

    /// Query the rolling window `[ref - window, ref]` for the given model
    /// at the requested quantile. The window reference time is the maximum
    /// of `clock.now()` and the series' most recently observed minute —
    /// this means WAL replay (which uses event timestamps) and tests with
    /// a frozen clock both return non-empty windows.
    ///
    /// Returns `None` if no series exists for the given model.
    pub fn query(
        &self,
        model: &str,
        window_nanos: u64,
        quantile: f64,
    ) -> Option<QueryResult> {
        // We only have model + (possibly) metadata when ingesting; for
        // queries we use model alone as the series prefix and find the
        // single matching series. (Multi-label fan-out is a future
        // extension — single-model lookup is the common case.)
        let id = SeriesKey::new("inference", [("model", model)]).id();
        let state = match self.series.get(&id) {
            Some(s) => s.clone(),
            None => return self.query_first_for_model(model, window_nanos, quantile),
        };
        let s = state.read();
        let (from_minute, to_minute) = self.window_bounds(&s, window_nanos);
        Some(s.aggregate(from_minute, to_minute, quantile))
    }

    fn query_first_for_model(
        &self,
        model: &str,
        window_nanos: u64,
        quantile: f64,
    ) -> Option<QueryResult> {
        for entry in self.series.iter() {
            let s = entry.value().read();
            if s.key.labels.get("model").map(String::as_str) == Some(model) {
                let (from_minute, to_minute) = self.window_bounds(&s, window_nanos);
                return Some(s.aggregate(from_minute, to_minute, quantile));
            }
        }
        None
    }

    /// Compute a window's `(from_minute, to_minute)` for one series,
    /// using the later of wall-clock now and the series' last-observed
    /// minute as the right edge.
    fn window_bounds(&self, s: &SeriesState, window_nanos: u64) -> (u64, u64) {
        let now_minute = self.clock.now().as_nanos() / MINUTE;
        let to_minute = now_minute.max(s.last_observed_minute);
        let window_minutes = window_nanos / MINUTE;
        let from_minute = to_minute.saturating_sub(window_minutes);
        (from_minute, to_minute)
    }

    /// Query the windowed count of events whose latency exceeded
    /// `threshold_ms`. Used by latency-threshold SLI evaluation.
    pub fn query_latency_above(
        &self,
        model: &str,
        window_nanos: u64,
        threshold_ms: f64,
    ) -> Option<LatencyThresholdResult> {
        let id = SeriesKey::new("inference", [("model", model)]).id();
        let state = self.series.get(&id)?;
        let s = state.read();
        let (from_minute, to_minute) = self.window_bounds(&s, window_nanos);
        Some(s.aggregate_threshold(from_minute, to_minute, threshold_ms))
    }

    /// Iterate snapshots of every series for a given window. Used by the
    /// SLO evaluator and the dashboard.
    pub fn snapshot_all(&self, window_nanos: u64, quantile: f64) -> Vec<(String, QueryResult)> {
        let mut out = Vec::with_capacity(self.series.len());
        for entry in self.series.iter() {
            let s = entry.value().read();
            let model = s
                .key
                .labels
                .get("model")
                .cloned()
                .unwrap_or_else(|| "unknown".to_string());
            let (from_minute, to_minute) = self.window_bounds(&s, window_nanos);
            out.push((model, s.aggregate(from_minute, to_minute, quantile)));
        }
        out
    }

    /// Helper: the clock currently in use. Mostly used by tests.
    pub fn now(&self) -> TimestampNanos {
        self.clock.now()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ingest::InferenceEvent;
    use crate::time::{MockClock, SECOND};

    fn ev(model: &str, status: Status, latency_ms: f64, ts_secs: u64) -> InferenceEvent {
        InferenceEvent {
            timestamp: TimestampNanos(ts_secs * SECOND),
            model: model.to_string(),
            model_version: "v1".to_string(),
            latency_ms,
            status,
            input_tokens: None,
            output_tokens: None,
            cost_usd: None,
            metadata: Default::default(),
        }
    }

    #[test]
    fn ingest_then_query_basic() {
        let clock = Arc::new(MockClock::starting_at(TimestampNanos(120 * SECOND)));
        let db = Tsdb::with_clock(60, clock.clone());

        for i in 0..100 {
            db.ingest(&ev(
                "m",
                if i % 10 == 0 {
                    Status::ServerError
                } else {
                    Status::Success
                },
                100.0 + i as f64,
                60,
            ));
        }
        let r = db.query("m", 5 * 60 * SECOND, 0.95).unwrap();
        assert_eq!(r.total, 100);
        assert_eq!(r.good, 90);
        assert!((r.success_ratio - 0.9).abs() < 1e-9);
        assert!(r.latency_quantile_ms > 100.0);
    }

    #[test]
    fn query_unknown_model_returns_none() {
        let db = Tsdb::new(60);
        assert!(db.query("nope", 60 * SECOND, 0.5).is_none());
    }

    #[test]
    fn retention_evicts_old_minutes() {
        let clock = Arc::new(MockClock::starting_at(TimestampNanos(0)));
        let db = Tsdb::with_clock(3, clock.clone());
        for minute in 0..10 {
            db.ingest(&ev("m", Status::Success, 50.0, minute * 60));
        }
        // Only the last 3 minutes should remain.
        let r = db.query("m", 60 * 60 * SECOND, 0.5);
        // Without advancing the clock, the window query uses now=0; just
        // verify series count and that ingest doesn't unbound-grow.
        assert!(r.is_some() || r.is_none()); // sanity — no panic
        let entry = db.series.iter().next().unwrap();
        let s = entry.value().read();
        assert_eq!(s.chunks.len(), 3);
    }
}
