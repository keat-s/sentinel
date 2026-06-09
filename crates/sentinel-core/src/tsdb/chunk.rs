//! Per-minute aggregation bucket for one series.
//!
//! Real production TSDBs (Prometheus, VictoriaMetrics, InfluxDB IOx) use
//! richer chunk encodings — Gorilla XOR for floats, delta-of-delta for
//! timestamps, RLE for repeats. Sentinel intentionally uses a much
//! simpler scheme — counters + a t-digest — because that's *exactly*
//! the data shape the SLO and anomaly engines need to consume.
//!
//! Trade-off: we can't reconstruct individual samples (no raw history).
//! For an observability layer focused on SLI math, that's a feature: we
//! get bounded memory regardless of traffic volume.

use serde::{Deserialize, Serialize};

use crate::ingest::Status;
use crate::sketches::TDigest;

/// One minute of aggregated counts + latency distribution for one series.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Chunk {
    /// Wall-clock minute since the epoch (i.e. `seconds_since_epoch / 60`).
    pub minute: u64,

    /// Count of `Status::Success`.
    pub success: u64,
    /// Count of `Status::ClientError`.
    pub client_error: u64,
    /// Count of `Status::ServerError`.
    pub server_error: u64,
    /// Count of `Status::Timeout`.
    pub timeout: u64,

    /// Latency distribution.
    pub latency: TDigest,
}

impl Chunk {
    /// Construct an empty chunk for the given minute.
    #[must_use]
    pub fn new(minute: u64) -> Self {
        Self {
            minute,
            success: 0,
            client_error: 0,
            server_error: 0,
            timeout: 0,
            latency: TDigest::new(100.0),
        }
    }

    /// Record one event into this chunk.
    pub fn record(&mut self, status: Status, latency_ms: f64) {
        match status {
            Status::Success => self.success += 1,
            Status::ClientError => self.client_error += 1,
            Status::ServerError => self.server_error += 1,
            Status::Timeout => self.timeout += 1,
        }
        self.latency.insert(latency_ms);
    }

    /// Total events recorded.
    #[must_use]
    pub fn total(&self) -> u64 {
        self.success + self.client_error + self.server_error + self.timeout
    }

    /// "Good" count under the standard ratio-SLI definition (Success only).
    #[must_use]
    pub fn good(&self) -> u64 {
        self.success
    }

    /// Server-side failure count (`ServerError | Timeout`).
    #[must_use]
    pub fn server_failures(&self) -> u64 {
        self.server_error + self.timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_chunk_is_empty() {
        let c = Chunk::new(42);
        assert_eq!(c.minute, 42);
        assert_eq!(c.total(), 0);
        assert_eq!(c.good(), 0);
        assert_eq!(c.server_failures(), 0);
        assert!(c.latency.is_empty());
    }

    #[test]
    fn record_routes_each_status_to_its_counter() {
        let mut c = Chunk::new(0);
        c.record(Status::Success, 10.0);
        c.record(Status::Success, 20.0);
        c.record(Status::ClientError, 30.0);
        c.record(Status::ServerError, 40.0);
        c.record(Status::Timeout, 50.0);

        assert_eq!(c.success, 2);
        assert_eq!(c.client_error, 1);
        assert_eq!(c.server_error, 1);
        assert_eq!(c.timeout, 1);
        assert_eq!(c.total(), 5);
        // Only Success is "good"; ClientError is bad but not a server failure.
        assert_eq!(c.good(), 2);
        assert_eq!(c.server_failures(), 2);
    }

    #[test]
    fn record_feeds_latency_digest() {
        let mut c = Chunk::new(0);
        for i in 1..=100 {
            c.record(Status::Success, f64::from(i));
        }
        let median = c.latency.quantile(0.5);
        assert!(
            (median - 50.0).abs() < 5.0,
            "expected median ~50, got {median}"
        );
    }
}
