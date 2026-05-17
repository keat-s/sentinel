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
