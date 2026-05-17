//! `InferenceEvent` — the atomic record Sentinel ingests.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::time::TimestampNanos;

/// Outcome classification for an inference call.
///
/// We deliberately keep this small and closed: the SLI math treats
/// `Success` as "good" and everything else as "bad". Finer-grained
/// categorization can be added via labels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// The call completed and returned a usable result.
    Success,
    /// The caller sent an invalid request (4xx-equivalent).
    ClientError,
    /// The service failed to produce a result (5xx-equivalent).
    ServerError,
    /// The call was aborted because it exceeded its deadline.
    Timeout,
}

impl Status {
    /// True iff this status counts as "good" for ratio-based SLIs.
    #[must_use]
    pub const fn is_good(self) -> bool {
        matches!(self, Status::Success)
    }

    /// True iff the failure should be attributed to the service (used to
    /// differentiate availability from validation-error noise).
    #[must_use]
    pub const fn is_server_failure(self) -> bool {
        matches!(self, Status::ServerError | Status::Timeout)
    }
}

/// One inference call observed by Sentinel.
///
/// `BTreeMap` is used for `metadata` so label sets canonicalize the same
/// way regardless of insertion order — that's how we get a stable
/// `SeriesId` from a label set.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceEvent {
    /// Wall-clock timestamp at which the inference call completed.
    pub timestamp: TimestampNanos,

    /// Logical model name (e.g. `"text-embedding-3"`).
    pub model: String,

    /// Model version string (drift signal — sudden cardinality change in
    /// this field is a strong indicator that a rollout is underway).
    pub model_version: String,

    /// End-to-end call latency in milliseconds.
    pub latency_ms: f64,

    /// Outcome classification.
    pub status: Status,

    /// Optional token counts for cost & throughput SLIs.
    #[serde(default)]
    pub input_tokens: Option<u32>,
    /// Optional token counts for cost & throughput SLIs.
    #[serde(default)]
    pub output_tokens: Option<u32>,

    /// Optional cost in USD.
    #[serde(default)]
    pub cost_usd: Option<f64>,

    /// Free-form low-cardinality labels (region, tenant, etc.). Keep
    /// cardinality bounded — these participate in the series key.
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
}

impl InferenceEvent {
    /// Construct a minimal valid event. Useful in tests and traffic
    /// generators.
    #[must_use]
    pub fn new(model: impl Into<String>, latency_ms: f64, status: Status) -> Self {
        Self {
            timestamp: TimestampNanos::now(),
            model: model.into(),
            model_version: "unknown".to_string(),
            latency_ms,
            status,
            input_tokens: None,
            output_tokens: None,
            cost_usd: None,
            metadata: BTreeMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_roundtrip_serde() {
        let json = serde_json::to_string(&Status::ServerError).unwrap();
        assert_eq!(json, "\"server_error\"");
        let back: Status = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Status::ServerError);
    }

    #[test]
    fn is_good_only_for_success() {
        assert!(Status::Success.is_good());
        assert!(!Status::ClientError.is_good());
        assert!(!Status::ServerError.is_good());
        assert!(!Status::Timeout.is_good());
    }

    #[test]
    fn server_failures_classify_correctly() {
        assert!(Status::ServerError.is_server_failure());
        assert!(Status::Timeout.is_server_failure());
        assert!(!Status::ClientError.is_server_failure());
        assert!(!Status::Success.is_server_failure());
    }
}
