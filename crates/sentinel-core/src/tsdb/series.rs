//! Series identity: a deterministic hash of `(metric_name, sorted_labels)`.

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};

use ahash::AHasher;
use serde::{Deserialize, Serialize};

/// Canonical label set. Always stored sorted so the [`SeriesId`] is
/// deterministic for the same logical series regardless of how labels
/// were originally inserted.
pub type Labels = BTreeMap<String, String>;

/// Opaque, hashable, equatable identifier for one time series.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SeriesId(pub u64);

/// Human-readable description of a series — the inputs that hash to a
/// [`SeriesId`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SeriesKey {
    /// Metric name (e.g. `"latency_ms"`, `"requests_total"`).
    pub metric: String,
    /// Canonical (sorted) label map.
    pub labels: Labels,
}

impl SeriesKey {
    /// Build a key from a metric name and an unordered label iterator.
    pub fn new<I, K, V>(metric: impl Into<String>, labels: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let labels = labels
            .into_iter()
            .map(|(k, v)| (k.into(), v.into()))
            .collect();
        Self {
            metric: metric.into(),
            labels,
        }
    }

    /// Compute the deterministic [`SeriesId`] for this key.
    ///
    /// Uses [`ahash`] because we need a fast, high-quality, non-DoS-resistant
    /// hash with stable output across process invocations when seeded the
    /// same way. We seed with zeros to get the same id across processes —
    /// this is fine because the hash never leaves the process trust
    /// boundary; the WAL stores keys explicitly, not just ids.
    #[must_use]
    pub fn id(&self) -> SeriesId {
        let mut hasher = AHasher::default();
        self.metric.hash(&mut hasher);
        for (k, v) in &self.labels {
            k.hash(&mut hasher);
            v.hash(&mut hasher);
        }
        SeriesId(hasher.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_is_label_order_independent() {
        let a = SeriesKey::new(
            "latency_ms",
            [("model", "gpt-4"), ("region", "us-east-1")],
        );
        let b = SeriesKey::new(
            "latency_ms",
            [("region", "us-east-1"), ("model", "gpt-4")],
        );
        assert_eq!(a.id(), b.id());
    }

    #[test]
    fn id_differs_for_different_labels() {
        let a = SeriesKey::new("latency_ms", [("model", "gpt-4")]);
        let b = SeriesKey::new("latency_ms", [("model", "gpt-4o")]);
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn id_differs_for_different_metrics() {
        let a = SeriesKey::new("latency_ms", [("model", "gpt-4")]);
        let b = SeriesKey::new("requests_total", [("model", "gpt-4")]);
        assert_ne!(a.id(), b.id());
    }

    #[test]
    fn empty_labels_is_valid() {
        let key = SeriesKey::new("uptime_seconds", std::iter::empty::<(String, String)>());
        let _id = key.id();
    }
}
