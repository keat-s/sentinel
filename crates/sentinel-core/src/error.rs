//! Crate-wide error type.

use std::io;

use thiserror::Error;

/// Convenience [`std::result::Result`] alias for `sentinel-core`.
pub type Result<T, E = SentinelError> = std::result::Result<T, E>;

/// All recoverable failure modes surfaced by `sentinel-core`.
#[derive(Debug, Error)]
pub enum SentinelError {
    /// I/O failure while interacting with the WAL or filesystem.
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// WAL record failed checksum validation.
    #[error("wal corruption at offset {offset}: {detail}")]
    WalCorruption {
        /// Byte offset where corruption was detected.
        offset: u64,
        /// Human-readable description of the problem.
        detail: String,
    },

    /// Serialization / deserialization error.
    #[error("serde error: {0}")]
    Serde(String),

    /// A requested series did not exist in the TSDB.
    #[error("series not found: id={0:?}")]
    UnknownSeries(crate::tsdb::SeriesId),

    /// SLO configuration referred to a non-existent metric.
    #[error("slo refers to unknown metric: {0}")]
    UnknownMetric(String),

    /// Outbound HTTP call to a configured LLM provider failed.
    #[error("llm request failed: {0}")]
    Llm(String),

    /// Catch-all for invariants that must hold but failed at runtime.
    #[error("invariant violated: {0}")]
    Invariant(&'static str),
}

impl From<serde_json::Error> for SentinelError {
    fn from(e: serde_json::Error) -> Self {
        SentinelError::Serde(e.to_string())
    }
}

impl From<serde_yaml::Error> for SentinelError {
    fn from(e: serde_yaml::Error) -> Self {
        SentinelError::Serde(e.to_string())
    }
}

impl From<reqwest::Error> for SentinelError {
    fn from(e: reqwest::Error) -> Self {
        SentinelError::Llm(e.to_string())
    }
}
