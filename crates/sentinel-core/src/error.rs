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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages_carry_context() {
        let e = SentinelError::WalCorruption {
            offset: 128,
            detail: "bad crc".into(),
        };
        assert_eq!(e.to_string(), "wal corruption at offset 128: bad crc");

        let e = SentinelError::UnknownMetric("latency_p99".into());
        assert_eq!(e.to_string(), "slo refers to unknown metric: latency_p99");

        let e = SentinelError::Llm("http 500".into());
        assert_eq!(e.to_string(), "llm request failed: http 500");

        let e = SentinelError::Invariant("chunks sorted");
        assert_eq!(e.to_string(), "invariant violated: chunks sorted");
    }

    #[test]
    fn io_errors_convert_and_preserve_message() {
        let io = io::Error::new(io::ErrorKind::NotFound, "missing wal");
        let e = SentinelError::from(io);
        assert!(matches!(e, SentinelError::Io(_)));
        assert!(e.to_string().contains("missing wal"));
    }

    #[test]
    fn serde_errors_convert_to_serde_variant() {
        let json_err = serde_json::from_str::<u64>("not json").unwrap_err();
        let e = SentinelError::from(json_err);
        assert!(matches!(e, SentinelError::Serde(_)));

        let yaml_err = serde_yaml::from_str::<u64>("[unclosed").unwrap_err();
        let e = SentinelError::from(yaml_err);
        assert!(matches!(e, SentinelError::Serde(_)));
    }
}
