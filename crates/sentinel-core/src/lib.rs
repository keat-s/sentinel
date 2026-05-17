//! Sentinel — embeddable observability engine for ML inference services.
//!
//! This crate exposes the engine pieces as a reusable library:
//!
//! - [`tsdb`]: a single-node, time-partitioned time-series store with
//!   t-digest sketches and a write-ahead log.
//! - [`slo`]: multi-window multi-burn-rate alert evaluation following
//!   the Google SRE Workbook formulas.
//! - [`anomaly`]: streaming statistical detectors (z-score, threshold).
//! - [`ai`]: pluggable incident summarizer with a no-op fallback so the
//!   engine is fully usable without any external model dependency.
//!
//! The companion [`sentinel-cli`](../sentinel_cli) binary wires these into
//! an HTTP service, a synthetic-traffic simulator, and a terminal dashboard.

#![cfg_attr(not(test), warn(clippy::unwrap_used))]

pub mod ai;
pub mod anomaly;
pub mod error;
pub mod ingest;
pub mod sketches;
pub mod slo;
pub mod time;
pub mod tsdb;

pub use error::{Result, SentinelError};
pub use ingest::{InferenceEvent, Status};
pub use tsdb::{SeriesId, Tsdb};
