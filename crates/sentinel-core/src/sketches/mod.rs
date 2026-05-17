//! Streaming sketches with bounded memory: t-digest, EWMA, HyperLogLog.
//!
//! These are the workhorses of a time-series engine. They let us answer
//! "what's the P95 over the last hour?" or "how many distinct model
//! versions did we see today?" in constant space, without retaining
//! every observation.

pub mod ewma;
pub mod hll;
pub mod tdigest;

pub use ewma::{Ewma, EwmaVariance};
pub use hll::HyperLogLog;
pub use tdigest::TDigest;
