//! Ingestion-side types: the [`InferenceEvent`] is the unit consumed by
//! the engine.

pub mod event;

pub use event::{InferenceEvent, Status};
