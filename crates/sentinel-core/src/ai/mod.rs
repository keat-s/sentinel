//! AI hooks: pluggable LLM-powered incident summarization with a
//! deterministic no-op fallback.
//!
//! The point of this module is to demonstrate **graceful AI integration**:
//! the engine is fully functional with zero AI dependencies, and adding
//! an `SENTINEL_LLM_API_KEY` to the environment is the only change
//! required to upgrade to real LLM summaries. This is the pattern you
//! want in production: AI is a value-add, never a hard dependency.

pub mod summarizer;

pub use summarizer::{IncidentContext, NoopSummarizer, OpenAiSummarizer, Summarizer};
