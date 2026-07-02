//! # sentinel-audit
//!
//! Tamper-evident audit log for AI agent actions.
//!
//! Every entry is a single JSONL line containing a `record` (what happened),
//! the hex SHA-256 `hash` of that record chained to the previous entry's
//! hash (`prev`), and an ed25519 `sig` over the hash. The chain makes the
//! log **append-only in effect**: editing, reordering, or deleting any entry
//! breaks verification of every entry after it, and the signature ties the
//! whole chain to a private key that never has to leave the machine running
//! the gateway.
//!
//! Canonical form: the record is serialized through [`serde_json::Value`]
//! (BTreeMap-backed, so object keys are sorted) before hashing, which makes
//! writer and verifier agree on bytes without a custom canonicalization
//! scheme.
//!
//! Data minimization is first-class: tool-call arguments are recorded as a
//! SHA-256 digest by default ([`ArgsRecord::Hash`]), with `full` and `omit`
//! modes opt-in.

mod chain;
mod keys;
mod record;

pub use chain::{verify_file, AuditWriter, Entry, VerifyError, VerifyReport, GENESIS_HASH};
pub use keys::{
    generate_signing_key, key_id, load_secret_key, load_verifying_key, save_keypair, KeyError,
};
pub use record::{Actor, ArgsMode, ArgsRecord, Event, Record};
