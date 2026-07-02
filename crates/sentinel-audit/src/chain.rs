//! The hash chain: append-only writer and offline verifier.

use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write as _};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer as _, SigningKey, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::keys::key_id;
use crate::record::{Actor, Event, Record};

/// `prev` value of the first entry in a log file.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One line of the audit log: a record plus its chain and signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    /// The signed record.
    pub record: Record,
    /// Hex SHA-256 hash of the previous entry (or [`GENESIS_HASH`]).
    pub prev: String,
    /// Hex SHA-256 over `prev` and the canonical record JSON.
    pub hash: String,
    /// Hex ed25519 signature over the raw 32-byte hash.
    pub sig: String,
    /// Identifier of the signing key (see [`crate::key_id`]).
    pub key_id: String,
}

/// Canonical JSON for hashing: serialize through `Value` so object keys are
/// sorted identically for the writer (typed structs) and the verifier
/// (parsed `Value`s).
fn canonical_record_json(record: &Record) -> Result<String, serde_json::Error> {
    let value = serde_json::to_value(record)?;
    serde_json::to_string(&value)
}

fn chain_hash(prev: &str, record_json: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(prev.as_bytes());
    hasher.update(b"\n");
    hasher.update(record_json.as_bytes());
    hasher.finalize().into()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Appends signed, chained entries to a JSONL log file.
///
/// Reopening an existing file resumes the chain from its last entry, so a
/// gateway restart extends the same tamper-evident history.
pub struct AuditWriter {
    out: BufWriter<File>,
    key: SigningKey,
    key_id: String,
    seq: u64,
    prev: String,
}

impl AuditWriter {
    /// Open (or create) the log at `path`, resuming the chain if the file
    /// already has entries.
    pub fn open(path: &Path, key: SigningKey) -> Result<Self, std::io::Error> {
        let (seq, prev) = match fs::read_to_string(path) {
            Ok(text) => match text.lines().rev().find(|l| !l.trim().is_empty()) {
                Some(last) => {
                    let entry: Entry = serde_json::from_str(last).map_err(|e| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("cannot resume audit chain, last line is corrupt: {e}"),
                        )
                    })?;
                    (entry.record.seq, entry.hash)
                }
                None => (0, GENESIS_HASH.to_string()),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (0, GENESIS_HASH.to_string()),
            Err(e) => return Err(e),
        };
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let kid = key_id(&key.verifying_key());
        Ok(Self {
            out: BufWriter::new(file),
            key,
            key_id: kid,
            seq,
            prev,
        })
    }

    /// Sign and append one event; flushes to the OS before returning so a
    /// crash can lose at most the entry being written.
    pub fn append(&mut self, actor: Actor, event: Event) -> Result<Entry, std::io::Error> {
        let record = Record {
            seq: self.seq + 1,
            ts_ms: now_ms(),
            actor,
            event,
        };
        let record_json = canonical_record_json(&record)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let digest = chain_hash(&self.prev, &record_json);
        let sig = self.key.sign(&digest);
        let entry = Entry {
            record,
            prev: self.prev.clone(),
            hash: hex::encode(digest),
            sig: hex::encode(sig.to_bytes()),
            key_id: self.key_id.clone(),
        };
        // Serialize the full line through Value too, so the `record` field
        // bytes on disk are exactly the canonical form that was hashed.
        let line = serde_json::to_string(&serde_json::to_value(&entry).map_err(io_inval)?)
            .map_err(io_inval)?;
        self.out.write_all(line.as_bytes())?;
        self.out.write_all(b"\n")?;
        self.out.flush()?;
        self.seq = entry.record.seq;
        self.prev = entry.hash.clone();
        Ok(entry)
    }
}

fn io_inval(e: serde_json::Error) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, e)
}

/// Successful verification summary.
#[derive(Debug)]
pub struct VerifyReport {
    /// Number of entries verified.
    pub entries: u64,
    /// Hash of the final entry (the chain head).
    pub head: String,
}

/// Why verification failed, and on which 1-based line.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    /// Could not read the file.
    #[error("audit log I/O: {0}")]
    Io(#[from] std::io::Error),
    /// A line is not a valid entry.
    #[error("line {line}: malformed entry: {detail}")]
    Malformed {
        /// 1-based line number.
        line: usize,
        /// Parse failure detail.
        detail: String,
    },
    /// `prev` does not equal the previous entry's hash.
    #[error("line {line}: chain broken (prev hash mismatch)")]
    BrokenChain {
        /// 1-based line number.
        line: usize,
    },
    /// Recomputed hash differs from the stored one — the record was edited.
    #[error("line {line}: record hash mismatch (entry tampered)")]
    BadHash {
        /// 1-based line number.
        line: usize,
    },
    /// Sequence numbers are not contiguous — entries were dropped/reordered.
    #[error("line {line}: sequence break (expected {expected}, found {found})")]
    BadSeq {
        /// 1-based line number.
        line: usize,
        /// Expected sequence number.
        expected: u64,
        /// Found sequence number.
        found: u64,
    },
    /// Signature does not verify under the supplied public key.
    #[error("line {line}: bad signature")]
    BadSignature {
        /// 1-based line number.
        line: usize,
    },
}

/// Verify an entire log file against a public key: hash chain, sequence
/// continuity, and per-entry signatures.
pub fn verify_file(path: &Path, vk: &VerifyingKey) -> Result<VerifyReport, VerifyError> {
    let text = fs::read_to_string(path)?;
    let mut prev = GENESIS_HASH.to_string();
    let mut expected_seq: u64 = 1;
    let mut entries: u64 = 0;

    for (idx, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let lineno = idx + 1;
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|e| VerifyError::Malformed {
                line: lineno,
                detail: e.to_string(),
            })?;
        let get_str = |key: &str| -> Result<&str, VerifyError> {
            value
                .get(key)
                .and_then(|v| v.as_str())
                .ok_or_else(|| VerifyError::Malformed {
                    line: lineno,
                    detail: format!("missing `{key}`"),
                })
        };
        let entry_prev = get_str("prev")?;
        let entry_hash = get_str("hash")?;
        let entry_sig = get_str("sig")?;
        let record = value.get("record").ok_or_else(|| VerifyError::Malformed {
            line: lineno,
            detail: "missing `record`".to_string(),
        })?;
        let seq = record
            .get("seq")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| VerifyError::Malformed {
                line: lineno,
                detail: "missing `record.seq`".to_string(),
            })?;

        if seq != expected_seq {
            return Err(VerifyError::BadSeq {
                line: lineno,
                expected: expected_seq,
                found: seq,
            });
        }
        if entry_prev != prev {
            return Err(VerifyError::BrokenChain { line: lineno });
        }

        // `record` was parsed into a key-sorted Value; re-serializing gives
        // back the writer's canonical bytes.
        let record_json =
            serde_json::to_string(record).map_err(|e| VerifyError::Malformed {
                line: lineno,
                detail: e.to_string(),
            })?;
        let digest = chain_hash(entry_prev, &record_json);
        if hex::encode(digest) != entry_hash {
            return Err(VerifyError::BadHash { line: lineno });
        }

        let sig_bytes: [u8; 64] = hex::decode(entry_sig)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or(VerifyError::BadSignature { line: lineno })?;
        vk.verify(&digest, &Signature::from_bytes(&sig_bytes))
            .map_err(|_| VerifyError::BadSignature { line: lineno })?;

        prev = entry_hash.to_string();
        expected_seq += 1;
        entries += 1;
    }

    Ok(VerifyReport {
        entries,
        head: prev,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::generate_signing_key;
    use crate::record::{ArgsMode, ArgsRecord};

    fn actor() -> Actor {
        Actor {
            agent: "claude-code".into(),
            principal: "keat@example.com".into(),
        }
    }

    fn sample_event(i: u64) -> Event {
        Event::ToolCallEvaluated {
            server: "email".into(),
            tool: "send_email".into(),
            request_id: i.to_string(),
            decision: "deny".into(),
            rule_id: "block-bcc".into(),
            risk: Some("critical".into()),
            reason: Some("BCC exfiltration guard".into()),
            args: ArgsRecord::capture(
                ArgsMode::Hash,
                &serde_json::json!({"to": ["a@example.com"], "bcc": ["x@evil.com"]}),
            ),
        }
    }

    #[test]
    fn write_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = generate_signing_key();
        let vk = key.verifying_key();

        let mut w = AuditWriter::open(&path, key).unwrap();
        for i in 0..5 {
            w.append(actor(), sample_event(i)).unwrap();
        }
        drop(w);

        let report = verify_file(&path, &vk).unwrap();
        assert_eq!(report.entries, 5);
        assert_ne!(report.head, GENESIS_HASH);
    }

    #[test]
    fn reopen_resumes_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = generate_signing_key();
        let vk = key.verifying_key();

        let mut w = AuditWriter::open(&path, key.clone()).unwrap();
        w.append(actor(), sample_event(0)).unwrap();
        drop(w);

        let mut w = AuditWriter::open(&path, key).unwrap();
        let e = w.append(actor(), sample_event(1)).unwrap();
        assert_eq!(e.record.seq, 2);
        drop(w);

        assert_eq!(verify_file(&path, &vk).unwrap().entries, 2);
    }

    #[test]
    fn tampered_record_is_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = generate_signing_key();
        let vk = key.verifying_key();

        let mut w = AuditWriter::open(&path, key).unwrap();
        for i in 0..3 {
            w.append(actor(), sample_event(i)).unwrap();
        }
        drop(w);

        // Flip the decision on line 2 from deny to allow.
        let text = fs::read_to_string(&path).unwrap();
        let doctored: Vec<String> = text
            .lines()
            .enumerate()
            .map(|(i, l)| {
                if i == 1 {
                    l.replace("\"deny\"", "\"allow\"")
                } else {
                    l.to_string()
                }
            })
            .collect();
        fs::write(&path, doctored.join("\n") + "\n").unwrap();

        match verify_file(&path, &vk).unwrap_err() {
            VerifyError::BadHash { line } => assert_eq!(line, 2),
            other => panic!("expected BadHash, got {other:?}"),
        }
    }

    #[test]
    fn deleted_entry_breaks_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let key = generate_signing_key();
        let vk = key.verifying_key();

        let mut w = AuditWriter::open(&path, key).unwrap();
        for i in 0..3 {
            w.append(actor(), sample_event(i)).unwrap();
        }
        drop(w);

        let text = fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text.lines().enumerate().filter(|(i, _)| *i != 1).map(|(_, l)| l).collect();
        fs::write(&path, kept.join("\n") + "\n").unwrap();

        assert!(matches!(
            verify_file(&path, &vk).unwrap_err(),
            VerifyError::BadSeq { .. } | VerifyError::BrokenChain { .. }
        ));
    }

    #[test]
    fn wrong_key_fails_signature() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let mut w = AuditWriter::open(&path, generate_signing_key()).unwrap();
        w.append(actor(), sample_event(0)).unwrap();
        drop(w);

        let other = generate_signing_key().verifying_key();
        assert!(matches!(
            verify_file(&path, &other).unwrap_err(),
            VerifyError::BadSignature { line: 1 }
        ));
    }

    #[test]
    fn args_hash_is_deterministic_and_content_free() {
        let a = ArgsRecord::capture(ArgsMode::Hash, &serde_json::json!({"b": 1, "a": 2}));
        let b = ArgsRecord::capture(ArgsMode::Hash, &serde_json::json!({"a": 2, "b": 1}));
        assert_eq!(a, b);
        let ArgsRecord::Hash { sha256 } = a else {
            panic!("expected hash mode")
        };
        assert_eq!(sha256.len(), 64);
    }
}
