//! Write-ahead log: append-only, length-prefixed, CRC-protected.
//!
//! File layout:
//!
//! - Fixed 8-byte header at offset 0: `b"SNTL"` + u32 little-endian
//!   format version.
//! - Then repeated frames: `u32 len | u32 crc | payload`, all LE.
//! - `crc` covers `(len_bytes || payload)` so corruption of either field
//!   is detected. (Payload-only CRCs leave the length field unprotected,
//!   which is the classic pre-allocation DoS vector.)
//! - Frame `len` is bounded by [`MAX_FRAME_BYTES`] before any allocation.
//! - Truncated last-write (process killed mid-flush) is reported as a
//!   clean end-of-log, not corruption.

use std::fs::{File, OpenOptions};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::error::{Result, SentinelError};
use crate::ingest::InferenceEvent;

/// On-disk file format magic.
pub const WAL_MAGIC: &[u8; 4] = b"SNTL";

/// Current on-disk format version. Bumped if framing changes.
pub const WAL_VERSION: u32 = 1;

/// Maximum allowed framed payload size in bytes.
///
/// Caps the `vec![0; len as usize]` allocation in [`WalReader::next`] so
/// a corrupt-or-malicious `len` field can't cause an unbounded allocation
/// before CRC validation runs.
pub const MAX_FRAME_BYTES: u32 = 1 << 20; // 1 MiB

/// Append-only WAL writer.
pub struct Wal {
    writer: BufWriter<File>,
    bytes_written: u64,
}

impl Wal {
    /// Open (or create) a WAL file at `path`. Writes the file header if
    /// the file is new; otherwise validates the existing header.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path.as_ref())?;
        let existing_len = file.metadata()?.len();
        if existing_len == 0 {
            // New file — write the header.
            // (`append` semantics route writes to EOF regardless of cursor.)
            file.write_all(WAL_MAGIC)?;
            file.write_all(&WAL_VERSION.to_le_bytes())?;
            let bytes_written = WAL_MAGIC.len() as u64 + 4;
            file.sync_data()?;
            return Ok(Self {
                writer: BufWriter::new(file),
                bytes_written,
            });
        }
        // Existing file — validate header.
        let mut hdr = [0u8; 8];
        file.read_exact(&mut hdr).map_err(|e| {
            SentinelError::WalCorruption {
                offset: 0,
                detail: format!("short header: {e}"),
            }
        })?;
        if &hdr[0..4] != WAL_MAGIC {
            return Err(SentinelError::WalCorruption {
                offset: 0,
                detail: format!("bad magic: {:?}", &hdr[0..4]),
            });
        }
        let version = u32::from_le_bytes(hdr[4..8].try_into().expect("4 bytes"));
        if version != WAL_VERSION {
            return Err(SentinelError::WalCorruption {
                offset: 4,
                detail: format!(
                    "unsupported wal version {version}, expected {WAL_VERSION}"
                ),
            });
        }
        Ok(Self {
            writer: BufWriter::new(file),
            bytes_written: existing_len,
        })
    }

    /// Append a single event. Caller is responsible for periodic [`flush`].
    pub fn append(&mut self, event: &InferenceEvent) -> Result<()> {
        let payload = serde_json::to_vec(event)?;
        let len = payload.len() as u32;
        if len > MAX_FRAME_BYTES {
            return Err(SentinelError::Invariant("wal payload exceeds max frame"));
        }
        let len_le = len.to_le_bytes();
        // CRC covers (len || payload) so corruption of either is detected.
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&len_le);
        hasher.update(&payload);
        let crc = hasher.finalize();
        self.writer.write_all(&len_le)?;
        self.writer.write_all(&crc.to_le_bytes())?;
        self.writer.write_all(&payload)?;
        self.bytes_written += 8 + payload.len() as u64;
        Ok(())
    }

    /// Flush the buffer and fsync the file. Call from a background task at
    /// a configurable cadence (e.g. every 200 ms) — calling per-event would
    /// trash throughput.
    pub fn flush(&mut self) -> Result<()> {
        self.writer.flush()?;
        self.writer.get_ref().sync_data()?;
        Ok(())
    }

    /// Current on-disk size in bytes.
    #[must_use]
    pub fn bytes_written(&self) -> u64 {
        self.bytes_written
    }
}

/// Streaming WAL reader. Each successful `next()` yields one event.
pub struct WalReader {
    reader: BufReader<File>,
    offset: u64,
}

impl std::fmt::Debug for WalReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WalReader")
            .field("offset", &self.offset)
            .finish()
    }
}

impl WalReader {
    /// Open a WAL for replay. Validates and skips the file header.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let mut file = File::open(path.as_ref())?;
        let len = file.metadata()?.len();
        if len == 0 {
            // Empty file — no header yet. Treat as empty WAL.
            return Ok(Self {
                reader: BufReader::new(file),
                offset: 0,
            });
        }
        let mut hdr = [0u8; 8];
        file.read_exact(&mut hdr).map_err(|e| {
            SentinelError::WalCorruption {
                offset: 0,
                detail: format!("short header: {e}"),
            }
        })?;
        if &hdr[0..4] != WAL_MAGIC {
            return Err(SentinelError::WalCorruption {
                offset: 0,
                detail: format!("bad magic: {:?}", &hdr[0..4]),
            });
        }
        let version = u32::from_le_bytes(hdr[4..8].try_into().expect("4 bytes"));
        if version != WAL_VERSION {
            return Err(SentinelError::WalCorruption {
                offset: 4,
                detail: format!(
                    "unsupported wal version {version}, expected {WAL_VERSION}"
                ),
            });
        }
        file.seek(SeekFrom::Start(8))?;
        Ok(Self {
            reader: BufReader::new(file),
            offset: 8,
        })
    }
}

impl Iterator for WalReader {
    type Item = Result<InferenceEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        let frame_start = self.offset;
        let mut hdr = [0u8; 8];
        match self.reader.read_exact(&mut hdr) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(e) => return Some(Err(SentinelError::Io(e))),
        }
        let len = u32::from_le_bytes(hdr[0..4].try_into().expect("4 bytes"));
        let expected_crc = u32::from_le_bytes(hdr[4..8].try_into().expect("4 bytes"));

        // Reject obviously bogus frame sizes before allocating. This
        // closes a pre-allocation DoS path on the replay code path.
        if len > MAX_FRAME_BYTES {
            return Some(Err(SentinelError::WalCorruption {
                offset: frame_start,
                detail: format!(
                    "frame length {len} exceeds MAX_FRAME_BYTES {MAX_FRAME_BYTES}"
                ),
            }));
        }

        let mut payload = vec![0u8; len as usize];
        if let Err(e) = self.reader.read_exact(&mut payload) {
            // Truncated tail — treat as clean end-of-log, not corruption.
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                return None;
            }
            return Some(Err(SentinelError::Io(e)));
        }

        // CRC covers (len || payload) — matches writer.
        let mut hasher = crc32fast::Hasher::new();
        hasher.update(&hdr[0..4]);
        hasher.update(&payload);
        let actual_crc = hasher.finalize();
        if actual_crc != expected_crc {
            return Some(Err(SentinelError::WalCorruption {
                offset: frame_start,
                detail: format!("crc mismatch: got {actual_crc:#x}, expected {expected_crc:#x}"),
            }));
        }
        self.offset += 8 + len as u64;
        let event = serde_json::from_slice::<InferenceEvent>(&payload)
            .map_err(SentinelError::from);
        Some(event)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, SeekFrom};

    use super::*;
    use crate::ingest::Status;
    use crate::time::TimestampNanos;

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("sentinel-wal-test-{name}-{}.bin", std::process::id()));
        let _ = std::fs::remove_file(&p);
        p
    }

    #[test]
    fn append_and_replay_roundtrip() {
        let path = tmp_path("roundtrip");
        {
            let mut w = Wal::open(&path).unwrap();
            for i in 0..50 {
                let ev = InferenceEvent {
                    timestamp: TimestampNanos(i as u64),
                    model: "m".into(),
                    model_version: "v1".into(),
                    latency_ms: i as f64,
                    status: Status::Success,
                    input_tokens: None,
                    output_tokens: None,
                    cost_usd: None,
                    metadata: Default::default(),
                };
                w.append(&ev).unwrap();
            }
            w.flush().unwrap();
        }
        let reader = WalReader::open(&path).unwrap();
        let events: Vec<_> = reader.collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(events.len(), 50);
        assert_eq!(events[10].latency_ms, 10.0);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn corruption_is_detected() {
        let path = tmp_path("corrupt");
        {
            let mut w = Wal::open(&path).unwrap();
            w.append(&InferenceEvent::new("m", 100.0, Status::Success))
                .unwrap();
            w.flush().unwrap();
        }
        // Flip a byte inside the first frame's payload.
        // Layout: 8-byte file header | 4-byte len | 4-byte crc | payload
        {
            let mut f = OpenOptions::new().read(true).write(true).open(&path).unwrap();
            f.seek(SeekFrom::Start(8 + 8 + 4)).unwrap();
            let buf = [0xff];
            f.write_all(&buf).unwrap();
        }
        let reader = WalReader::open(&path).unwrap();
        let result: Result<Vec<_>> = reader.collect();
        assert!(matches!(result, Err(SentinelError::WalCorruption { .. })));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn oversized_frame_is_rejected_before_allocation() {
        let path = tmp_path("oversize");
        // Write a valid file header, then a frame whose len claims
        // 4 GiB. The reader must reject without allocating.
        {
            let mut f = File::create(&path).unwrap();
            f.write_all(WAL_MAGIC).unwrap();
            f.write_all(&WAL_VERSION.to_le_bytes()).unwrap();
            f.write_all(&u32::MAX.to_le_bytes()).unwrap(); // bogus len
            f.write_all(&0u32.to_le_bytes()).unwrap();    // crc (will fail anyway)
        }
        let reader = WalReader::open(&path).unwrap();
        let result: Result<Vec<_>> = reader.collect();
        assert!(
            matches!(result, Err(SentinelError::WalCorruption { detail, .. }) if detail.contains("MAX_FRAME_BYTES"))
        );
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn header_mismatch_rejects_open() {
        let path = tmp_path("badmagic");
        std::fs::write(&path, b"XXXX\x01\x00\x00\x00garbage").unwrap();
        let err = WalReader::open(&path).unwrap_err();
        assert!(matches!(err, SentinelError::WalCorruption { .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_tail_is_treated_as_clean_eof() {
        let path = tmp_path("truncated");
        {
            let mut w = Wal::open(&path).unwrap();
            for _ in 0..3 {
                w.append(&InferenceEvent::new("m", 1.0, Status::Success))
                    .unwrap();
            }
            w.flush().unwrap();
        }
        // Truncate inside the last record.
        {
            let len = std::fs::metadata(&path).unwrap().len();
            let f = OpenOptions::new().write(true).open(&path).unwrap();
            f.set_len(len - 4).unwrap();
        }
        let reader = WalReader::open(&path).unwrap();
        let events: Vec<_> = reader.collect::<Result<Vec<_>>>().unwrap();
        assert_eq!(events.len(), 2);
        let _ = std::fs::remove_file(&path);
    }
}
