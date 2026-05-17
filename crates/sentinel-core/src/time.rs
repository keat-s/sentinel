//! Time primitives — newtype for nanosecond timestamps and helpers.
//!
//! Sentinel stores timestamps as `u64` nanoseconds since the Unix epoch.
//! That range is good for ~584 years from 1970, which is more than fine for
//! observability data.

use std::time::{SystemTime, UNIX_EPOCH};

/// Newtype wrapper for nanosecond Unix timestamps.
///
/// Using a newtype rather than a bare `u64` prevents accidentally mixing
/// nanos, millis, and seconds at call sites — a common bug class in
/// telemetry code.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(transparent)]
pub struct TimestampNanos(pub u64);

impl TimestampNanos {
    /// Returns the current wall-clock time as nanoseconds since the epoch.
    #[must_use]
    pub fn now() -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0);
        TimestampNanos(nanos)
    }

    /// Construct a timestamp from milliseconds (lossy upward — values fit).
    #[must_use]
    pub const fn from_millis(ms: u64) -> Self {
        TimestampNanos(ms.saturating_mul(1_000_000))
    }

    /// Returns the underlying nanosecond value.
    #[must_use]
    pub const fn as_nanos(self) -> u64 {
        self.0
    }

    /// Returns the value in milliseconds, rounded down.
    #[must_use]
    pub const fn as_millis(self) -> u64 {
        self.0 / 1_000_000
    }

    /// Returns the value in seconds, rounded down.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0 / 1_000_000_000
    }

    /// Bucket the timestamp by a duration (in nanoseconds), returning the
    /// timestamp of the start of the containing bucket.
    #[must_use]
    pub const fn bucket(self, bucket_size_nanos: u64) -> Self {
        TimestampNanos((self.0 / bucket_size_nanos) * bucket_size_nanos)
    }

    /// Subtract another timestamp, saturating at zero.
    #[must_use]
    pub const fn saturating_sub(self, other: Self) -> u64 {
        self.0.saturating_sub(other.0)
    }
}

impl std::ops::Add<u64> for TimestampNanos {
    type Output = TimestampNanos;
    fn add(self, nanos: u64) -> Self::Output {
        TimestampNanos(self.0.saturating_add(nanos))
    }
}

impl std::ops::Sub<u64> for TimestampNanos {
    type Output = TimestampNanos;
    fn sub(self, nanos: u64) -> Self::Output {
        TimestampNanos(self.0.saturating_sub(nanos))
    }
}

/// One second in nanoseconds.
pub const SECOND: u64 = 1_000_000_000;
/// One minute in nanoseconds.
pub const MINUTE: u64 = 60 * SECOND;
/// One hour in nanoseconds.
pub const HOUR: u64 = 60 * MINUTE;
/// One day in nanoseconds.
pub const DAY: u64 = 24 * HOUR;

/// A trait abstracting "now" so tests can advance time deterministically.
///
/// This is the standard Rust pattern for testable time: production code
/// uses [`SystemClock`], tests inject a [`MockClock`].
pub trait Clock: Send + Sync + 'static {
    /// Return the current timestamp.
    fn now(&self) -> TimestampNanos;
}

/// Wall-clock implementation of [`Clock`].
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> TimestampNanos {
        TimestampNanos::now()
    }
}

/// Test-only manually-advanced clock.
#[derive(Debug, Default)]
pub struct MockClock {
    nanos: parking_lot::Mutex<u64>,
}

impl MockClock {
    /// Create a mock clock starting at time zero.
    #[must_use]
    pub fn new() -> Self {
        Self {
            nanos: parking_lot::Mutex::new(0),
        }
    }

    /// Create a mock clock starting at the given nanosecond timestamp.
    #[must_use]
    pub fn starting_at(start: TimestampNanos) -> Self {
        Self {
            nanos: parking_lot::Mutex::new(start.0),
        }
    }

    /// Advance the mock clock by `delta` nanoseconds.
    pub fn advance(&self, delta: u64) {
        let mut g = self.nanos.lock();
        *g = g.saturating_add(delta);
    }
}

impl Clock for MockClock {
    fn now(&self) -> TimestampNanos {
        TimestampNanos(*self.nanos.lock())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_aligns_down() {
        let t = TimestampNanos::from_millis(1_234_567);
        let bucketed = t.bucket(SECOND);
        assert_eq!(bucketed.as_secs(), 1_234);
    }

    #[test]
    fn mock_clock_advances() {
        let c = MockClock::new();
        assert_eq!(c.now().as_nanos(), 0);
        c.advance(SECOND);
        assert_eq!(c.now().as_secs(), 1);
        c.advance(MINUTE);
        assert_eq!(c.now().as_secs(), 61);
    }
}
