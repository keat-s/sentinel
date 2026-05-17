//! Tiny HyperLogLog — cardinality estimation in constant memory.
//!
//! In the inference-observability context, HLL is useful as a drift
//! signal: "how many distinct `model_version` strings did we see in the
//! last 5 minutes?" jumps when a rollout starts.
//!
//! This is a stripped-down HLL with no bias correction beyond LinearCounting
//! at low ranges. It's intentionally simple — 1024 registers (precision
//! p = 10), ≈ 2.6% standard error, 1 KB of memory.

use std::hash::{Hash, Hasher};

use ahash::AHasher;

const P: u32 = 10;
const M: usize = 1 << P; // 1024 registers
const ALPHA_MM: f64 = 0.7213 / (1.0 + 1.079 / (M as f64));

/// Hyperloglog sketch with fixed precision p=10.
#[derive(Debug, Clone)]
pub struct HyperLogLog {
    registers: [u8; M],
}

impl Default for HyperLogLog {
    fn default() -> Self {
        Self::new()
    }
}

impl HyperLogLog {
    /// Construct an empty HLL with precision p=10 (1024 registers).
    #[must_use]
    pub fn new() -> Self {
        Self { registers: [0; M] }
    }

    /// Insert an element. Anything `Hash` works.
    pub fn insert<T: Hash + ?Sized>(&mut self, x: &T) {
        let mut h = AHasher::default();
        x.hash(&mut h);
        let hash = h.finish();
        let index = (hash >> (64 - P)) as usize;
        let w = (hash << P) | (1 << (P - 1));
        let leading = w.leading_zeros() as u8 + 1;
        if leading > self.registers[index] {
            self.registers[index] = leading;
        }
    }

    /// Current cardinality estimate.
    #[must_use]
    pub fn estimate(&self) -> u64 {
        let m = M as f64;

        let sum: f64 = self
            .registers
            .iter()
            .map(|&r| 2f64.powi(-(i32::from(r))))
            .sum();
        let raw = ALPHA_MM * m * m / sum;

        // Small-range correction: LinearCounting if many registers are zero.
        let zeros = self.registers.iter().filter(|&&r| r == 0).count();
        if raw <= 2.5 * m && zeros > 0 {
            (m * (m / zeros as f64).ln()).round() as u64
        } else {
            raw.round() as u64
        }
    }

    /// Merge in another HLL — union semantics.
    pub fn merge(&mut self, other: &HyperLogLog) {
        for (a, &b) in self.registers.iter_mut().zip(other.registers.iter()) {
            if b > *a {
                *a = b;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_zero() {
        let h = HyperLogLog::new();
        assert_eq!(h.estimate(), 0);
    }

    #[test]
    fn estimates_within_tolerance() {
        let mut h = HyperLogLog::new();
        let n = 10_000u64;
        for i in 0..n {
            h.insert(&format!("item-{i}"));
        }
        let est = h.estimate() as f64;
        let err = (est - n as f64).abs() / n as f64;
        // p=10 → expected stddev ≈ 2.6%; allow 3 stddev = ~8%
        assert!(err < 0.08, "estimate {est} too far from {n} (err {err})");
    }

    #[test]
    fn duplicates_dont_inflate_estimate() {
        let mut h = HyperLogLog::new();
        for _ in 0..1000 {
            h.insert("same-key");
        }
        // Should be ~1, certainly < 5
        assert!(h.estimate() < 5);
    }

    #[test]
    fn merge_unions_correctly() {
        let mut a = HyperLogLog::new();
        let mut b = HyperLogLog::new();
        for i in 0..500u64 {
            a.insert(&format!("a-{i}"));
        }
        for i in 0..500u64 {
            b.insert(&format!("b-{i}"));
        }
        a.merge(&b);
        let est = a.estimate() as f64;
        let err = (est - 1000.0).abs() / 1000.0;
        assert!(err < 0.10, "merged estimate {est} far from 1000");
    }
}
