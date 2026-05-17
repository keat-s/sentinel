//! Simplified t-digest — a sketch for accurate streaming quantiles.
//!
//! This is a faithful, compact implementation of Ted Dunning's t-digest
//! using the "merging" variant: incoming samples are buffered and then
//! merged into a sorted vector of weighted centroids using the canonical
//! scale function k(q) = δ/(2π) · arcsin(2q − 1).
//!
//! The scale function clusters centroids tightly near the tails (where
//! quantile estimates matter most for SRE work) and loosely near the
//! median, so total memory is bounded by the compression factor `δ`
//! regardless of how many samples are inserted.
//!
//! References:
//! - Dunning, "Computing Extremely Accurate Quantiles Using t-Digests"
//!   (2019), <https://arxiv.org/abs/1902.04023>

use std::cmp::Ordering;

use serde::{Deserialize, Serialize};

/// One weighted cluster of samples.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Centroid {
    /// Cluster center (weighted mean of the underlying samples).
    pub mean: f64,
    /// Number of samples summarized in this centroid.
    pub weight: f64,
}

/// Streaming quantile sketch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TDigest {
    /// Compression factor `δ`. Higher = more accurate, more memory.
    pub compression: f64,

    /// Centroids sorted by `mean` (ascending). Invariant: always sorted
    /// after compress(); buffer is flushed before any quantile query.
    centroids: Vec<Centroid>,

    /// Unmerged samples — flushed to `centroids` lazily.
    buffer: Vec<f64>,

    /// Sum of all weights inserted.
    total_weight: f64,

    /// Min and max observed values (preserved exactly for accurate tails).
    min: f64,
    max: f64,
}

impl TDigest {
    /// Construct an empty t-digest with the given compression factor.
    ///
    /// A `compression` of 100 is the canonical default and gives roughly
    /// 1% relative error on extreme quantiles.
    #[must_use]
    pub fn new(compression: f64) -> Self {
        Self {
            compression: compression.max(20.0),
            centroids: Vec::new(),
            buffer: Vec::new(),
            total_weight: 0.0,
            min: f64::INFINITY,
            max: f64::NEG_INFINITY,
        }
    }

    /// Number of underlying samples observed.
    #[must_use]
    pub fn count(&self) -> f64 {
        self.total_weight + self.buffer.len() as f64
    }

    /// True if no samples have been inserted.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.total_weight == 0.0 && self.buffer.is_empty()
    }

    /// Insert one sample.
    pub fn insert(&mut self, x: f64) {
        if !x.is_finite() {
            return;
        }
        self.min = self.min.min(x);
        self.max = self.max.max(x);
        self.buffer.push(x);
        if self.buffer.len() as f64 > self.compression * 8.0 {
            self.compress();
        }
    }

    /// Insert many samples at once.
    pub fn insert_many(&mut self, xs: impl IntoIterator<Item = f64>) {
        for x in xs {
            self.insert(x);
        }
    }

    /// Force a buffer flush + recompression pass.
    pub fn compress(&mut self) {
        if self.buffer.is_empty() {
            return;
        }

        // Move existing centroids + new samples into a single sorted list.
        let mut all: Vec<Centroid> = self.centroids.drain(..).collect();
        for x in self.buffer.drain(..) {
            all.push(Centroid {
                mean: x,
                weight: 1.0,
            });
        }
        all.sort_by(|a, b| a.mean.partial_cmp(&b.mean).unwrap_or(Ordering::Equal));

        let n: f64 = all.iter().map(|c| c.weight).sum();
        self.total_weight = n;

        // Merge adjacent centroids whenever the resulting weight stays
        // within the scale function's allowance for the current quantile.
        let delta = self.compression;
        let mut merged: Vec<Centroid> = Vec::with_capacity(all.len());
        let mut cum_w = 0.0;

        for c in all {
            if let Some(last) = merged.last_mut() {
                // q-position of the centroid we'd produce if we merged
                let proposed_weight = last.weight + c.weight;
                let q_lo = cum_w / n;
                let q_hi = (cum_w + proposed_weight) / n;
                let bound = (n / delta)
                    * (k_scale(q_hi, delta) - k_scale(q_lo, delta))
                          .abs()
                          .max(1.0); // never reject single samples

                if proposed_weight <= bound {
                    // merge
                    last.mean =
                        (last.mean * last.weight + c.mean * c.weight) / proposed_weight;
                    last.weight = proposed_weight;
                    continue;
                }
                cum_w += last.weight;
            }
            merged.push(c);
        }

        self.centroids = merged;
    }

    /// Estimate the CDF at value `x`: the fraction of observed samples that
    /// are less than or equal to `x`, in `[0, 1]`.
    ///
    /// This is the dual of [`quantile`](Self::quantile) and is what threshold
    /// SLIs need: "what fraction of calls were under 500 ms?"
    ///
    /// Returns `NaN` if no samples have been inserted.
    #[must_use]
    pub fn cdf(&mut self, x: f64) -> f64 {
        self.compress();
        if self.centroids.is_empty() {
            return f64::NAN;
        }
        if x < self.min {
            return 0.0;
        }
        if x >= self.max {
            return 1.0;
        }
        if self.centroids.len() == 1 {
            // single centroid — step function at its mean
            return if x < self.centroids[0].mean { 0.0 } else { 1.0 };
        }

        let n = self.total_weight;
        let mut cum = 0.0;
        for (i, c) in self.centroids.iter().enumerate() {
            if x < c.mean {
                if i == 0 {
                    // between min and first centroid
                    let frac = (x - self.min) / (c.mean - self.min).max(f64::EPSILON);
                    return frac * (c.weight / 2.0) / n;
                }
                let prev = &self.centroids[i - 1];
                let left_cum = cum - prev.weight / 2.0;
                let span = c.weight / 2.0 + prev.weight / 2.0;
                let frac = (x - prev.mean) / (c.mean - prev.mean).max(f64::EPSILON);
                return (left_cum + frac * span) / n;
            }
            cum += c.weight;
        }
        // Above all centroid means but ≤ max: interpolate from last centroid mean to max.
        let last = self.centroids.last().expect("non-empty checked above");
        let left_cum = cum - last.weight / 2.0;
        let frac = (x - last.mean) / (self.max - last.mean).max(f64::EPSILON);
        ((left_cum + frac * (last.weight / 2.0)) / n).clamp(0.0, 1.0)
    }

    /// Convenience: estimated count of samples greater than `x`.
    #[must_use]
    pub fn count_above(&mut self, x: f64) -> f64 {
        let n = self.count();
        if n == 0.0 {
            return 0.0;
        }
        let above_fraction = (1.0 - self.cdf(x)).clamp(0.0, 1.0);
        n * above_fraction
    }

    /// Estimate the value at quantile `q ∈ [0, 1]`.
    ///
    /// Returns `NaN` if no samples have been inserted.
    #[must_use]
    pub fn quantile(&mut self, q: f64) -> f64 {
        let q = q.clamp(0.0, 1.0);
        self.compress();

        if self.centroids.is_empty() {
            return f64::NAN;
        }
        if self.centroids.len() == 1 {
            return self.centroids[0].mean;
        }
        if q == 0.0 {
            return self.min;
        }
        if q == 1.0 {
            return self.max;
        }

        let n = self.total_weight;
        let target = q * n;
        let mut cum = 0.0;

        for (i, c) in self.centroids.iter().enumerate() {
            let half = c.weight / 2.0;
            if cum + half >= target {
                // interpolate between previous and current
                if i == 0 {
                    let frac = (target - cum) / half;
                    return self.min + frac * (c.mean - self.min);
                }
                let prev = &self.centroids[i - 1];
                let left_cum = cum - prev.weight / 2.0;
                let span = c.weight / 2.0 + prev.weight / 2.0;
                let frac = (target - left_cum) / span;
                return prev.mean + frac * (c.mean - prev.mean);
            }
            cum += c.weight;
        }

        // Tail
        let last = self.centroids.last().expect("non-empty checked above");
        let frac = (target - (cum - last.weight / 2.0)) / (last.weight / 2.0);
        last.mean + frac * (self.max - last.mean)
    }

    /// Merge another digest into this one. Both are left valid.
    ///
    /// Merges centroids directly (no per-sample rehydration), so fractional
    /// weights are preserved and memory is O(centroids), not O(samples).
    /// This is the canonical "merging digest" approach from Dunning's paper.
    pub fn merge(&mut self, other: &TDigest) {
        if other.is_empty() {
            return;
        }
        // Flush our own buffer first so all data is in centroid form.
        self.compress();

        // Combine and re-compress directly from centroids.
        let mut all: Vec<Centroid> = self.centroids.drain(..).collect();
        for c in &other.centroids {
            all.push(*c);
        }
        // Include other.buffer too (it hasn't been compressed yet).
        for x in &other.buffer {
            if x.is_finite() {
                all.push(Centroid {
                    mean: *x,
                    weight: 1.0,
                });
            }
        }
        all.sort_by(|a, b| a.mean.partial_cmp(&b.mean).unwrap_or(Ordering::Equal));

        let n: f64 = all.iter().map(|c| c.weight).sum();
        self.total_weight = n;

        let delta = self.compression;
        let mut merged: Vec<Centroid> = Vec::with_capacity(all.len());
        let mut cum_w = 0.0;
        for c in all {
            if let Some(last) = merged.last_mut() {
                let proposed_weight = last.weight + c.weight;
                let q_lo = cum_w / n;
                let q_hi = (cum_w + proposed_weight) / n;
                let bound = (n / delta)
                    * (k_scale(q_hi, delta) - k_scale(q_lo, delta))
                        .abs()
                        .max(1.0);
                if proposed_weight <= bound {
                    last.mean =
                        (last.mean * last.weight + c.mean * c.weight) / proposed_weight;
                    last.weight = proposed_weight;
                    continue;
                }
                cum_w += last.weight;
            }
            merged.push(c);
        }

        self.centroids = merged;
        self.min = self.min.min(other.min);
        self.max = self.max.max(other.max);
    }

    /// Observed minimum.
    #[must_use]
    pub fn min(&self) -> f64 {
        self.min
    }

    /// Observed maximum.
    #[must_use]
    pub fn max(&self) -> f64 {
        self.max
    }
}

/// k-scale function for t-digest: maps quantile q → "cluster space".
///
/// Using k1: k(q) = (δ/(2π)) · arcsin(2q − 1).
#[inline]
fn k_scale(q: f64, delta: f64) -> f64 {
    let q = q.clamp(0.0, 1.0);
    (delta / (2.0 * std::f64::consts::PI)) * ((2.0 * q - 1.0).asin())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn approx_eq(a: f64, b: f64, tol: f64) -> bool {
        (a - b).abs() <= tol
    }

    #[test]
    fn empty_quantile_is_nan() {
        let mut t = TDigest::new(100.0);
        assert!(t.quantile(0.5).is_nan());
    }

    #[test]
    fn quantile_of_uniform_distribution_is_accurate() {
        let mut t = TDigest::new(200.0);
        for i in 0..10_000 {
            t.insert(i as f64);
        }
        let p50 = t.quantile(0.5);
        let p95 = t.quantile(0.95);
        let p99 = t.quantile(0.99);
        // Tolerances: middle is loose, tails should be tight
        assert!(approx_eq(p50, 5000.0, 200.0), "p50={p50}");
        assert!(approx_eq(p95, 9500.0, 200.0), "p95={p95}");
        assert!(approx_eq(p99, 9900.0, 200.0), "p99={p99}");
    }

    #[test]
    fn min_max_are_preserved_exactly() {
        let mut t = TDigest::new(100.0);
        t.insert(1.0);
        t.insert(999.0);
        for _ in 0..5_000 {
            t.insert(500.0);
        }
        assert_eq!(t.quantile(0.0), 1.0);
        assert_eq!(t.quantile(1.0), 999.0);
    }

    #[test]
    fn merge_preserves_distribution() {
        let mut a = TDigest::new(200.0);
        let mut b = TDigest::new(200.0);
        for i in 0..5_000 {
            a.insert(i as f64);
        }
        for i in 5_000..10_000 {
            b.insert(i as f64);
        }
        a.merge(&b);
        let p95 = a.quantile(0.95);
        assert!(approx_eq(p95, 9500.0, 250.0), "p95={p95}");
    }

    #[test]
    fn cdf_matches_quantile_inverse() {
        let mut t = TDigest::new(200.0);
        for i in 0..10_000 {
            t.insert(i as f64);
        }
        // P95 of uniform[0, 9999] ≈ 9500; cdf(9500) should ≈ 0.95.
        let cdf_at_9500 = t.cdf(9500.0);
        assert!(
            (cdf_at_9500 - 0.95).abs() < 0.03,
            "cdf(9500)={cdf_at_9500}, expected ~0.95"
        );
        // count_above(9500) ≈ 500 samples (5% of 10k).
        let count = t.count_above(9500.0);
        assert!(
            (count - 500.0).abs() < 100.0,
            "count_above(9500)={count}, expected ~500"
        );
    }

    #[test]
    fn cdf_at_extremes() {
        let mut t = TDigest::new(100.0);
        for i in 0..100 {
            t.insert(i as f64);
        }
        assert_eq!(t.cdf(-100.0), 0.0);
        assert_eq!(t.cdf(1_000_000.0), 1.0);
    }

    #[test]
    fn merge_preserves_fractional_weights() {
        // Two digests with overlapping distributions; after merge,
        // total weight must equal sum of inputs and quantiles stay sane.
        let mut a = TDigest::new(200.0);
        let mut b = TDigest::new(200.0);
        for i in 0..1000 {
            a.insert(i as f64);
            b.insert((i as f64) + 0.5);
        }
        a.merge(&b);
        // 2000 samples total
        assert!((a.count() - 2000.0).abs() < 1.0);
        let p50 = a.quantile(0.5);
        assert!((p50 - 500.0).abs() < 25.0, "p50={p50}");
    }

    #[test]
    fn nan_and_infinity_are_ignored() {
        let mut t = TDigest::new(100.0);
        t.insert(f64::NAN);
        t.insert(f64::INFINITY);
        t.insert(f64::NEG_INFINITY);
        assert!(t.is_empty());
    }
}
