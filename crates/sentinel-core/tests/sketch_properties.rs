//! Property-based invariant tests for the streaming sketches.
//!
//! These complement the example-based unit tests in each sketch module:
//! instead of checking specific values, they assert invariants that must
//! hold for *any* input stream.

use proptest::prelude::*;

use sentinel_core::sketches::{Ewma, EwmaVariance, HyperLogLog, TDigest};

/// A non-empty vec of finite, sane-magnitude f64 samples.
fn samples() -> impl Strategy<Value = Vec<f64>> {
    prop::collection::vec(-1e9f64..1e9, 1..500)
}

proptest! {
    // --- TDigest ------------------------------------------------------------

    #[test]
    fn tdigest_quantile_stays_within_observed_range(xs in samples(), q in 0.0f64..=1.0) {
        let mut t = TDigest::new(100.0);
        t.insert_many(xs.iter().copied());
        let lo = xs.iter().copied().fold(f64::INFINITY, f64::min);
        let hi = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let v = t.quantile(q);
        prop_assert!(v >= lo && v <= hi, "quantile({q}) = {v} outside [{lo}, {hi}]");
    }

    #[test]
    fn tdigest_quantile_is_monotone_in_q(xs in samples(), a in 0.0f64..=1.0, b in 0.0f64..=1.0) {
        let (qa, qb) = if a <= b { (a, b) } else { (b, a) };
        let mut t = TDigest::new(100.0);
        t.insert_many(xs.iter().copied());
        prop_assert!(
            t.quantile(qa) <= t.quantile(qb),
            "quantile({qa}) > quantile({qb})"
        );
    }

    #[test]
    fn tdigest_cdf_is_bounded_and_monotone(xs in samples(), a in -1e9f64..1e9, b in -1e9f64..1e9) {
        let (xa, xb) = if a <= b { (a, b) } else { (b, a) };
        let mut t = TDigest::new(100.0);
        t.insert_many(xs.iter().copied());
        let ca = t.cdf(xa);
        let cb = t.cdf(xb);
        prop_assert!((0.0..=1.0).contains(&ca));
        prop_assert!((0.0..=1.0).contains(&cb));
        prop_assert!(ca <= cb, "cdf({xa}) = {ca} > cdf({xb}) = {cb}");
    }

    #[test]
    fn tdigest_count_above_is_bounded_by_count(xs in samples(), threshold in -1e9f64..1e9) {
        let mut t = TDigest::new(100.0);
        t.insert_many(xs.iter().copied());
        let above = t.count_above(threshold);
        prop_assert!(above >= 0.0);
        prop_assert!(above <= t.count() + 1e-6, "count_above {above} > count {}", t.count());
    }

    #[test]
    fn tdigest_merge_preserves_total_count(xs in samples(), ys in samples()) {
        let mut a = TDigest::new(100.0);
        a.insert_many(xs.iter().copied());
        let mut b = TDigest::new(100.0);
        b.insert_many(ys.iter().copied());
        let expected = a.count() + b.count();
        a.merge(&b);
        prop_assert!(
            (a.count() - expected).abs() < 1e-6,
            "merged count {} != {expected}",
            a.count()
        );
        // Merged extremes cover both inputs.
        let lo = xs.iter().chain(ys.iter()).copied().fold(f64::INFINITY, f64::min);
        let hi = xs.iter().chain(ys.iter()).copied().fold(f64::NEG_INFINITY, f64::max);
        prop_assert!(a.min() <= lo + 1e-9);
        prop_assert!(a.max() >= hi - 1e-9);
    }

    // --- HyperLogLog ----------------------------------------------------------

    #[test]
    fn hll_estimate_tracks_distinct_count(n in 1usize..3000) {
        let mut h = HyperLogLog::new();
        for i in 0..n {
            h.insert(&format!("item-{i}"));
        }
        let est = h.estimate() as f64;
        // Standard HLL error is ~1.04/sqrt(m); allow a generous 25% + small
        // absolute slack so tiny n doesn't flake.
        let err = (est - n as f64).abs();
        prop_assert!(
            err <= n as f64 * 0.25 + 8.0,
            "estimate {est} too far from true {n}"
        );
    }

    #[test]
    fn hll_is_idempotent_under_reinsertion(n in 1usize..500) {
        let mut h = HyperLogLog::new();
        for i in 0..n {
            h.insert(&format!("item-{i}"));
        }
        let first = h.estimate();
        // Re-inserting the same items must not change the estimate.
        for i in 0..n {
            h.insert(&format!("item-{i}"));
        }
        prop_assert_eq!(h.estimate(), first);
    }

    #[test]
    fn hll_merge_equals_union(n in 1usize..500, m in 1usize..500) {
        // Two overlapping sets: [0, n) and [n/2, n/2 + m).
        let mut a = HyperLogLog::new();
        for i in 0..n {
            a.insert(&format!("item-{i}"));
        }
        let mut b = HyperLogLog::new();
        for i in n / 2..n / 2 + m {
            b.insert(&format!("item-{i}"));
        }
        let mut union = HyperLogLog::new();
        for i in 0..n.max(n / 2 + m) {
            if i < n || (n / 2..n / 2 + m).contains(&i) {
                union.insert(&format!("item-{i}"));
            }
        }
        a.merge(&b);
        prop_assert_eq!(
            a.estimate(),
            union.estimate(),
            "merge must produce the same registers as inserting the union"
        );
    }

    // --- EWMA -----------------------------------------------------------------

    #[test]
    fn ewma_stays_within_observed_range(xs in samples(), alpha in 0.01f64..=1.0) {
        let mut e = Ewma::new(alpha);
        for &x in &xs {
            e.observe(x);
        }
        let lo = xs.iter().copied().fold(f64::INFINITY, f64::min);
        let hi = xs.iter().copied().fold(f64::NEG_INFINITY, f64::max);
        let v = e.value().unwrap();
        prop_assert!(v >= lo - 1e-9 && v <= hi + 1e-9, "ewma {v} outside [{lo}, {hi}]");
    }

    #[test]
    fn ewma_variance_is_never_negative(xs in samples(), alpha in 0.01f64..=1.0) {
        let mut v = EwmaVariance::new(alpha);
        for &x in &xs {
            v.observe(x);
        }
        prop_assert!(v.variance() >= 0.0);
        prop_assert!(v.stddev() >= 0.0);
        prop_assert_eq!(v.count(), xs.len() as u64);
    }
}
