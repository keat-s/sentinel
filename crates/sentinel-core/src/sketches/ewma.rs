//! Exponentially-weighted moving average — and its variance partner.
//!
//! EWMA is the bread-and-butter streaming estimator for "what's roughly
//! happening *recently*". A single scalar `alpha` controls how aggressively
//! recent samples dominate older ones:
//!
//! ```text
//! mean_{t+1} = alpha * x_{t+1} + (1 - alpha) * mean_t
//! ```
//!
//! For variance we use the Finch-style "EWMV" / West-style recurrence:
//!
//! ```text
//! diff   = x - mean
//! incr   = alpha * diff
//! mean   = mean + incr
//! var    = (1 - alpha) * (var + diff * incr)
//! ```
//!
//! …which is numerically stable and converges on the true variance of a
//! stationary stream.

/// Plain EWMA over `f64` observations.
#[derive(Debug, Clone)]
pub struct Ewma {
    alpha: f64,
    value: Option<f64>,
}

impl Ewma {
    /// Construct an EWMA with smoothing factor `alpha` in `(0, 1]`.
    ///
    /// Smaller alpha = smoother (longer effective memory).
    /// A handy rule of thumb: `alpha = 2 / (N + 1)` gives an N-sample EMA.
    ///
    /// # Panics
    /// Panics if `alpha` is outside `(0, 1]` or NaN.
    #[must_use]
    pub fn new(alpha: f64) -> Self {
        assert!(
            alpha > 0.0 && alpha <= 1.0 && alpha.is_finite(),
            "alpha must be in (0, 1]"
        );
        Self { alpha, value: None }
    }

    /// Update with a new observation and return the new estimate.
    pub fn observe(&mut self, x: f64) -> f64 {
        let new = match self.value {
            None => x,
            Some(prev) => self.alpha * x + (1.0 - self.alpha) * prev,
        };
        self.value = Some(new);
        new
    }

    /// Current estimate, or `None` if no observations have been made.
    #[must_use]
    pub fn value(&self) -> Option<f64> {
        self.value
    }
}

/// EWMA mean + variance.
///
/// Useful for streaming z-score anomaly detection where you want a
/// rolling notion of "typical" without keeping a window of samples.
#[derive(Debug, Clone)]
pub struct EwmaVariance {
    alpha: f64,
    mean: f64,
    var: f64,
    count: u64,
}

impl EwmaVariance {
    /// Construct an EWMA-variance estimator with smoothing factor `alpha`.
    ///
    /// # Panics
    /// Panics if `alpha` is outside `(0, 1]` or NaN.
    #[must_use]
    pub fn new(alpha: f64) -> Self {
        assert!(
            alpha > 0.0 && alpha <= 1.0 && alpha.is_finite(),
            "alpha must be in (0, 1]"
        );
        Self {
            alpha,
            mean: 0.0,
            var: 0.0,
            count: 0,
        }
    }

    /// Update with a new observation.
    pub fn observe(&mut self, x: f64) {
        self.count += 1;
        if self.count == 1 {
            self.mean = x;
            self.var = 0.0;
            return;
        }
        let diff = x - self.mean;
        let incr = self.alpha * diff;
        self.mean += incr;
        self.var = (1.0 - self.alpha) * (self.var + diff * incr);
    }

    /// Current mean estimate.
    #[must_use]
    pub fn mean(&self) -> f64 {
        self.mean
    }

    /// Current variance estimate (always non-negative).
    #[must_use]
    pub fn variance(&self) -> f64 {
        self.var.max(0.0)
    }

    /// Current standard deviation.
    #[must_use]
    pub fn stddev(&self) -> f64 {
        self.variance().sqrt()
    }

    /// Number of observations made.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.count
    }

    /// z-score of `x` relative to the current estimate.
    ///
    /// Returns `None` if there isn't enough data yet (< 2 samples) or the
    /// stddev is degenerate.
    #[must_use]
    pub fn z_score(&self, x: f64) -> Option<f64> {
        if self.count < 2 {
            return None;
        }
        let sd = self.stddev();
        if sd <= f64::EPSILON {
            return None;
        }
        Some((x - self.mean) / sd)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ewma_initial_equals_first_value() {
        let mut e = Ewma::new(0.3);
        assert_eq!(e.observe(10.0), 10.0);
    }

    #[test]
    fn ewma_converges_to_constant() {
        let mut e = Ewma::new(0.2);
        for _ in 0..200 {
            e.observe(5.0);
        }
        assert!((e.value().unwrap() - 5.0).abs() < 1e-6);
    }

    #[test]
    fn variance_zero_for_constant_stream() {
        let mut v = EwmaVariance::new(0.2);
        for _ in 0..1000 {
            v.observe(7.0);
        }
        assert!(v.variance() < 1e-6);
    }

    #[test]
    fn z_score_catches_spike() {
        let mut v = EwmaVariance::new(0.2);
        // Seed with noisy baseline around 100
        let mut rng_state: u64 = 0x12345678;
        for _ in 0..200 {
            // tiny LCG for determinism without an extra dep
            rng_state = rng_state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let noise = ((rng_state >> 11) as f64 / (1u64 << 53) as f64) - 0.5;
            v.observe(100.0 + noise);
        }
        let z = v.z_score(500.0).unwrap();
        assert!(z > 100.0, "expected huge z-score, got {z}");
    }
}
