//! Error-budget math.
//!
//! Given an SLO objective `O` and `total` events of which `bad` were bad,
//! the **error budget** is the number of bad events allowed across the
//! whole window: `total * (1 - O)`.
//!
//! The **budget remaining** is `total*(1-O) - bad`. Once it crosses zero
//! the SLO is in breach.

/// Error budget state at one point in time.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ErrorBudget {
    /// Total events seen.
    pub total: u64,
    /// Bad events seen.
    pub bad: u64,
    /// SLO objective in `(0, 1)`.
    pub objective: f64,
}

impl ErrorBudget {
    /// Construct from raw counters and objective.
    #[must_use]
    pub fn new(total: u64, bad: u64, objective: f64) -> Self {
        Self {
            total,
            bad,
            objective,
        }
    }

    /// Total bad-event allowance for this window.
    #[must_use]
    pub fn allowance(&self) -> f64 {
        self.total as f64 * (1.0 - self.objective)
    }

    /// Fraction of the budget consumed in `[0, ∞)`. `> 1.0` means breach.
    ///
    /// Returns 0 when total is zero (no events ⇒ no consumption).
    #[must_use]
    pub fn consumed_fraction(&self) -> f64 {
        let allow = self.allowance();
        if allow <= 0.0 {
            return 0.0;
        }
        self.bad as f64 / allow
    }

    /// Fraction of the budget remaining in `(-∞, 1]`.
    #[must_use]
    pub fn remaining_fraction(&self) -> f64 {
        1.0 - self.consumed_fraction()
    }

    /// Burn rate: how fast we are consuming the budget relative to the
    /// SLO's tolerable failure rate. `1.0` = exactly on budget; `> 1` =
    /// burning faster than allowed; `< 1` = burning slower.
    #[must_use]
    pub fn burn_rate(&self) -> f64 {
        if self.total == 0 {
            return 0.0;
        }
        let tolerable = 1.0 - self.objective;
        let observed = self.bad as f64 / self.total as f64;
        if tolerable <= 0.0 {
            return if observed > 0.0 { f64::INFINITY } else { 0.0 };
        }
        observed / tolerable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn on_budget_burn_rate_is_one() {
        // 1% bad against 99% objective.
        let b = ErrorBudget::new(10_000, 100, 0.99);
        assert!((b.burn_rate() - 1.0).abs() < 1e-9);
        assert!((b.consumed_fraction() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn double_burn_rate() {
        let b = ErrorBudget::new(10_000, 200, 0.99);
        assert!((b.burn_rate() - 2.0).abs() < 1e-9);
    }

    #[test]
    fn no_traffic_is_zero_burn() {
        let b = ErrorBudget::new(0, 0, 0.999);
        assert_eq!(b.burn_rate(), 0.0);
    }

    #[test]
    fn perfect_objective_with_failures_is_infinite_burn() {
        let b = ErrorBudget::new(1000, 1, 1.0);
        assert_eq!(b.burn_rate(), f64::INFINITY);
    }
}
