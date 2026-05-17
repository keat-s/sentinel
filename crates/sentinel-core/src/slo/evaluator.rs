//! Multi-window multi-burn-rate SLO alert evaluator.
//!
//! Implements the recipe from the Google SRE Workbook
//! (<https://sre.google/workbook/alerting-on-slos/>). For each SLO we
//! evaluate three tiers; each tier consumes a "long" and a "short"
//! window and fires only when both exceed the tier's burn threshold.
//!
//! This dual-window requirement is the key trick: the long window
//! detects sustained problems (so we don't page on a 10-second blip)
//! while the short window ensures the problem is *still happening*
//! (so the page auto-resolves once it stops). Naive single-window
//! alerts on burn rate suffer from one or the other failure mode.

use serde::Serialize;

use crate::time::{DAY, HOUR, MINUTE};
use crate::tsdb::Tsdb;

use super::budget::ErrorBudget;
use super::definition::{Sli, SloConfig};

/// Severity of a fired SLO alert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    /// Page-worthy.
    Page,
    /// File-a-ticket-worthy.
    Ticket,
}

/// Definition of one burn-rate tier (a long+short pair).
#[derive(Debug, Clone, Copy)]
pub struct BurnRateTier {
    /// Burn-rate threshold (multiple of the SLO's tolerable failure rate).
    pub burn_rate: f64,
    /// Long observation window in nanoseconds.
    pub long_window: u64,
    /// Short confirmation window in nanoseconds (must also exceed).
    pub short_window: u64,
    /// Severity assigned when this tier fires.
    pub severity: AlertSeverity,
    /// Human-readable label for logs and UI.
    pub label: &'static str,
}

/// Standard 3-tier set from the SRE Workbook.
///
/// - Tier 1: 1h/5m, 14.4× burn, page (2% of 30-day budget in 1h).
/// - Tier 2: 6h/30m, 6× burn, page (5% of 30-day budget in 6h).
/// - Tier 3: 3d/6h, 1× burn, ticket (10% of 30-day budget in 3d).
pub const DEFAULT_TIERS: &[BurnRateTier] = &[
    BurnRateTier {
        burn_rate: 14.4,
        long_window: HOUR,
        short_window: 5 * MINUTE,
        severity: AlertSeverity::Page,
        label: "fast-burn (1h/5m, 14.4x)",
    },
    BurnRateTier {
        burn_rate: 6.0,
        long_window: 6 * HOUR,
        short_window: 30 * MINUTE,
        severity: AlertSeverity::Page,
        label: "moderate-burn (6h/30m, 6x)",
    },
    BurnRateTier {
        burn_rate: 1.0,
        long_window: 3 * DAY,
        short_window: 6 * HOUR,
        severity: AlertSeverity::Ticket,
        label: "slow-burn (3d/6h, 1x)",
    },
];

/// One firing SLO alert.
#[derive(Debug, Clone, Serialize)]
pub struct SloAlert {
    /// SLO name.
    pub slo: String,
    /// Which tier fired.
    pub tier_label: String,
    /// Severity.
    pub severity: AlertSeverity,
    /// Observed long-window burn rate.
    pub long_burn_rate: f64,
    /// Observed short-window burn rate.
    pub short_burn_rate: f64,
    /// Total events in long window.
    pub long_total: u64,
    /// Total events in short window.
    pub short_total: u64,
}

/// Per-SLO evaluation (alerts + diagnostic snapshot).
#[derive(Debug, Clone, Serialize)]
pub struct SloEvaluation {
    /// SLO name.
    pub slo: String,
    /// Objective.
    pub objective: f64,
    /// Most recent long-window burn rate (Tier 1 long window).
    pub burn_rate_1h: f64,
    /// Burn rate over the full SLO window.
    pub burn_rate_full_window: f64,
    /// Fraction of budget remaining over the full SLO window.
    pub budget_remaining: f64,
    /// All firing alerts.
    pub alerts: Vec<SloAlert>,
}

/// Stateless evaluator. Holds an [`Arc`] to the TSDB it queries.
#[derive(Debug)]
pub struct MwmbrEvaluator {
    /// SLO definitions.
    pub slos: Vec<SloConfig>,
    /// Burn-rate tier set. Defaults to [`DEFAULT_TIERS`].
    pub tiers: Vec<BurnRateTier>,
}

impl MwmbrEvaluator {
    /// Construct an evaluator with the default 3-tier scheme.
    #[must_use]
    pub fn new(slos: Vec<SloConfig>) -> Self {
        Self {
            slos,
            tiers: DEFAULT_TIERS.to_vec(),
        }
    }

    /// Run one evaluation cycle against the given TSDB.
    pub fn evaluate(&self, tsdb: &Tsdb) -> Vec<SloEvaluation> {
        self.slos
            .iter()
            .map(|slo| self.evaluate_one(slo, tsdb))
            .collect()
    }

    fn evaluate_one(&self, slo: &SloConfig, tsdb: &Tsdb) -> SloEvaluation {
        let mut alerts = Vec::new();
        for tier in &self.tiers {
            let long = self.burn_rate(slo, tsdb, tier.long_window);
            let short = self.burn_rate(slo, tsdb, tier.short_window);
            if long.0 >= tier.burn_rate && short.0 >= tier.burn_rate {
                alerts.push(SloAlert {
                    slo: slo.name.clone(),
                    tier_label: tier.label.to_string(),
                    severity: tier.severity,
                    long_burn_rate: long.0,
                    short_burn_rate: short.0,
                    long_total: long.1,
                    short_total: short.1,
                });
            }
        }

        let burn_rate_1h = self.burn_rate(slo, tsdb, HOUR).0;
        let full = self.budget(slo, tsdb, slo.window.as_nanos());
        SloEvaluation {
            slo: slo.name.clone(),
            objective: slo.objective,
            burn_rate_1h,
            burn_rate_full_window: full.burn_rate(),
            budget_remaining: full.remaining_fraction(),
            alerts,
        }
    }

    /// Returns (burn_rate, total_events).
    fn burn_rate(&self, slo: &SloConfig, tsdb: &Tsdb, window_nanos: u64) -> (f64, u64) {
        let b = self.budget(slo, tsdb, window_nanos);
        (b.burn_rate(), b.total)
    }

    fn budget(&self, slo: &SloConfig, tsdb: &Tsdb, window_nanos: u64) -> ErrorBudget {
        match &slo.sli {
            Sli::SuccessRatio => match tsdb.query(&slo.model, window_nanos, 0.95) {
                Some(r) => {
                    let bad = r.total.saturating_sub(r.good);
                    ErrorBudget::new(r.total, bad, slo.objective)
                }
                None => ErrorBudget::new(0, 0, slo.objective),
            },
            Sli::LatencyThreshold { threshold_ms, .. } => {
                // For latency-threshold SLIs, "bad" is the count of events
                // whose latency exceeded the threshold. We compute this
                // from the merged digest's CDF — the correct dual of
                // quantile estimation for this query shape.
                match tsdb.query_latency_above(&slo.model, window_nanos, *threshold_ms) {
                    Some(r) => ErrorBudget::new(r.total, r.count_above, slo.objective),
                    None => ErrorBudget::new(0, 0, slo.objective),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::ingest::{InferenceEvent, Status};
    use crate::slo::definition::SloWindow;
    use crate::time::{MockClock, TimestampNanos, MINUTE, SECOND};
    use crate::tsdb::Tsdb;

    use super::*;

    fn make_db() -> (Arc<MockClock>, Tsdb) {
        let clock = Arc::new(MockClock::starting_at(TimestampNanos(0)));
        let db = Tsdb::with_clock(60 * 24 * 31, clock.clone());
        (clock, db)
    }

    fn ingest_window(db: &Tsdb, n: u64, bad_every: u64, ts_secs: u64) {
        for i in 0..n {
            let status = if bad_every > 0 && i % bad_every == 0 {
                Status::ServerError
            } else {
                Status::Success
            };
            let ev = InferenceEvent {
                timestamp: TimestampNanos(ts_secs.saturating_mul(SECOND).saturating_add(i)),
                model: "m".into(),
                model_version: "v1".into(),
                latency_ms: 100.0,
                status,
                input_tokens: None,
                output_tokens: None,
                cost_usd: None,
                metadata: Default::default(),
            };
            db.ingest(&ev);
        }
    }

    #[test]
    fn fast_burn_fires_on_sustained_failure_spike() {
        let (clock, db) = make_db();

        // Simulate 1 hour of 50% failure rate against a 0.99 objective ⇒
        // burn rate ≈ 50× — well above the 14.4× tier threshold.
        for minute in 0..70 {
            ingest_window(&db, 1000, 2, minute * 60); // half are bad
        }
        clock.advance(70 * MINUTE);

        let slo = SloConfig {
            name: "avail".into(),
            model: "m".into(),
            sli: Sli::SuccessRatio,
            objective: 0.99,
            window: SloWindow("30d".into()),
        };
        let eval = MwmbrEvaluator::new(vec![slo]);
        let result = eval.evaluate(&db);
        assert_eq!(result.len(), 1);
        let fired: Vec<_> = result[0]
            .alerts
            .iter()
            .map(|a| a.severity)
            .collect();
        assert!(
            fired.contains(&AlertSeverity::Page),
            "expected a Page alert, got {:?}",
            result[0].alerts
        );
    }

    #[test]
    fn healthy_traffic_fires_nothing() {
        let (clock, db) = make_db();
        for minute in 0..70 {
            ingest_window(&db, 1000, 0, minute * 60);
        }
        clock.advance(70 * MINUTE);

        let slo = SloConfig {
            name: "avail".into(),
            model: "m".into(),
            sli: Sli::SuccessRatio,
            objective: 0.99,
            window: SloWindow("30d".into()),
        };
        let eval = MwmbrEvaluator::new(vec![slo]);
        let result = eval.evaluate(&db);
        assert!(
            result[0].alerts.is_empty(),
            "no alerts expected on clean traffic, got {:?}",
            result[0].alerts
        );
    }

    #[test]
    fn short_window_clears_after_recovery() {
        let (clock, db) = make_db();
        // 30 minutes of bad traffic, then 30 minutes of good
        for minute in 0..30 {
            ingest_window(&db, 1000, 2, minute * 60);
        }
        for minute in 30..60 {
            ingest_window(&db, 1000, 0, minute * 60);
        }
        clock.advance(60 * MINUTE);

        let slo = SloConfig {
            name: "avail".into(),
            model: "m".into(),
            sli: Sli::SuccessRatio,
            objective: 0.99,
            window: SloWindow("30d".into()),
        };
        let eval = MwmbrEvaluator::new(vec![slo]);
        let result = eval.evaluate(&db);
        // Fast-burn requires both 1h (still dirty) AND 5m (now clean) >= 14.4.
        // The 5-minute confirmation window should be clean, so no Page alert.
        let fast_page = result[0]
            .alerts
            .iter()
            .any(|a| a.tier_label.starts_with("fast-burn"));
        assert!(
            !fast_page,
            "fast-burn page should NOT fire after recovery, got {:?}",
            result[0].alerts
        );
    }
}
