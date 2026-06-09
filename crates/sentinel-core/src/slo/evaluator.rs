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

    /// Ingest `n` events at `ts_secs` whose latency is `slow_ms` for one in
    /// every `slow_every` events and `fast_ms` otherwise. All succeed.
    fn ingest_latencies(db: &Tsdb, n: u64, fast_ms: f64, slow_ms: f64, slow_every: u64, ts_secs: u64) {
        for i in 0..n {
            let latency_ms = if slow_every > 0 && i % slow_every == 0 {
                slow_ms
            } else {
                fast_ms
            };
            let ev = InferenceEvent {
                timestamp: TimestampNanos(ts_secs.saturating_mul(SECOND).saturating_add(i)),
                model: "m".into(),
                model_version: "v1".into(),
                latency_ms,
                status: Status::Success,
                input_tokens: None,
                output_tokens: None,
                cost_usd: None,
                metadata: Default::default(),
            };
            db.ingest(&ev);
        }
    }

    fn latency_slo(objective: f64, threshold_ms: f64) -> SloConfig {
        SloConfig {
            name: "p95-latency".into(),
            model: "m".into(),
            sli: Sli::LatencyThreshold {
                quantile: 0.95,
                threshold_ms,
            },
            objective,
            window: SloWindow("30d".into()),
        }
    }

    #[test]
    fn latency_threshold_sli_fires_on_slow_tail() {
        let (clock, db) = make_db();
        // Half of all events are 10x slower than the 200ms threshold, against
        // a 0.99 objective ⇒ burn ≈ 50x, well above every tier.
        for minute in 0..70 {
            ingest_latencies(&db, 1000, 50.0, 2000.0, 2, minute * 60);
        }
        clock.advance(70 * MINUTE);

        let eval = MwmbrEvaluator::new(vec![latency_slo(0.99, 200.0)]);
        let result = eval.evaluate(&db);
        assert_eq!(result.len(), 1);
        assert!(
            result[0].alerts.iter().any(|a| a.severity == AlertSeverity::Page),
            "expected a Page alert from the latency SLI, got {:?}",
            result[0].alerts
        );
        assert!(
            result[0].burn_rate_1h > 14.4,
            "expected fast burn, got {}",
            result[0].burn_rate_1h
        );
    }

    #[test]
    fn latency_threshold_sli_quiet_when_under_threshold() {
        let (clock, db) = make_db();
        // Everything is far below the threshold ⇒ zero bad events.
        for minute in 0..70 {
            ingest_latencies(&db, 1000, 50.0, 50.0, 0, minute * 60);
        }
        clock.advance(70 * MINUTE);

        let eval = MwmbrEvaluator::new(vec![latency_slo(0.99, 500.0)]);
        let result = eval.evaluate(&db);
        assert!(
            result[0].alerts.is_empty(),
            "no alerts expected when all latencies are below threshold, got {:?}",
            result[0].alerts
        );
    }

    #[test]
    fn latency_threshold_sli_for_unknown_model_is_quiet() {
        let (_clock, db) = make_db();
        let mut slo = latency_slo(0.99, 200.0);
        slo.model = "does-not-exist".into();
        let eval = MwmbrEvaluator::new(vec![slo]);
        let result = eval.evaluate(&db);
        assert!(result[0].alerts.is_empty());
        assert_eq!(result[0].burn_rate_1h, 0.0);
    }

    #[test]
    fn moderate_sustained_burn_fires_ticket_not_page() {
        let (clock, db) = make_db();
        // 2.5% failure against a 0.99 objective ⇒ burn 2.5x: above the
        // slow-burn 1x tier, below moderate (6x) and fast (14.4x) tiers.
        for minute in 0..70 {
            ingest_window(&db, 1000, 40, minute * 60);
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
        let severities: Vec<_> = result[0].alerts.iter().map(|a| a.severity).collect();
        assert!(
            severities.contains(&AlertSeverity::Ticket),
            "expected a Ticket alert at 2.5x burn, got {:?}",
            result[0].alerts
        );
        assert!(
            !severities.contains(&AlertSeverity::Page),
            "2.5x burn must not page, got {:?}",
            result[0].alerts
        );
    }

    #[test]
    fn evaluation_reports_budget_diagnostics() {
        let (clock, db) = make_db();
        // 2% failure against 0.99 ⇒ full-window burn 2.0, budget fully
        // consumed twice over ⇒ remaining = 1 - 2.0 = -1.0.
        for minute in 0..70 {
            ingest_window(&db, 1000, 50, minute * 60);
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
        let e = &result[0];
        assert!((e.objective - 0.99).abs() < 1e-9);
        assert!(
            (e.burn_rate_full_window - 2.0).abs() < 0.1,
            "expected ~2.0 full-window burn, got {}",
            e.burn_rate_full_window
        );
        assert!(
            (e.budget_remaining - (-1.0)).abs() < 0.2,
            "expected ~-1.0 budget remaining, got {}",
            e.budget_remaining
        );
        // Alert diagnostics carry the event totals they were computed from.
        for a in &e.alerts {
            assert!(a.long_total > 0);
            assert!(a.short_total > 0);
        }
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
