//! End-to-end integration test: synthetic burst → SLO Page alert fires.
//!
//! Exercises the same pipeline a real `sentinel serve` would:
//! ingest → TSDB → MWMBR evaluator → alert.

use std::sync::Arc;

use sentinel_core::ingest::{InferenceEvent, Status};
use sentinel_core::slo::{
    AlertSeverity, MwmbrEvaluator, Sli, SloConfig, SloWindow,
};
use sentinel_core::time::{MockClock, TimestampNanos, MINUTE, SECOND};
use sentinel_core::tsdb::Tsdb;

fn event(model: &str, status: Status, latency_ms: f64, ts_ns: u64) -> InferenceEvent {
    InferenceEvent {
        timestamp: TimestampNanos(ts_ns),
        model: model.to_string(),
        model_version: "v1".to_string(),
        latency_ms,
        status,
        input_tokens: None,
        output_tokens: None,
        cost_usd: None,
        metadata: Default::default(),
    }
}

#[test]
fn burst_then_query_then_alert() {
    let clock = Arc::new(MockClock::starting_at(TimestampNanos(0)));
    let db = Tsdb::with_clock(60 * 24 * 31, clock.clone());

    // 70 minutes of moderate traffic with bursts of failure mixed in.
    // Burst windows are [10..20m] and [40..50m], 60% failure inside; baseline
    // is 0.1% failure. This is well above the 14.4x burn rate threshold during
    // bursts.
    for minute in 0u64..70 {
        let in_burst = (10..20).contains(&minute) || (40..50).contains(&minute);
        for i in 0..2000u64 {
            let ts = (minute * 60).saturating_mul(SECOND).saturating_add(i);
            let status = if in_burst {
                if i % 5 == 0 {
                    Status::Success
                } else {
                    Status::ServerError
                }
            } else if i % 1000 == 0 {
                Status::ServerError
            } else {
                Status::Success
            };
            db.ingest(&event("gpt-4o", status, 120.0, ts));
        }
    }
    clock.advance(70 * MINUTE);

    let slo = SloConfig {
        name: "availability".to_string(),
        model: "gpt-4o".to_string(),
        sli: Sli::SuccessRatio,
        objective: 0.99,
        window: SloWindow("30d".to_string()),
    };
    let eval = MwmbrEvaluator::new(vec![slo]);
    let result = eval.evaluate(&db);
    assert_eq!(result.len(), 1);

    let evaluation = &result[0];
    assert_eq!(evaluation.slo, "availability");

    // Burn rate over the 1h long window should be very high right now,
    // because the second burst (40-50m) ended only 20m ago.
    assert!(
        evaluation.burn_rate_1h > 6.0,
        "expected burn_rate_1h > 6, got {}",
        evaluation.burn_rate_1h
    );

    // Some Page-severity alert should be firing.
    let pages = evaluation
        .alerts
        .iter()
        .filter(|a| a.severity == AlertSeverity::Page)
        .count();
    assert!(
        pages >= 1,
        "expected at least one Page alert, got {:?}",
        evaluation.alerts
    );
}

#[test]
fn empty_db_produces_no_alerts() {
    let db = Tsdb::new(60);
    let slo = SloConfig {
        name: "noop".to_string(),
        model: "x".to_string(),
        sli: Sli::SuccessRatio,
        objective: 0.999,
        window: SloWindow("7d".to_string()),
    };
    let eval = MwmbrEvaluator::new(vec![slo]);
    let result = eval.evaluate(&db);
    assert!(result[0].alerts.is_empty());
    assert_eq!(result[0].burn_rate_1h, 0.0);
}
