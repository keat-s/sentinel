//! `sentinel serve` — HTTP API.
//!
//! Exposes:
//! - `POST /v1/ingest`  — body: `InferenceEvent` JSON
//! - `POST /v1/ingest/batch` — body: `Vec<InferenceEvent>`
//! - `GET  /v1/query`   — query: `model`, `window`, `quantile`
//! - `GET  /v1/slos`    — current SLO evaluations + firing alerts
//! - `GET  /v1/anomalies` — recent anomalies (in-memory ring)
//! - `POST /v1/incidents/summarize` — uses configured Summarizer
//! - `GET  /v1/healthz` — liveness

use std::collections::VecDeque;
use std::sync::Arc;

use std::time::Duration;

use anyhow::Context;
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use clap::Args as ClapArgs;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use tower::ServiceBuilder;
use tower_http::timeout::TimeoutLayer;
use tracing::{info, instrument, warn};

use sentinel_core::ai::{IncidentContext, NoopSummarizer, OpenAiSummarizer, Summarizer};
use sentinel_core::anomaly::{Anomaly, DetectorRegistry, ZScoreDetector};
use sentinel_core::ingest::InferenceEvent;
use sentinel_core::slo::{MwmbrEvaluator, SloEvaluation};
use sentinel_core::time::SECOND;
use sentinel_core::tsdb::{SeriesKey, Tsdb, Wal};

use crate::config::ServerConfig;

/// `sentinel serve` arguments.
#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Path to the YAML config (optional).
    #[arg(long, default_value = "")]
    pub config: String,
}

/// Application state shared across handlers.
struct AppState {
    tsdb: Arc<Tsdb>,
    evaluator: Arc<RwLock<MwmbrEvaluator>>,
    last_evaluation: Arc<RwLock<Vec<SloEvaluation>>>,
    anomalies: Arc<RwLock<VecDeque<Anomaly>>>,
    detectors: Arc<DetectorRegistry>,
    summarizer: Arc<dyn Summarizer>,
    wal: Option<Arc<parking_lot::Mutex<Wal>>>,
}

const ANOMALY_RING_CAP: usize = 256;
const MAX_INGEST_BODY_BYTES: usize = 1 << 20; // 1 MiB
const MAX_BATCH_SIZE: usize = 1000;
const REQUEST_TIMEOUT_SECS: u64 = 10;

/// Entrypoint for `sentinel serve`.
pub async fn run(args: Args) -> anyhow::Result<()> {
    let cfg = ServerConfig::from_yaml_path(&args.config)
        .with_context(|| format!("loading config from {:?}", args.config))?;

    let tsdb = Arc::new(Tsdb::new(cfg.retention_minutes));

    let wal = if cfg.wal_path.is_empty() {
        None
    } else {
        info!(path = %cfg.wal_path, "opening WAL");
        // Replay first.
        if std::path::Path::new(&cfg.wal_path).exists() {
            let reader = sentinel_core::tsdb::WalReader::open(&cfg.wal_path)?;
            let mut replayed = 0u64;
            for ev in reader {
                match ev {
                    Ok(e) => {
                        tsdb.ingest(&e);
                        replayed += 1;
                    }
                    Err(e) => {
                        warn!(error = %e, "wal replay stopped at corrupt record");
                        break;
                    }
                }
            }
            info!(replayed, "wal replay complete");
        }
        let wal = Wal::open(&cfg.wal_path)?;
        Some(Arc::new(parking_lot::Mutex::new(wal)))
    };

    let evaluator = Arc::new(RwLock::new(MwmbrEvaluator::new(cfg.slos.clone())));
    let last_evaluation: Arc<RwLock<Vec<SloEvaluation>>> = Arc::new(RwLock::new(Vec::new()));

    let detectors = Arc::new(DetectorRegistry::new());
    // Auto-register a z-score detector on latency for each known model from the config.
    for slo in &cfg.slos {
        let key = SeriesKey::new("inference", [("model", slo.model.as_str())]);
        detectors.register(key.id(), ZScoreDetector::new(key.id(), 0.05, 4.0, 60));
    }

    let summarizer: Arc<dyn Summarizer> = match OpenAiSummarizer::from_env() {
        Some(s) => {
            info!("LLM summarizer configured");
            Arc::new(s)
        }
        None => {
            info!("no LLM key; using deterministic summarizer fallback");
            Arc::new(NoopSummarizer)
        }
    };

    let state = Arc::new(AppState {
        tsdb: tsdb.clone(),
        evaluator: evaluator.clone(),
        last_evaluation: last_evaluation.clone(),
        anomalies: Arc::new(RwLock::new(VecDeque::with_capacity(ANOMALY_RING_CAP))),
        detectors,
        summarizer,
        wal,
    });

    // Background SLO evaluator
    {
        let state = state.clone();
        let interval = std::time::Duration::from_secs(cfg.eval_interval_secs.max(1));
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            loop {
                ticker.tick().await;
                let evals = state.evaluator.read().evaluate(&state.tsdb);
                let fired: usize = evals.iter().map(|e| e.alerts.len()).sum();
                if fired > 0 {
                    warn!(fired, "SLO alerts firing");
                }
                *state.last_evaluation.write() = evals;
            }
        });
    }

    // Background WAL flusher
    if let Some(wal) = state.wal.clone() {
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(std::time::Duration::from_millis(200));
            loop {
                ticker.tick().await;
                if let Err(e) = wal.lock().flush() {
                    warn!(error = %e, "wal flush failed");
                }
            }
        });
    }

    let app = build_router(state.clone());
    let listener = tokio::net::TcpListener::bind(&cfg.listen).await?;
    info!(addr = %cfg.listen, "sentinel listening");
    axum::serve(listener, app).await?;
    Ok(())
}

fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/healthz", get(healthz))
        .route("/v1/ingest", post(ingest_one))
        .route("/v1/ingest/batch", post(ingest_batch))
        .route("/v1/query", get(query_handler))
        .route("/v1/slos", get(slos_handler))
        .route("/v1/anomalies", get(anomalies_handler))
        .route("/v1/incidents/summarize", post(summarize_handler))
        // Hard request-body cap + per-request timeout. Without these,
        // an unauthenticated peer on the listener network could fan out
        // many slow large bodies and exhaust the runtime.
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(MAX_INGEST_BODY_BYTES))
                .layer(TimeoutLayer::with_status_code(
                    StatusCode::SERVICE_UNAVAILABLE,
                    Duration::from_secs(REQUEST_TIMEOUT_SECS),
                )),
        )
        .with_state(state)
}

async fn healthz() -> &'static str {
    "ok"
}

#[instrument(skip(state, event), fields(model = %event.model))]
async fn ingest_one(
    State(state): State<Arc<AppState>>,
    Json(event): Json<InferenceEvent>,
) -> impl IntoResponse {
    do_ingest(&state, &event);
    StatusCode::ACCEPTED
}

async fn ingest_batch(
    State(state): State<Arc<AppState>>,
    Json(events): Json<Vec<InferenceEvent>>,
) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    if events.len() > MAX_BATCH_SIZE {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "batch size {} exceeds limit {}",
                events.len(),
                MAX_BATCH_SIZE
            ),
        ));
    }
    let n = events.len();
    for ev in &events {
        do_ingest(&state, ev);
    }
    Ok((StatusCode::ACCEPTED, Json(serde_json::json!({ "ingested": n }))))
}

fn do_ingest(state: &AppState, event: &InferenceEvent) {
    state.tsdb.ingest(event);

    // Feed latency into per-series anomaly detectors.
    let series = SeriesKey::new("inference", [("model", event.model.as_str())]).id();
    let anomalies = state.detectors.observe(series, event.timestamp, event.latency_ms);
    if !anomalies.is_empty() {
        let mut ring = state.anomalies.write();
        for a in anomalies {
            if ring.len() >= ANOMALY_RING_CAP {
                ring.pop_front();
            }
            ring.push_back(a);
        }
    }

    if let Some(wal) = &state.wal {
        if let Err(e) = wal.lock().append(event) {
            warn!(error = %e, "wal append failed");
        }
    }
}

#[derive(Debug, Deserialize)]
struct QueryParams {
    model: String,
    #[serde(default = "default_window")]
    window: String,
    #[serde(default = "default_quantile")]
    quantile: f64,
}

fn default_window() -> String {
    "1h".to_string()
}
fn default_quantile() -> f64 {
    0.95
}

#[derive(Debug, Serialize)]
struct QueryResponse {
    model: String,
    window: String,
    quantile: f64,
    total: u64,
    good: u64,
    server_failures: u64,
    success_ratio: f64,
    latency_quantile_ms: f64,
    model_version_cardinality: u64,
}

async fn query_handler(
    State(state): State<Arc<AppState>>,
    Query(p): Query<QueryParams>,
) -> Result<Json<QueryResponse>, (StatusCode, String)> {
    let window_nanos = parse_duration(&p.window).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid duration {:?}", p.window),
        )
    })?;
    let result = state
        .tsdb
        .query(&p.model, window_nanos, p.quantile)
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("unknown model {:?}", p.model)))?;
    Ok(Json(QueryResponse {
        model: p.model,
        window: p.window,
        quantile: p.quantile,
        total: result.total,
        good: result.good,
        server_failures: result.server_failures,
        success_ratio: result.success_ratio,
        latency_quantile_ms: result.latency_quantile_ms,
        model_version_cardinality: result.model_version_cardinality,
    }))
}

async fn slos_handler(State(state): State<Arc<AppState>>) -> Json<Vec<SloEvaluation>> {
    Json(state.last_evaluation.read().clone())
}

async fn anomalies_handler(State(state): State<Arc<AppState>>) -> Json<Vec<Anomaly>> {
    Json(state.anomalies.read().iter().cloned().collect())
}

#[derive(Debug, Deserialize)]
struct SummarizeBody {
    title: Option<String>,
    notes: Option<Vec<String>>,
}

async fn summarize_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<SummarizeBody>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let evals = state.last_evaluation.read().clone();
    let mut alerts = Vec::new();
    for e in &evals {
        alerts.extend(e.alerts.clone());
    }
    let anomalies: Vec<Anomaly> = state.anomalies.read().iter().cloned().collect();
    let ctx = IncidentContext {
        title: body.title,
        alerts,
        anomalies,
        notes: body.notes.unwrap_or_default(),
    };
    let summary = state
        .summarizer
        .summarize(&ctx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::json!({ "summary": summary })))
}

/// Parse durations like `"30s"`, `"5m"`, `"6h"`, `"3d"`.
///
/// Uses checked multiplication — pathological inputs like
/// `"18446744073709551615d"` are rejected, not wrapped.
fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.len() < 2 {
        return None;
    }
    let (num, unit) = s.split_at(s.len() - 1);
    let n: u64 = num.parse().ok()?;
    let mul = match unit {
        "s" => SECOND,
        "m" => 60 * SECOND,
        "h" => 3600 * SECOND,
        "d" => 86400 * SECOND,
        _ => return None,
    };
    n.checked_mul(mul)
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::Request;
    use sentinel_core::ingest::Status;
    use sentinel_core::time::TimestampNanos;
    use sentinel_core::tsdb::Tsdb;
    use tower::ServiceExt;

    // --- parse_duration ----------------------------------------------------

    #[test]
    fn parse_duration_accepts_all_units() {
        assert_eq!(parse_duration("30s"), Some(30 * SECOND));
        assert_eq!(parse_duration("5m"), Some(5 * 60 * SECOND));
        assert_eq!(parse_duration("6h"), Some(6 * 3600 * SECOND));
        assert_eq!(parse_duration("3d"), Some(3 * 86400 * SECOND));
    }

    #[test]
    fn parse_duration_trims_whitespace() {
        assert_eq!(parse_duration("  1h "), Some(3600 * SECOND));
    }

    #[test]
    fn parse_duration_rejects_invalid_input() {
        assert_eq!(parse_duration(""), None);
        assert_eq!(parse_duration("5"), None, "missing unit");
        assert_eq!(parse_duration("h"), None, "missing number");
        assert_eq!(parse_duration("5x"), None, "unknown unit");
        assert_eq!(parse_duration("-5m"), None, "negative");
        assert_eq!(parse_duration("1.5h"), None, "fractional");
        assert_eq!(parse_duration("5 m"), None, "inner whitespace");
    }

    #[test]
    fn parse_duration_rejects_overflow_instead_of_wrapping() {
        let huge = format!("{}d", u64::MAX);
        assert_eq!(parse_duration(&huge), None);
        // Largest value that fits stays accepted.
        assert!(parse_duration("1d").is_some());
    }

    // --- HTTP handlers (in-process, no socket) ------------------------------

    fn test_state() -> Arc<AppState> {
        Arc::new(AppState {
            tsdb: Arc::new(Tsdb::new(60 * 24)),
            evaluator: Arc::new(RwLock::new(MwmbrEvaluator::new(Vec::new()))),
            last_evaluation: Arc::new(RwLock::new(Vec::new())),
            anomalies: Arc::new(RwLock::new(VecDeque::new())),
            detectors: Arc::new(DetectorRegistry::new()),
            summarizer: Arc::new(NoopSummarizer),
            wal: None,
        })
    }

    fn event_json(model: &str, status: Status, latency_ms: f64) -> serde_json::Value {
        serde_json::json!({
            "timestamp": TimestampNanos::now(),
            "model": model,
            "model_version": "v1",
            "latency_ms": latency_ms,
            "status": status,
        })
    }

    async fn body_json(resp: axum::response::Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn healthz_returns_ok() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/v1/healthz").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn ingest_then_query_roundtrip() {
        let state = test_state();
        let app = build_router(state.clone());

        for i in 0..10 {
            let status = if i == 0 { Status::ServerError } else { Status::Success };
            let req = Request::post("/v1/ingest")
                .header("content-type", "application/json")
                .body(Body::from(event_json("gpt-4o", status, 100.0).to_string()))
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::ACCEPTED);
        }

        let resp = app
            .oneshot(
                Request::get("/v1/query?model=gpt-4o&window=1h&quantile=0.5")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json["total"], 10);
        assert_eq!(json["good"], 9);
        assert_eq!(json["server_failures"], 1);
    }

    #[tokio::test]
    async fn query_with_invalid_window_is_bad_request() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::get("/v1/query?model=m&window=fortnight")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn query_unknown_model_is_not_found() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::get("/v1/query?model=missing&window=1h")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn batch_ingest_accepts_and_counts() {
        let app = build_router(test_state());
        let batch: Vec<_> = (0..5)
            .map(|_| event_json("m", Status::Success, 50.0))
            .collect();
        let resp = app
            .oneshot(
                Request::post("/v1/ingest/batch")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&batch).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);
        let json = body_json(resp).await;
        assert_eq!(json["ingested"], 5);
    }

    #[tokio::test]
    async fn oversized_batch_is_rejected() {
        let app = build_router(test_state());
        let batch: Vec<_> = (0..MAX_BATCH_SIZE + 1)
            .map(|_| event_json("m", Status::Success, 1.0))
            .collect();
        let resp = app
            .oneshot(
                Request::post("/v1/ingest/batch")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_string(&batch).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_by_limit_layer() {
        let app = build_router(test_state());
        let big = vec![b'x'; MAX_INGEST_BODY_BYTES + 1];
        let resp = app
            .oneshot(
                Request::post("/v1/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from(big))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn malformed_ingest_json_is_client_error() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::post("/v1/ingest")
                    .header("content-type", "application/json")
                    .body(Body::from("{not json"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert!(
            resp.status().is_client_error(),
            "expected 4xx, got {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn anomalies_endpoint_returns_empty_ring() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(Request::get("/v1/anomalies").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        assert_eq!(json, serde_json::json!([]));
    }

    #[tokio::test]
    async fn summarize_uses_fallback_summarizer() {
        let app = build_router(test_state());
        let resp = app
            .oneshot(
                Request::post("/v1/incidents/summarize")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "title": "DB outage",
                            "notes": ["replica lag spiked"]
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = body_json(resp).await;
        let summary = json["summary"].as_str().unwrap();
        assert!(summary.contains("DB outage"));
        assert!(summary.contains("replica lag spiked"));
    }

    #[tokio::test]
    async fn ingest_feeds_registered_anomaly_detectors() {
        use sentinel_core::anomaly::ZScoreDetector;
        use sentinel_core::tsdb::SeriesKey;

        let state = test_state();
        let series = SeriesKey::new("inference", [("model", "m")]).id();
        state
            .detectors
            .register(series, ZScoreDetector::new(series, 0.1, 3.0, 30));
        let app = build_router(state.clone());

        // Flat baseline, then one large spike.
        for i in 0..100 {
            let latency = if i == 99 { 10_000.0 } else { 50.0 + (i % 3) as f64 };
            let req = Request::post("/v1/ingest")
                .header("content-type", "application/json")
                .body(Body::from(event_json("m", Status::Success, latency).to_string()))
                .unwrap();
            app.clone().oneshot(req).await.unwrap();
        }

        let resp = app
            .oneshot(Request::get("/v1/anomalies").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let json = body_json(resp).await;
        let list = json.as_array().unwrap();
        assert!(!list.is_empty(), "the latency spike should be in the ring");
        assert_eq!(list[0]["source"], "zscore");
    }
}
