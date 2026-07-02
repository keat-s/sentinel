//! Local HTTP control API for listing and resolving approvals.
//!
//! Binds to loopback by default. This is the surface the `sentinel-gateway
//! approvals` CLI (and the Slack message's curl one-liners) talk to.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::json;

use super::Broker;

#[derive(Debug, Deserialize, Default)]
pub struct ResolveBody {
    /// Free-form identity of the approver, recorded in the audit log.
    pub by: Option<String>,
}

/// Bind the control API and serve it on a background task. Returns the
/// actual bound address (useful with port 0).
pub async fn start(listen: &str, broker: Arc<Broker>) -> anyhow::Result<SocketAddr> {
    let listener = tokio::net::TcpListener::bind(listen).await?;
    let addr = listener.local_addr()?;
    let app = router(broker);
    tokio::spawn(async move {
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!("control API server error: {e}");
        }
    });
    Ok(addr)
}

fn router(broker: Arc<Broker>) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/v1/approvals", get(list))
        .route("/v1/approvals/:id/approve", post(approve))
        .route("/v1/approvals/:id/deny", post(deny))
        .with_state(broker)
}

async fn list(State(broker): State<Arc<Broker>>) -> Json<serde_json::Value> {
    Json(json!({ "approvals": broker.list() }))
}

async fn approve(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    body: Option<Json<ResolveBody>>,
) -> (StatusCode, Json<serde_json::Value>) {
    resolve(&broker, &id, true, body)
}

async fn deny(
    State(broker): State<Arc<Broker>>,
    Path(id): Path<String>,
    body: Option<Json<ResolveBody>>,
) -> (StatusCode, Json<serde_json::Value>) {
    resolve(&broker, &id, false, body)
}

fn resolve(
    broker: &Broker,
    id: &str,
    approved: bool,
    body: Option<Json<ResolveBody>>,
) -> (StatusCode, Json<serde_json::Value>) {
    let by = body.and_then(|Json(b)| b.by);
    if broker.resolve(id, approved, by) {
        (
            StatusCode::OK,
            Json(json!({ "id": id, "resolved": if approved { "approved" } else { "denied" } })),
        )
    } else {
        (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": format!("no pending approval `{id}`") })),
        )
    }
}
