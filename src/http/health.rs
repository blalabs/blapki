//! Health check.

use axum::extract::State;
use axum::Json;
use serde_json::json;

use crate::http::Shared;

/// Liveness/readiness probe: reports the configured CAs and profiles.
pub async fn health(State(state): State<Shared>) -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "cas": state.cas.keys().collect::<Vec<_>>(),
        "profiles": state.profiles.keys().collect::<Vec<_>>(),
    }))
}
