//! Health check.

use axum::extract::State;
use axum::http::StatusCode;
use axum::Json;
use serde_json::json;

use crate::http::Shared;

/// Liveness/readiness probe. Reports only whether the server can reach its
/// database; it is unauthenticated, so it does not describe the configuration
/// (CA ids, profile names).
pub async fn health(State(state): State<Shared>) -> (StatusCode, Json<serde_json::Value>) {
    match sqlx::query("SELECT 1").execute(&state.db).await {
        Ok(_) => (StatusCode::OK, Json(json!({ "status": "ok" }))),
        Err(e) => {
            tracing::error!(error = %e, "health check: database unavailable");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unavailable" })),
            )
        }
    }
}
