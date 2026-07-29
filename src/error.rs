//! Application error type and HTTP mapping.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

/// Top-level error type for the whole application.
///
/// SCEP has its own in-band failure signalling (a signed `CertRep` with
/// `pkiStatus = FAILURE`), so most SCEP-protocol problems are *not* represented
/// here; they are turned into a failure response by the SCEP layer. `AppError`
/// is for transport/config/infrastructure failures that should surface as an
/// HTTP error instead.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("upstream (Intune) error: {0}")]
    Upstream(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl AppError {
    pub fn crypto(msg: impl Into<String>) -> Self {
        Self::Crypto(msg.into())
    }

    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self::BadRequest(msg.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::Config(_) | AppError::Crypto(_) | AppError::Database(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            AppError::Upstream(_) => StatusCode::BAD_GATEWAY,
            AppError::Other(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };
        // Log the full error; return a terse message to the client.
        tracing::error!(error = %self, "request failed");
        (status, self.to_string()).into_response()
    }
}

pub type AppResult<T> = std::result::Result<T, AppError>;
