//! HTTP surface: SCEP, OCSP, CRL and health endpoints.

pub mod crl;
pub mod health;
pub mod ocsp;
pub mod scep;

use std::collections::HashMap;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use sqlx::AnyPool;
use tower_http::trace::TraceLayer;

use crate::ca::CertificateAuthority;
use crate::challenge::ChallengeValidator;

/// Per-profile runtime state assembled from config.
pub struct ProfileRuntime {
    pub name: String,
    pub ca_id: String,
    pub validator: Arc<dyn ChallengeValidator>,
    pub validity_days: u32,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
}

/// Shared application state.
pub struct AppState {
    pub cas: HashMap<String, Arc<CertificateAuthority>>,
    pub profiles: HashMap<String, ProfileRuntime>,
    pub db: AnyPool,
    /// Externally reachable base URL (used to build AIA/CDP URLs).
    pub base_url: String,
}

pub type Shared = Arc<AppState>;

impl AppState {
    pub fn ca_for_profile(&self, profile: &str) -> Option<&Arc<CertificateAuthority>> {
        let rt = self.profiles.get(profile)?;
        self.cas.get(&rt.ca_id)
    }

    /// OCSP responder URL for a CA.
    pub fn ocsp_url(&self, ca_id: &str) -> String {
        format!("{}/ocsp/{}", self.base_url.trim_end_matches('/'), ca_id)
    }

    /// CRL URL for a CA.
    pub fn crl_url(&self, ca_id: &str) -> String {
        format!("{}/crl/{}", self.base_url.trim_end_matches('/'), ca_id)
    }
}

/// Build the axum router.
pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/health", get(health::health))
        // SCEP: Windows/Intune append /pkiclient.exe; both map to the same
        // GET (GetCACaps/GetCACert/PKIOperation) and POST (PKIOperation).
        .route("/scep/{profile}", get(scep::scep_get).post(scep::scep_post))
        .route(
            "/scep/{profile}/pkiclient.exe",
            get(scep::scep_get).post(scep::scep_post),
        )
        // OCSP: POST a request body, or GET with the base64 request in the path.
        .route("/ocsp/{ca}", get(ocsp::ocsp_get_root).post(ocsp::ocsp_post))
        .route("/ocsp/{ca}/{b64}", get(ocsp::ocsp_get))
        .route("/crl/{ca}", get(crl::crl))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
