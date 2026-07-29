//! Microsoft Intune SCEP validation client.
//!
//! Implements the same flow as Microsoft's `IntuneScepServiceClient` and
//! PacketFence's `pfpki`:
//!   1. acquire an AAD token (client credentials) for Microsoft Graph,
//!   2. discover the `ScepRequestValidationFEService` endpoint via
//!      `servicePrincipals/appId=<intune>/endpoints`,
//!   3. acquire an AAD token for the Intune API,
//!   4. POST to `{endpoint}/ScepActions/{validateRequest,successNotification,
//!      failureNotification}` with `api-version: 2018-02-20`.
//!
//! Requires an Entra app with the `Microsoft Intune API / SCEP challenge
//! validation` and `Application.Read.All` permissions.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use tokio::sync::RwLock;

use crate::config::IntuneConfig;
use crate::error::{AppError, AppResult};

const INTUNE_APP_ID: &str = "0000000a-0000-0000-c000-000000000000";
const GRAPH_RESOURCE: &str = "https://graph.microsoft.com/";
const GRAPH_API_VERSION: &str = "1.0";
const SCEP_SERVICE_VERSION: &str = "2018-02-20";
const VALIDATION_SERVICE_NAME: &str = "ScepRequestValidationFEService";
const CALLER_INFO: &str = "blapki";

const VALIDATE_PATH: &str = "ScepActions/validateRequest";
const SUCCESS_PATH: &str = "ScepActions/successNotification";
const FAILURE_PATH: &str = "ScepActions/failureNotification";

struct CachedToken {
    value: String,
    expires_at: Instant,
}

/// Details of an issued certificate needed for Intune notifications.
pub struct IssuedInfo {
    pub thumbprint_sha1: String,
    pub serial_decimal: String,
    pub not_after_utc: String,
    pub issuer_cn: String,
}

/// Client for the Intune SCEP validation API.
pub struct IntuneClient {
    http: reqwest::Client,
    tenant_id: String,
    client_id: String,
    client_secret: String,
    login_host: String,
    intune_resource: String,
    tokens: RwLock<HashMap<String, CachedToken>>,
    validation_uri: RwLock<Option<String>>,
}

impl IntuneClient {
    pub fn new(cfg: &IntuneConfig, client_secret: String) -> Self {
        Self {
            http: reqwest::Client::new(),
            tenant_id: cfg.tenant_id.clone(),
            client_id: cfg.client_id.clone(),
            client_secret,
            login_host: cfg.login_host.trim_end_matches('/').to_string(),
            intune_resource: cfg.resource.clone(),
            tokens: RwLock::new(HashMap::new()),
            validation_uri: RwLock::new(None),
        }
    }

    /// Validate a SCEP request against Intune. Returns `Ok` only if Intune
    /// approves the challenge; any other outcome is an error.
    pub async fn validate_request(&self, transaction_id: &str, csr_der: &[u8]) -> AppResult<()> {
        let uri = self.validation_endpoint(transaction_id).await?;
        let body = json!({
            "request": {
                "transactionId": transaction_id,
                "certificateRequest": b64(csr_der),
                "callerInfo": CALLER_INFO,
            }
        });
        let resp: ValidateResponse = self
            .post_intune(&format!("{uri}/{VALIDATE_PATH}"), transaction_id, &body)
            .await?;
        match resp.code.as_deref() {
            Some("Success") => Ok(()),
            Some(code) => Err(AppError::Upstream(format!(
                "Intune rejected the request: {code}{}",
                resp.error_description
                    .map(|d| format!(" ({d})"))
                    .unwrap_or_default()
            ))),
            None => Err(AppError::Upstream(
                "Intune returned no status code".to_string(),
            )),
        }
    }

    /// Notify Intune that a certificate was issued.
    pub async fn success_notification(
        &self,
        transaction_id: &str,
        csr_der: &[u8],
        info: &IssuedInfo,
    ) -> AppResult<()> {
        let uri = self.validation_endpoint(transaction_id).await?;
        let body = json!({
            "notification": {
                "transactionId": transaction_id,
                "certificateRequest": b64(csr_der),
                "certificateThumbprint": info.thumbprint_sha1,
                "certificateSerialNumber": info.serial_decimal,
                "certificateExpirationDateUtc": info.not_after_utc,
                "issuingCertificateAuthority": info.issuer_cn,
                "callerInfo": CALLER_INFO,
            }
        });
        let _: serde_json::Value = self
            .post_intune(&format!("{uri}/{SUCCESS_PATH}"), transaction_id, &body)
            .await?;
        Ok(())
    }

    /// Notify Intune that processing a request failed.
    pub async fn failure_notification(
        &self,
        transaction_id: &str,
        csr_der: &[u8],
        hresult: i64,
        message: &str,
    ) -> AppResult<()> {
        let uri = self.validation_endpoint(transaction_id).await?;
        let body = json!({
            "notification": {
                "transactionId": transaction_id,
                "certificateRequest": b64(csr_der),
                "hResult": hresult,
                "errorDescription": message.chars().take(255).collect::<String>(),
                "callerInfo": CALLER_INFO,
            }
        });
        let _: serde_json::Value = self
            .post_intune(&format!("{uri}/{FAILURE_PATH}"), transaction_id, &body)
            .await?;
        Ok(())
    }

    /// Discover (and cache) the SCEP validation service endpoint URI.
    async fn validation_endpoint(&self, transaction_id: &str) -> AppResult<String> {
        if let Some(uri) = self.validation_uri.read().await.clone() {
            return Ok(uri);
        }
        let token = self.token(&format!("{GRAPH_RESOURCE}.default")).await?;
        let url = format!(
            "{GRAPH_RESOURCE}v{GRAPH_API_VERSION}/servicePrincipals/appId={INTUNE_APP_ID}/endpoints"
        );
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&token)
            .header("api-version", GRAPH_API_VERSION)
            .header("client-request-id", transaction_id)
            .send()
            .await
            .map_err(|e| AppError::Upstream(format!("Graph endpoint discovery failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(AppError::Upstream(format!(
                "Graph endpoint discovery returned HTTP {}",
                resp.status()
            )));
        }
        let parsed: EndpointsResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Upstream(format!("bad Graph endpoints response: {e}")))?;
        let uri = parsed
            .value
            .into_iter()
            .find(|e| e.provider_name.as_deref() == Some(VALIDATION_SERVICE_NAME))
            .and_then(|e| e.uri)
            .ok_or_else(|| {
                AppError::Upstream(format!("Graph did not return a {VALIDATION_SERVICE_NAME}"))
            })?;
        let uri = uri.trim_end_matches('/').to_string();
        *self.validation_uri.write().await = Some(uri.clone());
        Ok(uri)
    }

    async fn post_intune<T: for<'de> Deserialize<'de>>(
        &self,
        url: &str,
        transaction_id: &str,
        body: &serde_json::Value,
    ) -> AppResult<T> {
        let token = self
            .token(&format!("{}.default", self.intune_resource))
            .await?;
        let resp = self
            .http
            .post(url)
            .bearer_auth(&token)
            .header("api-version", SCEP_SERVICE_VERSION)
            .header("client-request-id", transaction_id)
            .header("Accept", "application/json")
            .json(body)
            .send()
            .await
            .map_err(|e| AppError::Upstream(format!("Intune request failed: {e}")))?;
        if !resp.status().is_success() {
            return Err(AppError::Upstream(format!(
                "Intune returned HTTP {}",
                resp.status()
            )));
        }
        resp.json::<T>()
            .await
            .map_err(|e| AppError::Upstream(format!("bad Intune response: {e}")))
    }

    /// Fetch (and cache) an AAD access token for the given scope.
    async fn token(&self, scope: &str) -> AppResult<String> {
        if let Some(t) = self.tokens.read().await.get(scope) {
            if t.expires_at > Instant::now() {
                return Ok(t.value.clone());
            }
        }
        let url = format!("{}/{}/oauth2/v2.0/token", self.login_host, self.tenant_id);
        let form = [
            ("grant_type", "client_credentials"),
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("scope", scope),
        ];
        let resp = self
            .http
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|e| AppError::Upstream(format!("token request failed: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(AppError::Upstream(format!(
                "AAD token request returned HTTP {status}: {text}"
            )));
        }
        let token: TokenResponse = resp
            .json()
            .await
            .map_err(|e| AppError::Upstream(format!("bad token response: {e}")))?;
        let ttl = token.expires_in.unwrap_or(3600).max(60) as u64;
        let cached = CachedToken {
            value: token.access_token.clone(),
            // Refresh a minute early.
            expires_at: Instant::now() + Duration::from_secs(ttl.saturating_sub(60)),
        };
        self.tokens.write().await.insert(scope.to_string(), cached);
        Ok(token.access_token)
    }
}

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    expires_in: Option<i64>,
}

#[derive(Deserialize)]
struct EndpointsResponse {
    #[serde(default)]
    value: Vec<Endpoint>,
}

#[derive(Deserialize)]
struct Endpoint {
    #[serde(rename = "providerName")]
    provider_name: Option<String>,
    uri: Option<String>,
}

#[derive(Deserialize)]
struct ValidateResponse {
    code: Option<String>,
    #[serde(rename = "errorDescription")]
    error_description: Option<String>,
}
