//! Challenge validation strategies.
//!
//! A SCEP enrolment carries a `challengePassword` in its CSR. How that is
//! validated depends on the profile: a static shared secret (good for testing
//! and non-Intune clients) or delegation to the Microsoft Intune SCEP
//! validation API. The [`ChallengeValidator`] trait abstracts this so the SCEP
//! flow does not care which is in use.

use std::sync::Arc;

use async_trait::async_trait;

use crate::error::{AppError, AppResult};
use crate::intune::{IntuneClient, IssuedInfo};

/// Everything a validator needs to make a decision.
pub struct ValidationInput<'a> {
    pub transaction_id: &'a str,
    /// DER-encoded PKCS#10 CSR.
    pub csr_der: &'a [u8],
    pub challenge_password: Option<&'a str>,
}

/// Validates SCEP challenges and (for Intune) reports the outcome back.
#[async_trait]
pub trait ChallengeValidator: Send + Sync {
    /// Approve or reject a request before issuance.
    async fn validate(&self, input: &ValidationInput<'_>) -> AppResult<()>;

    /// Called after a certificate is issued (Intune success notification).
    async fn on_issued(&self, _input: &ValidationInput<'_>, _info: &IssuedInfo) -> AppResult<()> {
        Ok(())
    }

    /// Called when issuance fails (Intune failure notification).
    async fn on_failure(&self, _input: &ValidationInput<'_>, _message: &str) -> AppResult<()> {
        Ok(())
    }
}

/// Compares the CSR challenge password against a configured shared secret.
pub struct StaticSecretValidator {
    secret: String,
}

impl StaticSecretValidator {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }
}

#[async_trait]
impl ChallengeValidator for StaticSecretValidator {
    async fn validate(&self, input: &ValidationInput<'_>) -> AppResult<()> {
        match input.challenge_password {
            Some(pw) if constant_time_eq(pw.as_bytes(), self.secret.as_bytes()) => Ok(()),
            Some(_) => Err(AppError::bad_request("incorrect challenge password")),
            None => Err(AppError::bad_request("missing challenge password")),
        }
    }
}

/// Accepts every request. Only for closed test environments.
pub struct NoneValidator;

#[async_trait]
impl ChallengeValidator for NoneValidator {
    async fn validate(&self, _input: &ValidationInput<'_>) -> AppResult<()> {
        Ok(())
    }
}

/// Delegates validation and notification to Microsoft Intune.
pub struct IntuneValidator {
    client: Arc<IntuneClient>,
}

impl IntuneValidator {
    pub fn new(client: Arc<IntuneClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ChallengeValidator for IntuneValidator {
    async fn validate(&self, input: &ValidationInput<'_>) -> AppResult<()> {
        self.client
            .validate_request(input.transaction_id, input.csr_der)
            .await
    }

    async fn on_issued(&self, input: &ValidationInput<'_>, info: &IssuedInfo) -> AppResult<()> {
        self.client
            .success_notification(input.transaction_id, input.csr_der, info)
            .await
    }

    async fn on_failure(&self, input: &ValidationInput<'_>, message: &str) -> AppResult<()> {
        self.client
            .failure_notification(input.transaction_id, input.csr_der, 1234, message)
            .await
    }
}

/// Constant-time byte-slice equality (avoids leaking the secret via timing).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
