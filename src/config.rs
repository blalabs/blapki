//! Configuration model.
//!
//! Management is config-only: CAs and SCEP profiles are declared here, and the
//! database holds only issued-certificate / transaction / revocation state.
//!
//! Config is loaded with [`figment`] from a TOML file plus environment
//! variables (prefix `BLAPKI_`, `__` as a nesting separator). Secrets are never
//! stored in the file directly. The relevant fields name an environment
//! variable that holds the secret.

use std::path::PathBuf;

use figment::providers::{Env, Format, Toml};
use figment::Figment;
use serde::Deserialize;

use crate::error::{AppError, AppResult};

#[derive(Debug, Clone, Deserialize)]
pub struct Settings {
    pub server: ServerConfig,
    #[serde(default)]
    pub ca: Vec<CaConfig>,
    #[serde(default)]
    pub profile: Vec<ProfileConfig>,
    pub intune: Option<IntuneConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    /// Socket address to bind, e.g. `0.0.0.0:8080`.
    pub listen: String,
    /// Database URL. `sqlite://blapki.db`, `postgres://…`, or `mysql://…`.
    pub database_url: String,
    /// Externally reachable base URL, used to populate the AIA (OCSP) and CDP
    /// (CRL) URLs embedded in issued certificates, e.g. `https://pki.example.com`.
    pub base_url: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaConfig {
    /// Stable identifier referenced by profiles.
    pub id: String,
    /// Path to the CA key material (a PEM bundle with a CERTIFICATE and a
    /// private key block). Optional if inline material is given below.
    #[serde(default)]
    pub key_file: Option<PathBuf>,
    /// CA certificate as inline PEM (`-----BEGIN CERTIFICATE-----`). A base64
    /// blob of PEM or DER is also accepted. Alternative to `key_file`.
    pub cert_pem: Option<String>,
    /// Name of the environment variable holding the certificate PEM/base64.
    pub cert_pem_env: Option<String>,
    /// CA private key as inline PEM (`-----BEGIN PRIVATE KEY-----`, or an
    /// `RSA`/`ENCRYPTED` variant). A base64 blob of PEM or DER also works.
    /// Prefer `key_pem_env` so the key does not sit in the config file.
    pub key_pem: Option<String>,
    /// Name of the environment variable holding the private key PEM/base64.
    pub key_pem_env: Option<String>,
    /// Name of the environment variable holding the key password
    /// (for an encrypted PKCS#8 key; optional otherwise).
    pub key_password_env: Option<String>,
    /// How long a freshly generated CRL is valid, in hours.
    #[serde(default = "default_crl_lifetime")]
    pub crl_lifetime_hours: u64,
}

fn default_crl_lifetime() -> u64 {
    24
}

impl CaConfig {
    /// Whether the config declares a certificate source (inline or file).
    fn has_source(&self) -> bool {
        let has_cert = self.cert_pem.is_some() || self.cert_pem_env.is_some();
        let has_key = self.key_pem.is_some() || self.key_pem_env.is_some();
        (has_cert && has_key) || self.key_file.is_some()
    }

    /// Resolve the inline certificate and key strings, reading env vars where
    /// named. Each value is PEM text or a base64 blob. Returns `None` when no
    /// inline material is configured (use the file instead).
    pub fn inline_material(&self) -> AppResult<Option<(String, String)>> {
        let cert = resolve_value(&self.cert_pem, &self.cert_pem_env, "cert_pem")?;
        let key = resolve_value(&self.key_pem, &self.key_pem_env, "key_pem")?;
        match (cert, key) {
            (Some(cert), Some(key)) => Ok(Some((cert, key))),
            (None, None) => Ok(None),
            _ => Err(AppError::Config(format!(
                "ca '{}': provide both cert and key inline, or neither",
                self.id
            ))),
        }
    }
}

/// Return an inline value, or read it from the named env var, or `None`.
fn resolve_value(
    inline: &Option<String>,
    env_name: &Option<String>,
    field: &str,
) -> AppResult<Option<String>> {
    if let Some(v) = inline {
        return Ok(Some(v.clone()));
    }
    if let Some(env) = env_name {
        return std::env::var(env)
            .map(Some)
            .map_err(|_| AppError::Config(format!("{field} env var '{env}' is not set")));
    }
    Ok(None)
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProfileConfig {
    /// Profile name; also the URL path segment (`/scep/<name>`).
    pub name: String,
    /// The CA (by `id`) that issues certificates for this profile.
    pub ca: String,
    /// Challenge validation mode.
    #[serde(default)]
    pub challenge: ChallengeMode,
    /// Environment variable holding the shared secret (for `challenge = "static"`).
    pub static_secret_env: Option<String>,
    /// Validity of issued leaf certificates, in days.
    #[serde(default = "default_validity_days")]
    pub validity_days: u32,
    /// Key usage bits to set on issued certificates.
    #[serde(default = "default_key_usage")]
    pub key_usage: Vec<String>,
    /// Extended key usages to set on issued certificates.
    #[serde(default = "default_eku")]
    pub extended_key_usage: Vec<String>,
}

fn default_validity_days() -> u32 {
    365
}

fn default_key_usage() -> Vec<String> {
    vec!["digitalSignature".into(), "keyEncipherment".into()]
}

fn default_eku() -> Vec<String> {
    vec!["clientAuth".into()]
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ChallengeMode {
    /// Compare the CSR `challengePassword` against a configured shared secret.
    #[default]
    Static,
    /// Delegate validation to the Microsoft Intune SCEP validation API.
    Intune,
    /// Accept any request. Only for closed test environments; never expose.
    None,
}

#[derive(Debug, Clone, Deserialize)]
pub struct IntuneConfig {
    pub tenant_id: String,
    pub client_id: String,
    /// Environment variable holding the client secret.
    pub client_secret_env: String,
    /// Login authority host. Defaults to the public cloud.
    #[serde(default = "default_login_host")]
    pub login_host: String,
    /// Intune SCEP validation resource/audience.
    #[serde(default = "default_intune_resource")]
    pub resource: String,
}

fn default_login_host() -> String {
    "https://login.microsoftonline.com".into()
}

fn default_intune_resource() -> String {
    "https://api.manage.microsoft.com/".into()
}

impl Settings {
    /// Load configuration from `path` (TOML) merged with `BLAPKI_*` env vars.
    pub fn load(path: &str) -> AppResult<Self> {
        let settings: Settings = Figment::new()
            .merge(Toml::file(path))
            .merge(Env::prefixed("BLAPKI_").split("__"))
            .extract()
            .map_err(|e| AppError::Config(e.to_string()))?;
        settings.validate()?;
        Ok(settings)
    }

    fn validate(&self) -> AppResult<()> {
        if self.ca.is_empty() {
            return Err(AppError::Config("no [[ca]] defined".into()));
        }
        for ca in &self.ca {
            if !ca.has_source() {
                return Err(AppError::Config(format!(
                    "ca '{}' has no key material: set key_file, or cert_pem(_env) + key_pem(_env)",
                    ca.id
                )));
            }
        }
        for profile in &self.profile {
            if !self.ca.iter().any(|c| c.id == profile.ca) {
                return Err(AppError::Config(format!(
                    "profile '{}' references unknown ca '{}'",
                    profile.name, profile.ca
                )));
            }
            if profile.challenge == ChallengeMode::Static && profile.static_secret_env.is_none() {
                return Err(AppError::Config(format!(
                    "profile '{}' uses static challenge but has no static_secret_env",
                    profile.name
                )));
            }
            if profile.challenge == ChallengeMode::Intune && self.intune.is_none() {
                return Err(AppError::Config(format!(
                    "profile '{}' uses intune challenge but [intune] is not configured",
                    profile.name
                )));
            }
        }
        Ok(())
    }

    pub fn ca(&self, id: &str) -> Option<&CaConfig> {
        self.ca.iter().find(|c| c.id == id)
    }

    pub fn profile(&self, name: &str) -> Option<&ProfileConfig> {
        self.profile.iter().find(|p| p.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server() -> ServerConfig {
        ServerConfig {
            listen: "0.0.0.0:8080".into(),
            database_url: "sqlite://x?mode=rwc".into(),
            base_url: "http://x".into(),
        }
    }

    fn ca_with_file() -> CaConfig {
        CaConfig {
            id: "default".into(),
            key_file: Some("ca.pem".into()),
            cert_pem: None,
            cert_pem_env: None,
            key_pem: None,
            key_pem_env: None,
            key_password_env: None,
            crl_lifetime_hours: 24,
        }
    }

    fn static_profile() -> ProfileConfig {
        ProfileConfig {
            name: "test".into(),
            ca: "default".into(),
            challenge: ChallengeMode::Static,
            static_secret_env: Some("SECRET".into()),
            validity_days: 90,
            key_usage: vec![],
            extended_key_usage: vec![],
        }
    }

    fn settings(ca: Vec<CaConfig>, profile: Vec<ProfileConfig>) -> Settings {
        Settings {
            server: server(),
            ca,
            profile,
            intune: None,
        }
    }

    #[test]
    fn valid_config_passes() {
        assert!(settings(vec![ca_with_file()], vec![static_profile()])
            .validate()
            .is_ok());
    }

    #[test]
    fn no_ca_is_rejected() {
        assert!(settings(vec![], vec![]).validate().is_err());
    }

    #[test]
    fn ca_without_source_is_rejected() {
        let mut ca = ca_with_file();
        ca.key_file = None;
        assert!(settings(vec![ca], vec![]).validate().is_err());
    }

    #[test]
    fn static_profile_without_secret_env_is_rejected() {
        let mut p = static_profile();
        p.static_secret_env = None;
        assert!(settings(vec![ca_with_file()], vec![p]).validate().is_err());
    }

    #[test]
    fn intune_profile_without_intune_section_is_rejected() {
        let mut p = static_profile();
        p.challenge = ChallengeMode::Intune;
        assert!(settings(vec![ca_with_file()], vec![p]).validate().is_err());
    }

    #[test]
    fn profile_referencing_unknown_ca_is_rejected() {
        let mut p = static_profile();
        p.ca = "ghost".into();
        assert!(settings(vec![ca_with_file()], vec![p]).validate().is_err());
    }

    #[test]
    fn has_source_covers_file_and_inline() {
        assert!(ca_with_file().has_source());

        let mut inline = ca_with_file();
        inline.key_file = None;
        inline.cert_pem = Some("c".into());
        inline.key_pem = Some("k".into());
        assert!(inline.has_source());

        let mut partial = ca_with_file();
        partial.key_file = None;
        partial.cert_pem = Some("c".into());
        assert!(!partial.has_source());
    }

    #[test]
    fn inline_material_requires_both_cert_and_key() {
        let mut ca = ca_with_file();
        ca.key_file = None;
        ca.cert_pem = Some("c".into());
        ca.key_pem = Some("k".into());
        assert_eq!(
            ca.inline_material().unwrap(),
            Some(("c".to_string(), "k".to_string()))
        );

        ca.key_pem = None;
        assert!(ca.inline_material().is_err());

        ca.cert_pem = None;
        assert_eq!(ca.inline_material().unwrap(), None);
    }

    #[test]
    fn inline_material_reads_env_vars() {
        std::env::set_var("BLAPKI_TEST_CERT_XYZ", "cert-value");
        std::env::set_var("BLAPKI_TEST_KEY_XYZ", "key-value");
        let mut ca = ca_with_file();
        ca.key_file = None;
        ca.cert_pem_env = Some("BLAPKI_TEST_CERT_XYZ".into());
        ca.key_pem_env = Some("BLAPKI_TEST_KEY_XYZ".into());
        assert_eq!(
            ca.inline_material().unwrap(),
            Some(("cert-value".to_string(), "key-value".to_string()))
        );
    }
}
