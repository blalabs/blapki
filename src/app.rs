//! Application wiring: turn [`Settings`] into a running [`AppState`].

use std::collections::HashMap;
use std::sync::Arc;

use der::pem::LineEnding;
use der::EncodePem;
use rsa::pkcs8::EncodePrivateKey;

use crate::ca::keystore::{FileKeyStore, InlineKeyStore, KeyStore};
use crate::ca::CertificateAuthority;
use crate::challenge::{ChallengeValidator, IntuneValidator, NoneValidator, StaticSecretValidator};
use crate::config::{CaConfig, ChallengeMode, ProfileConfig, Settings};
use crate::db;
use crate::error::{AppError, AppResult};
use crate::http::{AppState, ProfileRuntime, Shared};
use crate::intune::IntuneClient;

/// Build shared application state from configuration.
pub async fn build_state(settings: &Settings) -> AppResult<Shared> {
    let db = db::connect(&settings.server.database_url).await?;

    let mut cas = HashMap::new();
    for ca_cfg in &settings.ca {
        let ca = load_or_bootstrap_ca(ca_cfg)?;
        cas.insert(ca_cfg.id.clone(), Arc::new(ca));
    }

    let intune = match &settings.intune {
        Some(cfg) => {
            let secret = std::env::var(&cfg.client_secret_env).map_err(|_| {
                AppError::Config(format!(
                    "intune client secret env '{}' is not set",
                    cfg.client_secret_env
                ))
            })?;
            Some(Arc::new(IntuneClient::new(cfg, secret)))
        }
        None => None,
    };

    let mut profiles = HashMap::new();
    for p in &settings.profile {
        let validator = build_validator(p, intune.as_ref())?;
        profiles.insert(
            p.name.clone(),
            ProfileRuntime {
                name: p.name.clone(),
                ca_id: p.ca.clone(),
                validator,
                validity_days: p.validity_days,
                key_usage: p.key_usage.clone(),
                extended_key_usage: p.extended_key_usage.clone(),
            },
        );
    }

    Ok(Arc::new(AppState {
        cas,
        profiles,
        db,
        base_url: settings.server.base_url.clone(),
    }))
}

fn build_validator(
    profile: &ProfileConfig,
    intune: Option<&Arc<IntuneClient>>,
) -> AppResult<Arc<dyn ChallengeValidator>> {
    Ok(match profile.challenge {
        ChallengeMode::Static => {
            let env = profile.static_secret_env.as_ref().ok_or_else(|| {
                AppError::Config(format!(
                    "profile '{}' missing static_secret_env",
                    profile.name
                ))
            })?;
            let secret = std::env::var(env).map_err(|_| {
                AppError::Config(format!("static challenge secret env '{env}' is not set"))
            })?;
            Arc::new(StaticSecretValidator::new(secret))
        }
        ChallengeMode::Intune => {
            let client = intune
                .ok_or_else(|| {
                    AppError::Config("intune profile but [intune] not configured".into())
                })?
                .clone();
            Arc::new(IntuneValidator::new(client))
        }
        ChallengeMode::None => Arc::new(NoneValidator),
    })
}

/// Load a CA from inline base64 material or its key file, or generate and
/// persist a self-signed CA if a key file is configured but missing
/// (convenient for first run / dev).
fn load_or_bootstrap_ca(cfg: &CaConfig) -> AppResult<CertificateAuthority> {
    let password = cfg
        .key_password_env
        .as_ref()
        .and_then(|env| std::env::var(env).ok());

    // 1. Inline PEM (or base64) certificate + key (config value or env var).
    if let Some((cert, key)) = cfg.inline_material()? {
        tracing::info!(ca = %cfg.id, "loading CA from inline material");
        let (cert, key) = InlineKeyStore::from_material(&cert, &key, password)?.load()?;
        return Ok(CertificateAuthority::new(cfg.id.clone(), cert, key));
    }

    // 2. Key file on disk.
    let Some(key_file) = &cfg.key_file else {
        return Err(AppError::Config(format!(
            "ca '{}' has no key material configured",
            cfg.id
        )));
    };
    if key_file.exists() {
        let (cert, key) = FileKeyStore::new(key_file, password).load()?;
        return Ok(CertificateAuthority::new(cfg.id.clone(), cert, key));
    }

    // 3. Dev bootstrap: generate and persist a self-signed CA.
    tracing::warn!(
        ca = %cfg.id,
        path = %key_file.display(),
        "CA key file not found; generating a self-signed CA (dev bootstrap)"
    );
    let ca = CertificateAuthority::generate_self_signed(
        &cfg.id,
        &format!("blapki CA {}", cfg.id),
        3072,
    )?;
    if let Some(parent) = key_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    write_ca_pem(&ca, key_file)?;
    Ok(ca)
}

fn write_ca_pem(ca: &CertificateAuthority, path: &std::path::Path) -> AppResult<()> {
    let cert_pem = ca
        .cert
        .to_pem(LineEnding::LF)
        .map_err(|e| AppError::crypto(format!("encode CA cert PEM: {e}")))?;
    let key_pem = ca
        .private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| AppError::crypto(format!("encode CA key PEM: {e}")))?;
    let bundle = format!("{cert_pem}{}", key_pem.as_str());
    std::fs::write(path, bundle).map_err(|e| {
        AppError::Config(format!(
            "cannot write bootstrapped CA to {}: {e}",
            path.display()
        ))
    })?;
    tracing::warn!(path = %path.display(), "wrote new self-signed CA (unencrypted PKCS#8)");
    Ok(())
}
