//! Application wiring: turn [`Settings`] into a running [`AppState`].

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use der::pem::LineEnding;
use der::EncodePem;
use rsa::pkcs8::EncodePrivateKey;
use x509_cert::ext::pkix::BasicConstraints;

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

    // The Intune client (and its secret) is only needed when a profile uses it.
    let intune = match &settings.intune {
        Some(cfg) if settings.uses_intune() => {
            let secret = read_secret(&cfg.client_secret_env, "intune client secret")?;
            Some(Arc::new(IntuneClient::new(cfg, secret)?))
        }
        _ => None,
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
            let secret = read_secret(env, "static challenge secret")?;
            if secret.len() < 16 || secret == "change-me" {
                tracing::warn!(
                    profile = %profile.name,
                    "static challenge secret is short or a placeholder; anyone who \
                     knows it can obtain a certificate for any subject"
                );
            }
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
        ChallengeMode::None => {
            tracing::warn!(
                profile = %profile.name,
                "profile has challenge = \"none\": every request is issued a \
                 certificate without authentication; never expose this profile"
            );
            Arc::new(NoneValidator)
        }
    })
}

/// Read a secret from an environment variable. An unset or empty variable is
/// an error: an empty shared secret would match an empty challenge password.
fn read_secret(env: &str, what: &str) -> AppResult<String> {
    match std::env::var(env) {
        Ok(v) if !v.trim().is_empty() => Ok(v),
        Ok(_) => Err(AppError::Config(format!("{what} env '{env}' is empty"))),
        Err(_) => Err(AppError::Config(format!("{what} env '{env}' is not set"))),
    }
}

/// Load a CA from inline material or its key file. If the key file is missing
/// and `generate_if_missing` is set, generate and persist a self-signed CA
/// (first run / development).
fn load_or_bootstrap_ca(cfg: &CaConfig) -> AppResult<CertificateAuthority> {
    let password = cfg
        .key_password_env
        .as_ref()
        .and_then(|env| std::env::var(env).ok());

    // 1. Inline PEM (or base64) certificate + key (config value or env var).
    if let Some((cert, key)) = cfg.inline_material()? {
        tracing::info!(ca = %cfg.id, "loading CA from inline material");
        let (cert, key) = InlineKeyStore::from_material(&cert, &key, password)?.load()?;
        check_ca_material(&cfg.id, &cert, &key)?;
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
        warn_if_key_file_exposed(&cfg.id, key_file);
        let (cert, key) = FileKeyStore::new(key_file, password).load()?;
        check_ca_material(&cfg.id, &cert, &key)?;
        return Ok(CertificateAuthority::new(cfg.id.clone(), cert, key));
    }

    // 3. Bootstrap, only when explicitly enabled. Generating a CA because a
    // path was mistyped or a volume was not mounted would silently orphan
    // every certificate issued so far.
    if !cfg.generate_if_missing {
        return Err(AppError::Config(format!(
            "ca '{}': key file {} does not exist (set generate_if_missing = true \
             to create a new self-signed CA there)",
            cfg.id,
            key_file.display()
        )));
    }
    tracing::warn!(
        ca = %cfg.id,
        path = %key_file.display(),
        "CA key file not found; generating a new self-signed CA"
    );
    let ca = CertificateAuthority::generate_self_signed(
        &cfg.id,
        &format!("blapki CA {}", cfg.id),
        3072,
    )?;
    write_ca_pem(&ca, key_file)?;
    Ok(ca)
}

/// Refuse CA material that cannot work: a key that does not belong to the
/// certificate, a certificate that is not a CA, or one outside its validity.
fn check_ca_material(
    id: &str,
    cert: &x509_cert::Certificate,
    key: &rsa::RsaPrivateKey,
) -> AppResult<()> {
    let cert_key = crate::crypto::rsa_public_key(cert)
        .map_err(|e| AppError::Config(format!("ca '{id}': certificate key: {e}")))?;
    if cert_key != key.to_public_key() {
        return Err(AppError::Config(format!(
            "ca '{id}': the private key does not match the certificate"
        )));
    }
    match cert.tbs_certificate.get::<BasicConstraints>() {
        Ok(Some((_, bc))) if bc.ca => {}
        _ => {
            return Err(AppError::Config(format!(
                "ca '{id}': certificate is not a CA (basicConstraints CA:TRUE missing)"
            )))
        }
    }
    let now = SystemTime::now();
    let validity = &cert.tbs_certificate.validity;
    if now < validity.not_before.to_system_time() || now >= validity.not_after.to_system_time() {
        return Err(AppError::Config(format!(
            "ca '{id}': certificate is expired or not yet valid"
        )));
    }
    Ok(())
}

/// Warn when an existing CA key file is readable by other users.
fn warn_if_key_file_exposed(id: &str, path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = std::fs::metadata(path) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    ca = %id,
                    path = %path.display(),
                    mode = %format!("{mode:o}"),
                    "CA key file is accessible to other users; chmod 600 it"
                );
            }
        }
    }
    #[cfg(not(unix))]
    let _ = (id, path);
}

/// Write a new CA bundle. The file holds the private key, so it is created
/// owner-only and never overwrites an existing file.
fn write_ca_pem(ca: &CertificateAuthority, path: &Path) -> AppResult<()> {
    use std::io::Write;

    let io_err = |e: std::io::Error| {
        AppError::Config(format!(
            "cannot write bootstrapped CA to {}: {e}",
            path.display()
        ))
    };
    let cert_pem = ca
        .cert
        .to_pem(LineEnding::LF)
        .map_err(|e| AppError::crypto(format!("encode CA cert PEM: {e}")))?;
    let key_pem = ca
        .private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| AppError::crypto(format!("encode CA key PEM: {e}")))?;

    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut dir = std::fs::DirBuilder::new();
        dir.recursive(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            dir.mode(0o700);
        }
        dir.create(parent).map_err(io_err)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(io_err)?;
    file.write_all(cert_pem.as_bytes())
        .and_then(|_| file.write_all(key_pem.as_bytes()))
        .and_then(|_| file.sync_all())
        .map_err(io_err)?;
    tracing::warn!(path = %path.display(), "wrote new self-signed CA (unencrypted PKCS#8, mode 0600)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mismatched_key_is_rejected() {
        let a = CertificateAuthority::generate_self_signed("a", "a", 2048).unwrap();
        let b = CertificateAuthority::generate_self_signed("b", "b", 2048).unwrap();
        assert!(check_ca_material("a", &a.cert, &a.private_key).is_ok());
        assert!(check_ca_material("a", &a.cert, &b.private_key).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn bootstrapped_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let ca = CertificateAuthority::generate_self_signed("p", "p", 2048).unwrap();
        let dir = std::env::temp_dir().join(format!("blapki-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("ca.pem");
        write_ca_pem(&ca, &path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // An existing key file is never overwritten.
        assert!(write_ca_pem(&ca, &path).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_secret_is_rejected() {
        std::env::set_var("BLAPKI_TEST_EMPTY_SECRET", "");
        assert!(read_secret("BLAPKI_TEST_EMPTY_SECRET", "x").is_err());
        assert!(read_secret("BLAPKI_TEST_UNSET_SECRET_XYZ", "x").is_err());
    }
}
