//! CA key material loading.
//!
//! `KeyStore` abstracts where a CA's certificate and private key come from.
//! Two sources are implemented: [`FileKeyStore`] (a local PEM bundle) and
//! [`InlineKeyStore`] (cert and key bytes supplied directly, e.g. decoded from
//! base64 in config or a secret). Both accept PEM or DER. Azure Key Vault or a
//! PKCS#11 HSM can be added later behind the same trait without touching the
//! issuance code.

use std::path::{Path, PathBuf};

use base64::Engine;
use der::Decode;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use x509_cert::Certificate;

use crate::error::{AppError, AppResult};

/// A source of CA key material.
pub trait KeyStore: Send + Sync {
    /// Load the CA certificate and its private key.
    fn load(&self) -> AppResult<(Certificate, RsaPrivateKey)>;
}

/// Loads a CA certificate and RSA private key from a PEM bundle file.
///
/// The file may contain both a `CERTIFICATE` and a private key block
/// (`PRIVATE KEY`, `ENCRYPTED PRIVATE KEY`, or `RSA PRIVATE KEY`). If a
/// password is supplied it is used to decrypt an encrypted PKCS#8 key.
pub struct FileKeyStore {
    path: PathBuf,
    password: Option<String>,
}

impl FileKeyStore {
    pub fn new(path: impl AsRef<Path>, password: Option<String>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            password,
        }
    }
}

impl KeyStore for FileKeyStore {
    fn load(&self) -> AppResult<(Certificate, RsaPrivateKey)> {
        let bytes = std::fs::read(&self.path).map_err(|e| {
            AppError::Config(format!(
                "cannot read CA key file {}: {e}",
                self.path.display()
            ))
        })?;
        let cert = parse_certificate(&bytes)?;
        let key = parse_private_key(&bytes, self.password.as_deref())?;
        Ok((cert, key))
    }
}

/// Loads a CA certificate and key from bytes supplied directly (PEM or DER).
///
/// The certificate and key are separate byte blobs; typically each is the
/// base64-decoded content of a config value or environment variable.
pub struct InlineKeyStore {
    cert: Vec<u8>,
    key: Vec<u8>,
    password: Option<String>,
}

impl InlineKeyStore {
    pub fn new(cert: Vec<u8>, key: Vec<u8>, password: Option<String>) -> Self {
        Self {
            cert,
            key,
            password,
        }
    }

    /// Build from certificate and key strings supplied in config. Each value is
    /// either PEM text (`-----BEGIN ...`) used as-is, or a base64 blob of PEM or
    /// DER (auto-detected).
    pub fn from_material(cert: &str, key: &str, password: Option<String>) -> AppResult<Self> {
        Ok(Self::new(
            material_to_bytes(cert, "CA certificate")?,
            material_to_bytes(key, "CA key")?,
            password,
        ))
    }
}

impl KeyStore for InlineKeyStore {
    fn load(&self) -> AppResult<(Certificate, RsaPrivateKey)> {
        let cert = parse_certificate(&self.cert)?;
        let key = parse_private_key(&self.key, self.password.as_deref())?;
        Ok((cert, key))
    }
}

/// Parse a certificate from PEM or DER bytes.
pub fn parse_certificate(bytes: &[u8]) -> AppResult<Certificate> {
    if let Some(blocks) = as_pem_blocks(bytes) {
        let der = blocks
            .iter()
            .find(|(label, _)| label == "CERTIFICATE")
            .map(|(_, der)| der.clone())
            .ok_or_else(|| AppError::Config("no CERTIFICATE block in CA cert material".into()))?;
        return Certificate::from_der(&der)
            .map_err(|e| AppError::Config(format!("bad CA certificate: {e}")));
    }
    Certificate::from_der(bytes)
        .map_err(|e| AppError::Config(format!("bad CA certificate DER: {e}")))
}

/// Parse an RSA private key from PEM or DER bytes (PKCS#8, encrypted PKCS#8, or
/// PKCS#1). `password` decrypts an encrypted PKCS#8 key.
pub fn parse_private_key(bytes: &[u8], password: Option<&str>) -> AppResult<RsaPrivateKey> {
    if let Some(blocks) = as_pem_blocks(bytes) {
        return blocks
            .iter()
            .find_map(|(label, der)| load_key_block(label, der, password))
            .ok_or_else(|| AppError::Config("no private key block in CA key material".into()))?;
    }
    key_from_der(bytes, password)
}

fn load_key_block(
    label: &str,
    der: &[u8],
    password: Option<&str>,
) -> Option<AppResult<RsaPrivateKey>> {
    match label {
        "PRIVATE KEY" => Some(
            RsaPrivateKey::from_pkcs8_der(der)
                .map_err(|e| AppError::Config(format!("bad PKCS#8 key: {e}"))),
        ),
        "RSA PRIVATE KEY" => Some(
            RsaPrivateKey::from_pkcs1_der(der)
                .map_err(|e| AppError::Config(format!("bad PKCS#1 key: {e}"))),
        ),
        "ENCRYPTED PRIVATE KEY" => Some(decrypt_pkcs8(der, password)),
        _ => None,
    }
}

/// Try to parse a private key from DER, covering PKCS#8, PKCS#1, and encrypted
/// PKCS#8 (in that order).
fn key_from_der(der: &[u8], password: Option<&str>) -> AppResult<RsaPrivateKey> {
    if let Ok(key) = RsaPrivateKey::from_pkcs8_der(der) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_der(der) {
        return Ok(key);
    }
    if pkcs8::EncryptedPrivateKeyInfo::from_der(der).is_ok() {
        return decrypt_pkcs8(der, password);
    }
    Err(AppError::Config(
        "CA key DER is not a recognised RSA key (PKCS#8/PKCS#1)".into(),
    ))
}

fn decrypt_pkcs8(der: &[u8], password: Option<&str>) -> AppResult<RsaPrivateKey> {
    let password = password
        .ok_or_else(|| AppError::Config("CA key is encrypted but no password given".into()))?;
    let epki = pkcs8::EncryptedPrivateKeyInfo::from_der(der)
        .map_err(|e| AppError::Config(format!("bad encrypted key: {e}")))?;
    let secret = epki
        .decrypt(password.as_bytes())
        .map_err(|e| AppError::Config(format!("CA key decryption failed: {e}")))?;
    RsaPrivateKey::from_pkcs8_der(secret.as_bytes())
        .map_err(|e| AppError::Config(format!("decrypted key is not RSA PKCS#8: {e}")))
}

/// If `bytes` is UTF-8 text containing PEM, split it into `(label, der)` blocks.
fn as_pem_blocks(bytes: &[u8]) -> Option<Vec<(String, Vec<u8>)>> {
    let text = std::str::from_utf8(bytes).ok()?;
    if !text.contains("-----BEGIN ") {
        return None;
    }
    Some(pem_blocks(text))
}

/// Split PEM text into `(label, der_bytes)` blocks.
fn pem_blocks(text: &str) -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(label) = line
            .trim()
            .strip_prefix("-----BEGIN ")
            .and_then(|s| s.strip_suffix("-----"))
        else {
            continue;
        };
        let mut b64 = String::new();
        for l in lines.by_ref() {
            if l.trim().starts_with("-----END ") {
                break;
            }
            b64.push_str(l.trim());
        }
        if let Ok(der) = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
            out.push((label.to_string(), der));
        }
    }
    out
}

/// Turn a config value into raw bytes: PEM text is used as-is; anything else is
/// treated as a base64 blob (of PEM or DER) and decoded.
fn material_to_bytes(value: &str, what: &str) -> AppResult<Vec<u8>> {
    if value.trim_start().starts_with("-----BEGIN") {
        return Ok(value.as_bytes().to_vec());
    }
    let cleaned: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(cleaned.as_bytes())
        .map_err(|e| AppError::Config(format!("{what} is neither PEM nor valid base64: {e}")))
}
