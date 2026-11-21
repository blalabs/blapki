//! A certificate authority: its certificate, signing key, and the logic to
//! issue leaf certificates from a CSR.

use core::time::Duration;
use std::str::FromStr;
use std::time::SystemTime;

use der::referenced::OwnedToRef;
use rsa::RsaPrivateKey;
use signature::Keypair;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier};
use x509_cert::name::Name;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::{Time, Validity};
use x509_cert::Certificate;

use crate::ca::{extensions, serial};
use crate::crypto::CaSigningKey;
use crate::error::{AppError, AppResult};

/// How far `notBefore` is backdated to tolerate device clock skew.
const NOT_BEFORE_BACKDATE: Duration = Duration::from_secs(5 * 60);

/// Parameters controlling how a leaf certificate is issued.
pub struct IssueOptions {
    pub validity_days: u32,
    pub key_usage: Vec<String>,
    pub extended_key_usage: Vec<String>,
    /// OCSP responder URL for the AIA extension.
    pub ocsp_url: Option<String>,
    /// CRL URL for the CRL distribution points extension.
    pub crl_url: Option<String>,
}

/// A loaded certificate authority.
pub struct CertificateAuthority {
    pub id: String,
    pub cert: Certificate,
    /// RSA + SHA-256 signer used for both certificates and CMS.
    pub signing_key: CaSigningKey,
    /// Raw private key, used to decrypt SCEP `EnvelopedData`.
    pub private_key: RsaPrivateKey,
    /// How long a published CRL is valid, in hours.
    pub crl_lifetime_hours: u64,
}

/// CRL lifetime used unless the configuration says otherwise.
pub const DEFAULT_CRL_LIFETIME_HOURS: u64 = 24;

impl CertificateAuthority {
    /// Construct from an existing certificate and private key.
    pub fn new(id: impl Into<String>, cert: Certificate, private_key: RsaPrivateKey) -> Self {
        let signing_key = CaSigningKey::new(private_key.clone());
        Self {
            id: id.into(),
            cert,
            signing_key,
            private_key,
            crl_lifetime_hours: DEFAULT_CRL_LIFETIME_HOURS,
        }
    }

    /// Generate a fresh self-signed root CA. Used for tests and for
    /// bootstrapping a dev instance.
    pub fn generate_self_signed(id: &str, common_name: &str, bits: usize) -> AppResult<Self> {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, bits)
            .map_err(|e| AppError::crypto(format!("RSA keygen failed: {e}")))?;
        let signing_key = CaSigningKey::new(private_key.clone());

        let subject = Name::from_str(&format!("CN={common_name}"))
            .map_err(|e| AppError::Config(format!("invalid CA subject: {e}")))?;
        let serial = serial::random_serial();
        let validity = Validity::from_now(Duration::from_secs(3650 * 86_400)).map_err(der_err)?;
        let spki = SubjectPublicKeyInfoOwned::from_key(signing_key.verifying_key())
            .map_err(|e| AppError::crypto(format!("SPKI encode: {e}")))?;

        let builder =
            CertificateBuilder::new(Profile::Root, serial, validity, subject, spki, &signing_key)
                .map_err(bld_err)?;
        let cert = builder
            .build::<rsa::pkcs1v15::Signature>()
            .map_err(bld_err)?;

        Ok(Self {
            id: id.to_string(),
            cert,
            signing_key,
            private_key,
            crl_lifetime_hours: DEFAULT_CRL_LIFETIME_HOURS,
        })
    }

    /// The CA's subject DN (the issuer DN of certificates it issues).
    pub fn subject(&self) -> Name {
        self.cert.tbs_certificate.subject.clone()
    }

    /// Issue a leaf certificate from a parsed CSR.
    pub fn issue(
        &self,
        csr: &x509_cert::request::CertReq,
        opts: &IssueOptions,
    ) -> AppResult<Certificate> {
        let serial = serial::random_serial();
        let validity = self.leaf_validity(opts.validity_days)?;
        let subject = csr.info.subject.clone();
        let spki = csr.info.public_key.clone();

        let ski = SubjectKeyIdentifier::try_from(spki.owned_to_ref())
            .map_err(|e| AppError::crypto(format!("subject key identifier: {e}")))?;
        let aki = self.authority_key_identifier()?;

        let mut builder = CertificateBuilder::new(
            Profile::Manual {
                issuer: Some(self.subject()),
            },
            serial,
            validity,
            subject,
            spki,
            &self.signing_key,
        )
        .map_err(bld_err)?;

        builder
            .add_extension(&BasicConstraints {
                ca: false,
                path_len_constraint: None,
            })
            .map_err(bld_err)?;
        // A KeyUsage extension with no bits set is invalid (RFC 5280 4.2.1.3).
        if !opts.key_usage.is_empty() {
            builder
                .add_extension(&extensions::key_usage(&opts.key_usage)?)
                .map_err(bld_err)?;
        }
        let eku = extensions::extended_key_usage(&opts.extended_key_usage)?;
        if !eku.0.is_empty() {
            builder.add_extension(&eku).map_err(bld_err)?;
        }
        builder.add_extension(&ski).map_err(bld_err)?;
        builder.add_extension(&aki).map_err(bld_err)?;
        if let Some(san) = extensions::requested_san(csr)? {
            builder.add_extension(&san).map_err(bld_err)?;
        }
        if let Some(ocsp) = &opts.ocsp_url {
            builder
                .add_extension(&extensions::authority_info_access(ocsp)?)
                .map_err(bld_err)?;
        }
        if let Some(crl) = &opts.crl_url {
            builder
                .add_extension(&extensions::crl_distribution_points(crl)?)
                .map_err(bld_err)?;
        }

        builder.build::<rsa::pkcs1v15::Signature>().map_err(bld_err)
    }
}

impl CertificateAuthority {
    /// Validity window for a leaf issued now. `notBefore` is backdated a few
    /// minutes so a device whose clock runs slightly behind does not see its
    /// new certificate as "not yet valid", and `notAfter` never exceeds the
    /// CA certificate's own expiry.
    fn leaf_validity(&self, validity_days: u32) -> AppResult<Validity> {
        let now = SystemTime::now();
        let ca_validity = &self.cert.tbs_certificate.validity;
        let ca_not_before = ca_validity.not_before.to_system_time();
        let ca_not_after = ca_validity.not_after.to_system_time();
        if now >= ca_not_after {
            return Err(AppError::crypto("CA certificate has expired"));
        }
        let not_before = now
            .checked_sub(NOT_BEFORE_BACKDATE)
            .unwrap_or(now)
            .max(ca_not_before);
        let not_after =
            (now + Duration::from_secs(validity_days as u64 * 86_400)).min(ca_not_after);
        Ok(Validity {
            not_before: Time::try_from(not_before).map_err(der_err)?,
            not_after: Time::try_from(not_after).map_err(der_err)?,
        })
    }

    /// The AKI for issued certificates. It must equal the CA certificate's
    /// subject key identifier, so that is copied when present (an imported CA
    /// may not use the SHA-1 method); otherwise it is derived from the key.
    pub fn authority_key_identifier(&self) -> AppResult<AuthorityKeyIdentifier> {
        if let Ok(Some((_, ski))) = self.cert.tbs_certificate.get::<SubjectKeyIdentifier>() {
            return Ok(AuthorityKeyIdentifier {
                key_identifier: Some(ski.0),
                authority_cert_issuer: None,
                authority_cert_serial_number: None,
            });
        }
        AuthorityKeyIdentifier::try_from(
            self.cert
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref(),
        )
        .map_err(|e| AppError::crypto(format!("authority key identifier: {e}")))
    }
}

fn bld_err(e: x509_cert::builder::Error) -> AppError {
    AppError::crypto(format!("certificate builder error: {e}"))
}

fn der_err(e: der::Error) -> AppError {
    AppError::crypto(format!("DER error: {e}"))
}
