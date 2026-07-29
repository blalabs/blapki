//! A certificate authority: its certificate, signing key, and the logic to
//! issue leaf certificates from a CSR.

use core::time::Duration;
use std::str::FromStr;

use der::referenced::OwnedToRef;
use rsa::RsaPrivateKey;
use signature::Keypair;
use x509_cert::builder::{Builder, CertificateBuilder, Profile};
use x509_cert::ext::pkix::{AuthorityKeyIdentifier, BasicConstraints, SubjectKeyIdentifier};
use x509_cert::name::Name;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;
use x509_cert::Certificate;

use crate::ca::{extensions, serial};
use crate::crypto::CaSigningKey;
use crate::error::{AppError, AppResult};

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
}

impl CertificateAuthority {
    /// Construct from an existing certificate and private key.
    pub fn new(id: impl Into<String>, cert: Certificate, private_key: RsaPrivateKey) -> Self {
        let signing_key = CaSigningKey::new(private_key.clone());
        Self {
            id: id.into(),
            cert,
            signing_key,
            private_key,
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
        let validity = Validity::from_now(Duration::from_secs(opts.validity_days as u64 * 86_400))
            .map_err(der_err)?;
        let subject = csr.info.subject.clone();
        let spki = csr.info.public_key.clone();

        let ski = SubjectKeyIdentifier::try_from(spki.owned_to_ref())
            .map_err(|e| AppError::crypto(format!("subject key identifier: {e}")))?;
        let aki = AuthorityKeyIdentifier::try_from(
            self.cert
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref(),
        )
        .map_err(|e| AppError::crypto(format!("authority key identifier: {e}")))?;

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
        builder
            .add_extension(&extensions::key_usage(&opts.key_usage)?)
            .map_err(bld_err)?;
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

fn bld_err(e: x509_cert::builder::Error) -> AppError {
    AppError::crypto(format!("certificate builder error: {e}"))
}

fn der_err(e: der::Error) -> AppError {
    AppError::crypto(format!("DER error: {e}"))
}
