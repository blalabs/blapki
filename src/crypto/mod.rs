//! CMS / PKCS#7 glue for SCEP.
//!
//! Named `crypto` rather than `cms` to avoid shadowing the external `cms`
//! crate. The `cms` crate provides the ASN.1 types and a builder for the
//! *outgoing* (encrypt / sign) direction; the *incoming* direction
//! (verify a `SignedData` signature, decrypt an `EnvelopedData`) is not
//! provided by any crate and is implemented here in [`verify`] and [`envelope`].

pub mod degenerate;
pub mod envelope;
pub mod sign;
pub mod verify;

use const_oid::ObjectIdentifier;
use der::asn1::Null;
use rsa::RsaPublicKey;
use sha2::Sha256;
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;

use crate::error::{AppError, AppResult};

/// The RSA + SHA-256 signing key used by CAs to sign both certificates
/// (via the `x509-cert` builder) and CMS `SignedData` (via the `cms` builder).
pub type CaSigningKey = rsa::pkcs1v15::SigningKey<Sha256>;

/// content-type / algorithm OIDs.
pub mod oids {
    use const_oid::ObjectIdentifier;

    pub const ID_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_DATA;
    pub const ID_SIGNED_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_SIGNED_DATA;
    pub const ID_ENVELOPED_DATA: ObjectIdentifier = const_oid::db::rfc5911::ID_ENVELOPED_DATA;

    pub const ID_SHA1: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_1;
    pub const ID_SHA256: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_256;

    pub const ID_AES_128_CBC: ObjectIdentifier = const_oid::db::rfc5911::ID_AES_128_CBC;
    pub const ID_AES_192_CBC: ObjectIdentifier = const_oid::db::rfc5911::ID_AES_192_CBC;
    pub const ID_AES_256_CBC: ObjectIdentifier = const_oid::db::rfc5911::ID_AES_256_CBC;
    /// des-ede3-cbc (3DES)
    pub const ID_DES_EDE3_CBC: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.3.7");
    /// des-cbc (single DES, legacy)
    pub const ID_DES_CBC: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.14.3.2.7");
}

/// Build a digest `AlgorithmIdentifier` (parameters absent, per modern CMS).
pub fn digest_alg(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

/// The SHA-256 digest algorithm identifier, with an explicit NULL parameter,
/// as emitted by most peers.
pub fn sha256_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: oids::ID_SHA256,
        parameters: Some(der::Any::from(Null)),
    }
}

/// Extract an RSA public key from a certificate's `SubjectPublicKeyInfo`.
pub fn rsa_public_key(cert: &Certificate) -> AppResult<RsaPublicKey> {
    rsa_public_key_from_spki(&cert.tbs_certificate.subject_public_key_info)
}

/// Extract an RSA public key from a `SubjectPublicKeyInfo`.
pub fn rsa_public_key_from_spki(spki: &spki::SubjectPublicKeyInfoOwned) -> AppResult<RsaPublicKey> {
    use rsa::pkcs1::DecodeRsaPublicKey;
    RsaPublicKey::from_pkcs1_der(spki.subject_public_key.raw_bytes())
        .map_err(|e| AppError::crypto(format!("not an RSA key: {e}")))
}

fn der_err(e: der::Error) -> AppError {
    AppError::crypto(format!("DER error: {e}"))
}
