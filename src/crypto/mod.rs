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
    pub const ID_SHA384: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_384;
    pub const ID_SHA512: ObjectIdentifier = const_oid::db::rfc5912::ID_SHA_512;

    pub const RSA_ENCRYPTION: ObjectIdentifier = const_oid::db::rfc5912::RSA_ENCRYPTION;
    pub const SHA1_WITH_RSA: ObjectIdentifier = const_oid::db::rfc5912::SHA_1_WITH_RSA_ENCRYPTION;
    pub const SHA256_WITH_RSA: ObjectIdentifier =
        const_oid::db::rfc5912::SHA_256_WITH_RSA_ENCRYPTION;
    pub const SHA384_WITH_RSA: ObjectIdentifier =
        const_oid::db::rfc5912::SHA_384_WITH_RSA_ENCRYPTION;
    pub const SHA512_WITH_RSA: ObjectIdentifier =
        const_oid::db::rfc5912::SHA_512_WITH_RSA_ENCRYPTION;

    pub const ID_AES_128_CBC: ObjectIdentifier = const_oid::db::rfc5911::ID_AES_128_CBC;
    pub const ID_AES_192_CBC: ObjectIdentifier = const_oid::db::rfc5911::ID_AES_192_CBC;
    pub const ID_AES_256_CBC: ObjectIdentifier = const_oid::db::rfc5911::ID_AES_256_CBC;
    /// des-ede3-cbc (3DES)
    pub const ID_DES_EDE3_CBC: ObjectIdentifier =
        ObjectIdentifier::new_unwrap("1.2.840.113549.3.7");
    // Single DES (56-bit) is deliberately not supported: a captured request
    // would give up its challenge password to a brute-force search.
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
    if spki.algorithm.oid != oids::RSA_ENCRYPTION {
        return Err(AppError::crypto(format!(
            "not an RSA key (algorithm {})",
            spki.algorithm.oid
        )));
    }
    RsaPublicKey::from_pkcs1_der(spki.subject_public_key.raw_bytes())
        .map_err(|e| AppError::crypto(format!("not an RSA key: {e}")))
}

/// The hash functions accepted in signatures from SCEP clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    /// Resolve a digest algorithm OID (as used in a CMS `SignerInfo`).
    pub fn from_digest_oid(oid: ObjectIdentifier) -> Option<Self> {
        Some(match oid {
            oids::ID_SHA1 => Self::Sha1,
            oids::ID_SHA256 => Self::Sha256,
            oids::ID_SHA384 => Self::Sha384,
            oids::ID_SHA512 => Self::Sha512,
            _ => return None,
        })
    }

    /// Resolve an RSA PKCS#1 v1.5 signature algorithm OID (as used in a CSR).
    pub fn from_rsa_signature_oid(oid: ObjectIdentifier) -> Option<Self> {
        Some(match oid {
            oids::SHA1_WITH_RSA => Self::Sha1,
            oids::SHA256_WITH_RSA => Self::Sha256,
            oids::SHA384_WITH_RSA => Self::Sha384,
            oids::SHA512_WITH_RSA => Self::Sha512,
            _ => return None,
        })
    }

    /// Hash `data`.
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        use sha2::Digest;
        match self {
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
            Self::Sha256 => sha2::Sha256::digest(data).to_vec(),
            Self::Sha384 => sha2::Sha384::digest(data).to_vec(),
            Self::Sha512 => sha2::Sha512::digest(data).to_vec(),
        }
    }

    /// Verify an RSA PKCS#1 v1.5 signature over `msg`.
    pub fn verify_rsa(self, key: &RsaPublicKey, msg: &[u8], sig: &[u8]) -> bool {
        use rsa::pkcs1v15::{Signature, VerifyingKey};
        use signature::Verifier;
        let Ok(sig) = Signature::try_from(sig) else {
            return false;
        };
        let key = key.clone();
        match self {
            Self::Sha1 => VerifyingKey::<sha1::Sha1>::new(key).verify(msg, &sig),
            Self::Sha256 => VerifyingKey::<sha2::Sha256>::new(key).verify(msg, &sig),
            Self::Sha384 => VerifyingKey::<sha2::Sha384>::new(key).verify(msg, &sig),
            Self::Sha512 => VerifyingKey::<sha2::Sha512>::new(key).verify(msg, &sig),
        }
        .is_ok()
    }
}

fn der_err(e: der::Error) -> AppError {
    AppError::crypto(format!("DER error: {e}"))
}
