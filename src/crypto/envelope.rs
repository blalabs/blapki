//! CMS `EnvelopedData`: decrypt an inbound SCEP request (`open`) and encrypt an
//! outbound response (`build`).
//!
//! The `cms` crate models the ASN.1 but provides no recipient-side
//! decryption, so `open` does it by hand: RSA-unwrap the content-encryption
//! key (CEK) from the matching
//! `KeyTransRecipientInfo`, read the CBC IV from the algorithm parameters, then
//! symmetric-decrypt the content.
//!
//! The CEK unwrap uses RSA PKCS#1 v1.5, which is open to Bleichenbacher's
//! padding-oracle attack if a caller can tell a padding failure apart from
//! any later failure. `open` therefore uses implicit rejection: a CEK that
//! fails to unwrap (or has the wrong length) is silently replaced by a
//! deterministic secret-derived key, and decryption carries on as normal.
//! Callers must still map every `open` error to one uniform response.

use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::enveloped_data::{
    EncryptedContentInfo, EnvelopedData, KeyTransRecipientInfo, RecipientIdentifier, RecipientInfo,
};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, Null, OctetString, SetOfVec};
use der::{Decode, Encode, Sequence, Tag};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rsa::traits::PrivateKeyParts;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};
use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::Raw;
use x509_cert::ext::pkix::SubjectKeyIdentifier;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::Certificate;

use crate::crypto::{der_err, oids, rsa_public_key};
use crate::error::{AppError, AppResult};

/// A serial number decoded without the RFC 5280 20-octet cap. SCEP clients such
/// as sscep use longer serials (a hex transaction id) in their self-signed
/// signer certificate, and the reply must echo that serial exactly so the
/// client's `PKCS7_decrypt` matches the recipient.
pub type RawSerial = SerialNumber<Raw>;

/// The recipient of an outbound `EnvelopedData` (the enrolling device).
pub struct Recipient<'a> {
    pub public_key: &'a RsaPublicKey,
    pub issuer: &'a Name,
    pub serial: &'a RawSerial,
}

/// Decrypt an `EnvelopedData` addressed to `ca_cert`/`ca_key` and return the
/// recovered plaintext (for SCEP: the DER-encoded PKCS#10 CSR).
pub fn open(
    enveloped: &EnvelopedData,
    ca_cert: &Certificate,
    ca_key: &RsaPrivateKey,
) -> AppResult<Vec<u8>> {
    // Every check that depends only on public data runs before the RSA step.
    let eci = &enveloped.encrypted_content;
    let key_len = content_key_len(eci.content_enc_alg.oid)?;
    let ciphertext = eci
        .encrypted_content
        .as_ref()
        .ok_or_else(|| AppError::crypto("enveloped data has no encrypted content"))?
        .as_bytes();
    let iv = read_iv(&eci.content_enc_alg.parameters)?;
    let ktri = select_recipient(enveloped, ca_cert)?;

    let cek = unwrap_cek(ca_key, ktri.enc_key.as_bytes(), key_len);
    decrypt_symmetric(eci.content_enc_alg.oid, &cek, &iv, ciphertext)
}

/// The reply's `KeyTransRecipientInfo`, encoded by hand so the recipient serial
/// is a plain (uncapped) INTEGER rather than the RFC 5280 `SerialNumber` used by
/// the `cms` builder.
#[derive(Sequence)]
struct OutIssuerAndSerial {
    issuer: Name,
    serial_number: RawSerial,
}

#[derive(Sequence)]
struct OutKeyTransRecipientInfo {
    version: CmsVersion,
    rid: OutIssuerAndSerial,
    key_enc_alg: AlgorithmIdentifierOwned,
    enc_key: OctetString,
}

#[derive(Sequence)]
struct OutEnvelopedData {
    version: CmsVersion,
    recip_infos: SetOfVec<Any>,
    encrypted_content: EncryptedContentInfo,
}

/// Encrypt `plaintext` to a certificate recipient. Convenience wrapper used by
/// tests; production code uses [`build_for`] with the parsed recipient.
pub fn build(plaintext: &[u8], recipient_cert: &Certificate) -> AppResult<Vec<u8>> {
    let public_key = rsa_public_key(recipient_cert)?;
    let issuer = recipient_cert.tbs_certificate.issuer.clone();
    let serial = SerialNumber::<Raw>::new(recipient_cert.tbs_certificate.serial_number.as_bytes())
        .map_err(der_err)?;
    build_for(
        plaintext,
        &Recipient {
            public_key: &public_key,
            issuer: &issuer,
            serial: &serial,
        },
    )
}

/// Encrypt `plaintext` to `recipient` with AES-256-CBC + RSA key transport and
/// return the DER of a `ContentInfo` wrapping the `EnvelopedData` (the SCEP
/// `pkcsPKIEnvelope`).
pub fn build_for(plaintext: &[u8], recipient: &Recipient) -> AppResult<Vec<u8>> {
    let mut rng = rand::thread_rng();

    // Content-encryption key + IV for AES-256-CBC.
    let mut cek = [0u8; 32];
    let mut iv = [0u8; 16];
    rng.fill_bytes(&mut cek);
    rng.fill_bytes(&mut iv);

    let ciphertext = cbc::Encryptor::<aes::Aes256>::new_from_slices(&cek, &iv)
        .map_err(|_| AppError::crypto("invalid AES key/IV length"))?
        .encrypt_padded_vec_mut::<Pkcs7>(plaintext);

    // RSA-wrap the CEK to the recipient.
    let encrypted_key = recipient
        .public_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, &cek)
        .map_err(|e| AppError::crypto(format!("RSA key wrap failed: {e}")))?;

    let ktri = OutKeyTransRecipientInfo {
        version: CmsVersion::V0,
        rid: OutIssuerAndSerial {
            issuer: recipient.issuer.clone(),
            serial_number: recipient.serial.clone(),
        },
        key_enc_alg: AlgorithmIdentifierOwned {
            oid: const_oid::db::rfc5912::RSA_ENCRYPTION,
            parameters: Some(Any::from(Null)),
        },
        enc_key: OctetString::new(encrypted_key).map_err(der_err)?,
    };

    let mut recip_infos = SetOfVec::new();
    recip_infos
        .insert(Any::encode_from(&ktri).map_err(der_err)?)
        .map_err(der_err)?;

    let encrypted_content = EncryptedContentInfo {
        content_type: oids::ID_DATA,
        content_enc_alg: AlgorithmIdentifierOwned {
            oid: oids::ID_AES_256_CBC,
            parameters: Some(Any::new(Tag::OctetString, iv.to_vec()).map_err(der_err)?),
        },
        encrypted_content: Some(OctetString::new(ciphertext).map_err(der_err)?),
    };

    let enveloped = OutEnvelopedData {
        version: CmsVersion::V0,
        recip_infos,
        encrypted_content,
    };

    let ci = ContentInfo {
        content_type: oids::ID_ENVELOPED_DATA,
        content: Any::encode_from(&enveloped).map_err(der_err)?,
    };
    ci.to_der().map_err(der_err)
}

/// Parse DER that is either a bare `EnvelopedData` or a `ContentInfo` wrapping
/// one. SCEP message data is a `ContentInfo`, but be lenient.
pub fn parse(der: &[u8]) -> AppResult<EnvelopedData> {
    if let Ok(ci) = ContentInfo::from_der(der) {
        if ci.content_type == oids::ID_ENVELOPED_DATA {
            return ci
                .content
                .decode_as::<EnvelopedData>()
                .map_err(|e| AppError::crypto(format!("bad EnvelopedData in ContentInfo: {e}")));
        }
    }
    EnvelopedData::from_der(der).map_err(|e| AppError::crypto(format!("not an EnvelopedData: {e}")))
}

/// Pick the key-transport recipient to unwrap, using only the public recipient
/// identifiers. The choice must never depend on whether an unwrap succeeds:
/// "try each recipient until one decrypts" lets an attacker pair a probe
/// ciphertext with a known-good one and read the padding result from which
/// key ended up being used.
fn select_recipient<'a>(
    enveloped: &'a EnvelopedData,
    ca_cert: &Certificate,
) -> AppResult<&'a KeyTransRecipientInfo> {
    let ktris: Vec<&KeyTransRecipientInfo> = enveloped
        .recip_infos
        .0
        .iter()
        .filter_map(|ri| match ri {
            RecipientInfo::Ktri(ktri) => Some(ktri),
            _ => None,
        })
        .collect();
    if let Some(ktri) = ktris.iter().find(|ktri| ktri_matches(ktri, ca_cert)) {
        return Ok(ktri);
    }
    // Be lenient with a lone recipient whose identifier we do not recognise.
    match ktris.as_slice() {
        [only] => Ok(only),
        _ => Err(AppError::crypto(
            "no key-transport recipient names the CA certificate",
        )),
    }
}

/// RSA-unwrap the CEK with implicit rejection: if the PKCS#1 v1.5 padding is
/// invalid or the key has the wrong length for the content cipher, return a
/// synthetic key instead of an error. The bad CEK then fails later, at the
/// symmetric unpad or CSR parse, exactly like a well-padded but wrong one.
///
/// This removes the explicit oracle. The `rsa` crate's decryption is not
/// constant time (RUSTSEC-2023-0071, "Marvin"), so a timing side channel
/// remains; a separate RA decryption key is the fix for that.
fn unwrap_cek(ca_key: &RsaPrivateKey, encrypted_key: &[u8], key_len: usize) -> Vec<u8> {
    // Derive the fallback up front so both outcomes do the same work.
    let synthetic = synthetic_cek(ca_key, encrypted_key, key_len);
    match ca_key.decrypt_blinded(&mut rand::thread_rng(), Pkcs1v15Encrypt, encrypted_key) {
        Ok(cek) if cek.len() == key_len => cek,
        _ => synthetic,
    }
}

/// A CEK derived from the encrypted key with HMAC-SHA256, keyed by a hash of
/// the CA's private exponent. It is unpredictable to an attacker but stable
/// for a given ciphertext, so resending the same probe changes nothing.
fn synthetic_cek(ca_key: &RsaPrivateKey, encrypted_key: &[u8], key_len: usize) -> Vec<u8> {
    let kdk = Sha256::new()
        .chain_update(b"blapki implicit rejection")
        .chain_update(ca_key.d().to_bytes_be())
        .finalize();
    let mut mac = Hmac::<Sha256>::new_from_slice(&kdk).expect("HMAC accepts any key length");
    mac.update(encrypted_key);
    // key_len is at most 32 (AES-256), the HMAC-SHA256 output size.
    mac.finalize().into_bytes()[..key_len].to_vec()
}

fn ktri_matches(ktri: &KeyTransRecipientInfo, ca_cert: &Certificate) -> bool {
    match &ktri.rid {
        RecipientIdentifier::IssuerAndSerialNumber(ias) => {
            ias.issuer == ca_cert.tbs_certificate.issuer
                && ias.serial_number == ca_cert.tbs_certificate.serial_number
        }
        RecipientIdentifier::SubjectKeyIdentifier(ski) => ca_cert
            .tbs_certificate
            .get::<SubjectKeyIdentifier>()
            .ok()
            .flatten()
            .is_some_and(|(_, ca_ski)| ca_ski.0.as_bytes() == ski.0.as_bytes()),
    }
}

/// Key length in bytes of a supported content-encryption algorithm.
fn content_key_len(alg: ObjectIdentifier) -> AppResult<usize> {
    Ok(match alg {
        oids::ID_AES_128_CBC => 16,
        oids::ID_AES_192_CBC => 24,
        oids::ID_AES_256_CBC => 32,
        oids::ID_DES_EDE3_CBC => 24,
        oids::ID_DES_CBC => 8,
        other => {
            return Err(AppError::crypto(format!(
                "unsupported content encryption algorithm {other}"
            )))
        }
    })
}

fn read_iv(parameters: &Option<Any>) -> AppResult<Vec<u8>> {
    let any = parameters
        .as_ref()
        .ok_or_else(|| AppError::crypto("content encryption algorithm has no IV parameter"))?;
    let iv = any
        .decode_as::<OctetString>()
        .map_err(|e| AppError::crypto(format!("IV is not an OCTET STRING: {e}")))?;
    Ok(iv.as_bytes().to_vec())
}

fn decrypt_symmetric(
    alg: ObjectIdentifier,
    key: &[u8],
    iv: &[u8],
    ciphertext: &[u8],
) -> AppResult<Vec<u8>> {
    let unpad = |r: Result<Vec<u8>, cipher::block_padding::UnpadError>| {
        r.map_err(|_| AppError::crypto("content decryption / unpad failed"))
    };
    let bad_key = |_| AppError::crypto("invalid key/IV length for content cipher");

    match alg {
        oids::ID_AES_128_CBC => {
            let c = cbc::Decryptor::<aes::Aes128>::new_from_slices(key, iv).map_err(bad_key)?;
            unpad(c.decrypt_padded_vec_mut::<Pkcs7>(ciphertext))
        }
        oids::ID_AES_192_CBC => {
            let c = cbc::Decryptor::<aes::Aes192>::new_from_slices(key, iv).map_err(bad_key)?;
            unpad(c.decrypt_padded_vec_mut::<Pkcs7>(ciphertext))
        }
        oids::ID_AES_256_CBC => {
            let c = cbc::Decryptor::<aes::Aes256>::new_from_slices(key, iv).map_err(bad_key)?;
            unpad(c.decrypt_padded_vec_mut::<Pkcs7>(ciphertext))
        }
        oids::ID_DES_EDE3_CBC => {
            let c = cbc::Decryptor::<des::TdesEde3>::new_from_slices(key, iv).map_err(bad_key)?;
            unpad(c.decrypt_padded_vec_mut::<Pkcs7>(ciphertext))
        }
        oids::ID_DES_CBC => {
            let c = cbc::Decryptor::<des::Des>::new_from_slices(key, iv).map_err(bad_key)?;
            unpad(c.decrypt_padded_vec_mut::<Pkcs7>(ciphertext))
        }
        other => Err(AppError::crypto(format!(
            "unsupported content encryption algorithm {other}"
        ))),
    }
}
