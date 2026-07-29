//! CMS `EnvelopedData`: decrypt an inbound SCEP request (`open`) and encrypt an
//! outbound response (`build`).
//!
//! The `cms` crate models the ASN.1 but provides no recipient-side
//! decryption, so `open` does it by hand: RSA-unwrap the content-encryption
//! key (CEK) from the matching
//! `KeyTransRecipientInfo`, read the CBC IV from the algorithm parameters, then
//! symmetric-decrypt the content.

use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::enveloped_data::{
    EncryptedContentInfo, EnvelopedData, KeyTransRecipientInfo, RecipientIdentifier, RecipientInfo,
};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, Null, OctetString, SetOfVec};
use der::{Decode, Encode, Sequence, Tag};
use rand::RngCore;
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use spki::AlgorithmIdentifierOwned;
use x509_cert::certificate::Raw;
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
    let cek = recover_cek(enveloped, ca_cert, ca_key)?;

    let eci = &enveloped.encrypted_content;
    let ciphertext = eci
        .encrypted_content
        .as_ref()
        .ok_or_else(|| AppError::crypto("enveloped data has no encrypted content"))?
        .as_bytes();
    let iv = read_iv(&eci.content_enc_alg.parameters)?;

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

fn recover_cek(
    enveloped: &EnvelopedData,
    ca_cert: &Certificate,
    ca_key: &RsaPrivateKey,
) -> AppResult<Vec<u8>> {
    // Prefer the recipient that names our CA cert.
    for ri in enveloped.recip_infos.0.iter() {
        if let RecipientInfo::Ktri(ktri) = ri {
            if ktri_matches(ktri, ca_cert) {
                return rsa_unwrap(ca_key, ktri.enc_key.as_bytes());
            }
        }
    }
    // Fall back to trying every key-transport recipient.
    for ri in enveloped.recip_infos.0.iter() {
        if let RecipientInfo::Ktri(ktri) = ri {
            if let Ok(cek) = rsa_unwrap(ca_key, ktri.enc_key.as_bytes()) {
                return Ok(cek);
            }
        }
    }
    Err(AppError::crypto(
        "no recipient in the enveloped data could be decrypted with the CA key",
    ))
}

fn rsa_unwrap(ca_key: &RsaPrivateKey, encrypted_key: &[u8]) -> AppResult<Vec<u8>> {
    ca_key
        .decrypt(Pkcs1v15Encrypt, encrypted_key)
        .map_err(|e| AppError::crypto(format!("RSA key unwrap failed: {e}")))
}

fn ktri_matches(ktri: &KeyTransRecipientInfo, ca_cert: &Certificate) -> bool {
    match &ktri.rid {
        RecipientIdentifier::IssuerAndSerialNumber(ias) => {
            ias.issuer == ca_cert.tbs_certificate.issuer
                && ias.serial_number == ca_cert.tbs_certificate.serial_number
        }
        // SKI matching is not needed for the issuer+serial recipients Intune/
        // Windows emit; the fallback loop covers the SKI case.
        RecipientIdentifier::SubjectKeyIdentifier(_) => false,
    }
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
