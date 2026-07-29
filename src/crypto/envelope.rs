//! CMS `EnvelopedData`: decrypt an inbound SCEP request (`open`) and encrypt an
//! outbound response (`build`).
//!
//! The `cms` crate models the ASN.1 but provides no recipient-side
//! decryption, so `open` does it by hand: RSA-unwrap the content-encryption
//! key (CEK) from the matching
//! `KeyTransRecipientInfo`, read the CBC IV from the algorithm parameters, then
//! symmetric-decrypt the content.

use cipher::block_padding::Pkcs7;
use cipher::{BlockDecryptMut, KeyIvInit};
use cms::builder::{
    ContentEncryptionAlgorithm, EnvelopedDataBuilder, KeyEncryptionInfo,
    KeyTransRecipientInfoBuilder,
};
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::ContentInfo;
use cms::enveloped_data::{
    EnvelopedData, KeyTransRecipientInfo, RecipientIdentifier, RecipientInfo,
};
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString};
use der::{Decode, Encode};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};
use x509_cert::Certificate;

use crate::crypto::{der_err, oids, rsa_public_key};
use crate::error::{AppError, AppResult};

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

/// Encrypt `plaintext` to a single recipient (`recipient_cert`) using
/// AES-256-CBC and RSA key transport, returning the `EnvelopedData`.
pub fn build(plaintext: &[u8], recipient_cert: &Certificate) -> AppResult<EnvelopedData> {
    let rid = RecipientIdentifier::IssuerAndSerialNumber(issuer_and_serial(recipient_cert));
    let pubkey = rsa_public_key(recipient_cert)?;

    // The recipient builder needs an RNG to encrypt the CEK, and the enveloped
    // builder needs one to generate the CEK+IV, so we make two handles.
    let mut rng_recipient = rand::thread_rng();
    let mut rng_content = rand::thread_rng();

    let recipient =
        KeyTransRecipientInfoBuilder::new(rid, KeyEncryptionInfo::Rsa(pubkey), &mut rng_recipient)
            .map_err(builder_err)?;

    let mut builder =
        EnvelopedDataBuilder::new(None, plaintext, ContentEncryptionAlgorithm::Aes256Cbc, None)
            .map_err(builder_err)?;
    builder.add_recipient_info(recipient).map_err(builder_err)?;
    builder
        .build_with_rng(&mut rng_content)
        .map_err(builder_err)
}

/// Wrap an `EnvelopedData` in a `ContentInfo` and DER-encode it (the SCEP
/// `pkcsPKIEnvelope` that becomes a `CertRep`'s message data).
pub fn to_content_info_der(enveloped: &EnvelopedData) -> AppResult<Vec<u8>> {
    let ci = ContentInfo {
        content_type: oids::ID_ENVELOPED_DATA,
        content: Any::encode_from(enveloped).map_err(der_err)?,
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

fn issuer_and_serial(cert: &Certificate) -> IssuerAndSerialNumber {
    IssuerAndSerialNumber {
        issuer: cert.tbs_certificate.issuer.clone(),
        serial_number: cert.tbs_certificate.serial_number.clone(),
    }
}

fn builder_err(e: cms::builder::Error) -> AppError {
    AppError::crypto(format!("CMS builder error: {e}"))
}
