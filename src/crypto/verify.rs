//! Parse and verify an inbound SCEP `pkiMessage` (a CMS `SignedData`).
//!
//! The `cms` crate has no signature verifier, so we:
//!   1. decode the `SignedData` and locate the signer's certificate,
//!   2. re-encode the `signedAttrs` as a `SET OF` (the field is stored as a
//!      `SetOfVec`, so `to_der()` yields the `SET OF` form that was signed,
//!      not the `[0] IMPLICIT` wire form),
//!   3. verify the RSA signature over those bytes,
//!   4. check that the `messageDigest` signed attribute equals the digest of
//!      the encapsulated content.

use cms::content_info::ContentInfo;
use cms::enveloped_data::EnvelopedData;
use cms::signed_data::{SignedData, SignerIdentifier, SignerInfo};
use const_oid::ObjectIdentifier;
use der::{Decode, Encode};
use rsa::RsaPublicKey;
use sha2::Digest;
use signature::Verifier;
use x509_cert::attr::Attribute;
use x509_cert::Certificate;

use crate::crypto::{oids, rsa_public_key};
use crate::error::{AppError, AppResult};
use crate::scep::attributes as scep_attr;
use crate::scep::attributes::MessageType;

/// The verified contents of an inbound SCEP request.
pub struct ParsedRequest {
    pub message_type: MessageType,
    pub transaction_id: String,
    pub sender_nonce: Vec<u8>,
    /// The requester's certificate (self-signed for a first enrolment).
    pub signer_cert: Certificate,
    /// The decrypted-later envelope, present for PKCSReq / RenewalReq.
    pub enveloped: Option<EnvelopedData>,
}

/// Decode a `SignedData`, verify its signature, and extract SCEP metadata.
pub fn parse_and_verify(der: &[u8]) -> AppResult<ParsedRequest> {
    let ci = ContentInfo::from_der(der)
        .map_err(|e| AppError::bad_request(format!("not a CMS ContentInfo: {e}")))?;
    if ci.content_type != oids::ID_SIGNED_DATA {
        return Err(AppError::bad_request("SCEP message is not signedData"));
    }
    let sd: SignedData = ci
        .content
        .decode_as()
        .map_err(|e| AppError::bad_request(format!("bad SignedData: {e}")))?;

    let signer = sd
        .signer_infos
        .0
        .iter()
        .next()
        .ok_or_else(|| AppError::bad_request("SignedData has no SignerInfo"))?;

    let signer_cert = find_signer_cert(&sd, &signer.sid)?;

    verify_signer(&sd, signer, &signer_cert)?;

    let attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| AppError::bad_request("SignerInfo has no signed attributes"))?;

    let message_type =
        MessageType::from_value(&scep_attr::read_string(attrs, scep_attr::ID_MESSAGE_TYPE)?)?;
    let transaction_id = scep_attr::read_string(attrs, scep_attr::ID_TRANSACTION_ID)?;
    let sender_nonce = scep_attr::read_octets(attrs, scep_attr::ID_SENDER_NONCE)?;

    // PKCSReq / RenewalReq carry an enveloped CSR; a SUCCESS CertRep carries an
    // enveloped certs-only reply. (GetCert / GetCertInitial carry a plain
    // issuerAndSerial, not an envelope, and are not handled in v1.)
    let enveloped = match message_type {
        MessageType::PkcsReq | MessageType::RenewalReq | MessageType::CertRep => {
            econtent_bytes(&sd)
                .map(|content| crate::crypto::envelope::parse(&content))
                .transpose()?
        }
        _ => None,
    };

    Ok(ParsedRequest {
        message_type,
        transaction_id,
        sender_nonce,
        signer_cert,
        enveloped,
    })
}

fn verify_signer(sd: &SignedData, signer: &SignerInfo, signer_cert: &Certificate) -> AppResult<()> {
    let attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| AppError::bad_request("SCEP requires signed attributes"))?;

    // Re-encode as SET OF: this is the tbsSignedAttrs that was actually signed.
    let signed_attrs_der = attrs
        .to_der()
        .map_err(|e| AppError::crypto(format!("re-encode signed attrs: {e}")))?;

    let pubkey = rsa_public_key(signer_cert)?;
    verify_rsa(
        signer.digest_alg.oid,
        &pubkey,
        &signed_attrs_der,
        signer.signature.as_bytes(),
    )?;

    // Bind the signed attributes to the content: messageDigest == H(eContent).
    if let Some(content) = econtent_bytes(sd) {
        let md_attr = find_attr(attrs.iter(), const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
            .ok_or_else(|| AppError::bad_request("missing messageDigest attribute"))?;
        let claimed = md_attr
            .values
            .iter()
            .next()
            .and_then(|v| v.decode_as::<der::asn1::OctetString>().ok())
            .ok_or_else(|| AppError::bad_request("bad messageDigest attribute"))?;
        let computed = digest(signer.digest_alg.oid, &content)?;
        if claimed.as_bytes() != computed.as_slice() {
            return Err(AppError::bad_request(
                "messageDigest does not match content",
            ));
        }
    }
    Ok(())
}

fn verify_rsa(
    digest_oid: ObjectIdentifier,
    pubkey: &RsaPublicKey,
    msg: &[u8],
    sig: &[u8],
) -> AppResult<()> {
    let signature = rsa::pkcs1v15::Signature::try_from(sig)
        .map_err(|e| AppError::bad_request(format!("malformed signature: {e}")))?;
    let result =
        match digest_oid {
            oids::ID_SHA256 => rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(pubkey.clone())
                .verify(msg, &signature),
            oids::ID_SHA1 => rsa::pkcs1v15::VerifyingKey::<sha1::Sha1>::new(pubkey.clone())
                .verify(msg, &signature),
            other => {
                return Err(AppError::bad_request(format!(
                    "unsupported signature digest {other}"
                )))
            }
        };
    result.map_err(|_| AppError::bad_request("SCEP message signature is invalid"))
}

fn digest(oid: ObjectIdentifier, data: &[u8]) -> AppResult<Vec<u8>> {
    Ok(match oid {
        oids::ID_SHA256 => sha2::Sha256::digest(data).to_vec(),
        oids::ID_SHA1 => sha1::Sha1::digest(data).to_vec(),
        other => return Err(AppError::bad_request(format!("unsupported digest {other}"))),
    })
}

/// Return the raw bytes of the encapsulated content (the value of the eContent
/// OCTET STRING), if present.
fn econtent_bytes(sd: &SignedData) -> Option<Vec<u8>> {
    sd.encap_content_info
        .econtent
        .as_ref()
        .map(|any| any.value().to_vec())
}

fn find_signer_cert(sd: &SignedData, sid: &SignerIdentifier) -> AppResult<Certificate> {
    let set = sd
        .certificates
        .as_ref()
        .ok_or_else(|| AppError::bad_request("SignedData carries no certificates"))?;

    let certs: Vec<&Certificate> = set
        .0
        .iter()
        .filter_map(|choice| match choice {
            cms::cert::CertificateChoices::Certificate(c) => Some(c),
            _ => None,
        })
        .collect();

    if certs.len() == 1 {
        return Ok(certs[0].clone());
    }
    if let SignerIdentifier::IssuerAndSerialNumber(ias) = sid {
        for c in &certs {
            if c.tbs_certificate.issuer == ias.issuer
                && c.tbs_certificate.serial_number == ias.serial_number
            {
                return Ok((*c).clone());
            }
        }
    }
    certs
        .first()
        .map(|c| (*c).clone())
        .ok_or_else(|| AppError::bad_request("no signer certificate found"))
}

fn find_attr<'a>(
    mut attrs: impl Iterator<Item = &'a Attribute>,
    oid: ObjectIdentifier,
) -> Option<&'a Attribute> {
    attrs.find(|a| a.oid == oid)
}
