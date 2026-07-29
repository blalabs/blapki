//! Parse and verify an inbound SCEP `pkiMessage` (a CMS `SignedData`).
//!
//! The `cms` crate has no signature verifier, and its strict types reject the
//! oversized serial numbers some SCEP clients (e.g. sscep) put in their
//! self-signed signer certificate. So the `SignedData` is decoded with relaxed
//! `der` types: the embedded certificate uses x509-cert's `Raw` profile (no
//! RFC 5280 20-octet serial cap) and the `SignerInfo`'s `sid` is left as raw
//! bytes. From there we:
//!   1. locate the signer certificate and its public key,
//!   2. re-encode the `signedAttrs` as a `SET OF` (the form that was signed),
//!   3. verify the RSA signature over those bytes,
//!   4. check that the `messageDigest` signed attribute equals the digest of
//!      the encapsulated content.

use cms::content_info::ContentInfo;
use cms::enveloped_data::EnvelopedData;
use cms::signed_data::EncapsulatedContentInfo;
use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString};
use der::{Decode, Encode, Sequence, SliceReader};
use rsa::RsaPublicKey;
use sha2::Digest;
use signature::Verifier;
use spki::AlgorithmIdentifierOwned;
use x509_cert::attr::{Attribute, Attributes};
use x509_cert::certificate::{CertificateInner, Raw};
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;

use crate::crypto::{envelope, oids, rsa_public_key_from_spki};
use crate::error::{AppError, AppResult};
use crate::scep::attributes as scep_attr;
use crate::scep::attributes::MessageType;

/// A certificate parsed without the RFC 5280 serial-length constraint.
type RelaxedCertificate = CertificateInner<Raw>;

/// Everything needed to encrypt the reply back to the requesting device.
pub struct RecipientKey {
    pub public_key: RsaPublicKey,
    pub issuer: Name,
    /// The device certificate's serial, preserved verbatim (may exceed 20
    /// octets) so the reply's recipient matches at the client.
    pub serial: SerialNumber<Raw>,
}

/// The verified contents of an inbound SCEP request.
pub struct ParsedRequest {
    pub message_type: MessageType,
    pub transaction_id: String,
    pub sender_nonce: Vec<u8>,
    /// The requester's key + identity, used to envelope the reply.
    pub recipient: RecipientKey,
    /// The decrypted-later envelope, present for PKCSReq / RenewalReq.
    pub enveloped: Option<EnvelopedData>,
}

/// Relaxed `SignedData`: serial-bearing fields are kept as raw `Any` so the
/// strict `cms`/`x509-cert` serial limits do not reject the message.
#[derive(Sequence)]
struct RelaxedSignedData {
    version: Any,
    digest_algorithms: Any,
    encap_content_info: EncapsulatedContentInfo,
    #[asn1(context_specific = "0", tag_mode = "IMPLICIT", optional = "true")]
    certificates: Option<Any>,
    #[asn1(context_specific = "1", tag_mode = "IMPLICIT", optional = "true")]
    crls: Option<Any>,
    signer_infos: Any,
}

/// Relaxed `SignerInfo`: `sid` (an issuer+serial) is kept raw.
#[derive(Sequence)]
struct RelaxedSignerInfo {
    version: Any,
    sid: Any,
    digest_alg: AlgorithmIdentifierOwned,
    #[asn1(
        context_specific = "0",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    signed_attrs: Option<Attributes>,
    signature_algorithm: AlgorithmIdentifierOwned,
    signature: OctetString,
    #[asn1(
        context_specific = "1",
        tag_mode = "IMPLICIT",
        constructed = "true",
        optional = "true"
    )]
    unsigned_attrs: Option<Any>,
}

/// Decode a `SignedData`, verify its signature, and extract SCEP metadata.
pub fn parse_and_verify(der: &[u8]) -> AppResult<ParsedRequest> {
    let ci = ContentInfo::from_der(der)
        .map_err(|e| AppError::bad_request(format!("not a CMS ContentInfo: {e}")))?;
    if ci.content_type != oids::ID_SIGNED_DATA {
        return Err(AppError::bad_request("SCEP message is not signedData"));
    }
    let sd: RelaxedSignedData = ci
        .content
        .decode_as()
        .map_err(|e| AppError::bad_request(format!("bad SignedData: {e}")))?;

    // SCEP messages carry exactly one signer and its self-signed certificate.
    let signer: RelaxedSignerInfo = decode_first(&sd.signer_infos, "SignerInfo")?;
    let certs = sd
        .certificates
        .as_ref()
        .ok_or_else(|| AppError::bad_request("SignedData carries no certificates"))?;
    let cert: RelaxedCertificate = decode_first(certs, "certificate")?;

    let attrs = signer
        .signed_attrs
        .as_ref()
        .ok_or_else(|| AppError::bad_request("SignerInfo has no signed attributes"))?;

    let public_key = rsa_public_key_from_spki(&cert.tbs_certificate.subject_public_key_info)?;

    // Verify the signature over the re-encoded SET OF signedAttrs.
    let signed_attrs_der = attrs
        .to_der()
        .map_err(|e| AppError::crypto(format!("re-encode signed attrs: {e}")))?;
    verify_rsa(
        signer.digest_alg.oid,
        &public_key,
        &signed_attrs_der,
        signer.signature.as_bytes(),
    )?;

    // Bind the signed attributes to the content: messageDigest == H(eContent).
    let econtent = sd
        .encap_content_info
        .econtent
        .as_ref()
        .map(|any| any.value().to_vec());
    if let Some(content) = &econtent {
        let md_attr = find_attr(attrs.iter(), const_oid::db::rfc5911::ID_MESSAGE_DIGEST)
            .ok_or_else(|| AppError::bad_request("missing messageDigest attribute"))?;
        let claimed = md_attr
            .values
            .iter()
            .next()
            .and_then(|v| v.decode_as::<OctetString>().ok())
            .ok_or_else(|| AppError::bad_request("bad messageDigest attribute"))?;
        let computed = digest(signer.digest_alg.oid, content)?;
        if claimed.as_bytes() != computed.as_slice() {
            return Err(AppError::bad_request(
                "messageDigest does not match content",
            ));
        }
    }

    let message_type =
        MessageType::from_value(&scep_attr::read_string(attrs, scep_attr::ID_MESSAGE_TYPE)?)?;
    let transaction_id = scep_attr::read_string(attrs, scep_attr::ID_TRANSACTION_ID)?;
    let sender_nonce = scep_attr::read_octets(attrs, scep_attr::ID_SENDER_NONCE)?;

    // PKCSReq / RenewalReq carry an enveloped CSR; a SUCCESS CertRep carries an
    // enveloped certs-only reply.
    let enveloped = match message_type {
        MessageType::PkcsReq | MessageType::RenewalReq | MessageType::CertRep => {
            econtent.as_deref().map(envelope::parse).transpose()?
        }
        _ => None,
    };

    Ok(ParsedRequest {
        message_type,
        transaction_id,
        sender_nonce,
        recipient: RecipientKey {
            public_key,
            issuer: cert.tbs_certificate.issuer.clone(),
            serial: cert.tbs_certificate.serial_number.clone(),
        },
        enveloped,
    })
}

/// Decode the first element from the value of a SET/`[0]` container `Any`
/// (SCEP has a single signer / signer certificate).
fn decode_first<'a, T: Decode<'a>>(container: &'a Any, what: &str) -> AppResult<T> {
    let mut reader = SliceReader::new(container.value())
        .map_err(|e| AppError::bad_request(format!("bad {what} container: {e}")))?;
    T::decode(&mut reader).map_err(|e| AppError::bad_request(format!("bad {what}: {e}")))
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

fn find_attr<'a>(
    mut attrs: impl Iterator<Item = &'a Attribute>,
    oid: ObjectIdentifier,
) -> Option<&'a Attribute> {
    attrs.find(|a| a.oid == oid)
}
