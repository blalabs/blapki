//! Build and sign an outbound SCEP `CertRep` (a CMS `SignedData`).

use cms::builder::{create_content_type_attribute, SignedDataBuilder, SignerInfoBuilder};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::signed_data::{EncapsulatedContentInfo, SignerIdentifier};
use der::asn1::{Any, OctetString};
use der::Encode;
use x509_cert::attr::Attribute;
use x509_cert::Certificate;

use crate::crypto::{der_err, oids, sha256_alg, CaSigningKey};
use crate::error::{AppError, AppResult};

/// Assemble a signed `CertRep`.
///
/// * `signer` / `signer_cert`: the CA (or RA) key and certificate signing the
///   response.
/// * `message_data`: the DER `pkcsPKIEnvelope` for a SUCCESS response, or
///   `None` for FAILURE / PENDING (which carry no content).
/// * `signed_attrs`: the SCEP signed attributes (messageType, transactionID,
///   pkiStatus, senderNonce, recipientNonce, and failInfo on failure).
///
/// Returns the DER of a `ContentInfo` of type signedData.
pub fn build_cert_rep(
    signer: &CaSigningKey,
    signer_cert: &Certificate,
    message_data: Option<&[u8]>,
    signed_attrs: Vec<Attribute>,
) -> AppResult<Vec<u8>> {
    let econtent = match message_data {
        Some(data) => {
            let os = OctetString::new(data).map_err(der_err)?;
            Some(Any::encode_from(&os).map_err(der_err)?)
        }
        None => None,
    };
    let encap = EncapsulatedContentInfo {
        econtent_type: oids::ID_DATA,
        econtent,
    };

    let sid = SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
        issuer: signer_cert.tbs_certificate.issuer.clone(),
        serial_number: signer_cert.tbs_certificate.serial_number.clone(),
    });

    let digest = sha256_alg();
    let mut signer_info =
        SignerInfoBuilder::new(signer, sid, digest.clone(), &encap, None).map_err(builder_err)?;

    // When there is no content, the builder won't add a content-type attribute;
    // add it so the signed attributes remain valid CMS.
    if message_data.is_none() {
        let ct = create_content_type_attribute(oids::ID_DATA).map_err(builder_err)?;
        signer_info.add_signed_attribute(ct).map_err(builder_err)?;
    }
    for attr in signed_attrs {
        signer_info
            .add_signed_attribute(attr)
            .map_err(builder_err)?;
    }

    let mut builder = SignedDataBuilder::new(&encap);
    builder
        .add_digest_algorithm(digest)
        .map_err(builder_err)?
        .add_certificate(CertificateChoices::Certificate(signer_cert.clone()))
        .map_err(builder_err)?
        .add_signer_info::<CaSigningKey, rsa::pkcs1v15::Signature>(signer_info)
        .map_err(builder_err)?;

    let content_info = builder.build().map_err(builder_err)?;
    content_info.to_der().map_err(der_err)
}

fn builder_err(e: cms::builder::Error) -> AppError {
    AppError::crypto(format!("CMS builder error: {e}"))
}
