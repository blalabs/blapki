//! Certificate extension helpers: translate profile config into X.509
//! extensions and copy the SubjectAltName requested in a CSR.

use const_oid::ObjectIdentifier;
use der::Decode;
use flagset::FlagSet;
use x509_cert::ext::pkix::crl::dp::DistributionPoint;
use x509_cert::ext::pkix::name::{DistributionPointName, GeneralName, GeneralNames};
use x509_cert::ext::pkix::{
    AccessDescription, AuthorityInfoAccessSyntax, CrlDistributionPoints, ExtendedKeyUsage,
    KeyUsage, KeyUsages, SubjectAltName,
};
use x509_cert::ext::Extension;
use x509_cert::request::CertReq;

use crate::error::{AppError, AppResult};

const ID_CE_SUBJECT_ALT_NAME: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.5.29.17");
const ID_AD_OCSP: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1");
const ID_EXTENSION_REQ: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.14");

/// Build a `KeyUsage` extension from the configured usage names.
pub fn key_usage(names: &[String]) -> AppResult<KeyUsage> {
    let mut flags = FlagSet::<KeyUsages>::default();
    for name in names {
        let flag = match name.as_str() {
            "digitalSignature" => KeyUsages::DigitalSignature,
            "nonRepudiation" | "contentCommitment" => KeyUsages::NonRepudiation,
            "keyEncipherment" => KeyUsages::KeyEncipherment,
            "dataEncipherment" => KeyUsages::DataEncipherment,
            "keyAgreement" => KeyUsages::KeyAgreement,
            "keyCertSign" => KeyUsages::KeyCertSign,
            "cRLSign" | "crlSign" => KeyUsages::CRLSign,
            other => {
                return Err(AppError::Config(format!("unknown key usage '{other}'")));
            }
        };
        flags |= flag;
    }
    Ok(KeyUsage(flags))
}

/// Build an `ExtendedKeyUsage` extension from configured EKU names or OIDs.
pub fn extended_key_usage(names: &[String]) -> AppResult<ExtendedKeyUsage> {
    let mut oids = Vec::new();
    for name in names {
        let oid = match name.as_str() {
            "clientAuth" => const_oid::db::rfc5280::ID_KP_CLIENT_AUTH,
            "serverAuth" => const_oid::db::rfc5280::ID_KP_SERVER_AUTH,
            "emailProtection" => const_oid::db::rfc5280::ID_KP_EMAIL_PROTECTION,
            other => ObjectIdentifier::new(other)
                .map_err(|_| AppError::Config(format!("invalid EKU '{other}'")))?,
        };
        oids.push(oid);
    }
    Ok(ExtendedKeyUsage(oids))
}

/// Extract the SubjectAltName requested in a CSR's extensionRequest, if any.
pub fn requested_san(csr: &CertReq) -> AppResult<Option<SubjectAltName>> {
    for attr in csr.info.attributes.iter() {
        if attr.oid != ID_EXTENSION_REQ {
            continue;
        }
        let Some(value) = attr.values.iter().next() else {
            continue;
        };
        let extensions = value
            .decode_as::<Vec<Extension>>()
            .map_err(|e| AppError::bad_request(format!("bad extensionRequest: {e}")))?;
        for ext in extensions {
            if ext.extn_id == ID_CE_SUBJECT_ALT_NAME {
                let san = SubjectAltName::from_der(ext.extn_value.as_bytes())
                    .map_err(|e| AppError::bad_request(format!("bad SAN in CSR: {e}")))?;
                return Ok(Some(san));
            }
        }
    }
    Ok(None)
}

/// Build an Authority Information Access extension pointing at an OCSP responder.
pub fn authority_info_access(ocsp_url: &str) -> AppResult<AuthorityInfoAccessSyntax> {
    let uri = der::asn1::Ia5String::new(ocsp_url)
        .map_err(|e| AppError::Config(format!("invalid OCSP URL: {e}")))?;
    let desc = AccessDescription {
        access_method: ID_AD_OCSP,
        access_location: GeneralName::UniformResourceIdentifier(uri),
    };
    Ok(AuthorityInfoAccessSyntax(vec![desc]))
}

/// Build a CRL Distribution Points extension pointing at a CRL URL.
pub fn crl_distribution_points(crl_url: &str) -> AppResult<CrlDistributionPoints> {
    let uri = der::asn1::Ia5String::new(crl_url)
        .map_err(|e| AppError::Config(format!("invalid CRL URL: {e}")))?;
    let names: GeneralNames = vec![GeneralName::UniformResourceIdentifier(uri)];
    let dp = DistributionPoint {
        distribution_point: Some(DistributionPointName::FullName(names)),
        reasons: None,
        crl_issuer: None,
    };
    Ok(CrlDistributionPoints(vec![dp]))
}
