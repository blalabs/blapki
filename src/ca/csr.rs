//! PKCS#10 certificate signing request parsing.

use der::asn1::{Ia5StringRef, PrintableString, Utf8StringRef};
use der::Decode;
use x509_cert::request::CertReq;

use crate::error::{AppError, AppResult};
use crate::scep::attributes::ID_CHALLENGE_PASSWORD;

/// A parsed CSR plus the fields SCEP needs from it.
pub struct ParsedCsr {
    pub req: CertReq,
    /// The original DER (needed for the Intune validation call and audit trail).
    pub der: Vec<u8>,
    /// The PKCS#9 challengePassword, if present.
    pub challenge_password: Option<String>,
}

impl ParsedCsr {
    /// The subject distinguished name as an RFC 4514 string.
    pub fn subject(&self) -> String {
        self.req.info.subject.to_string()
    }
}

/// Parse a DER-encoded PKCS#10 CSR.
pub fn parse(der: &[u8]) -> AppResult<ParsedCsr> {
    let req =
        CertReq::from_der(der).map_err(|e| AppError::bad_request(format!("invalid CSR: {e}")))?;
    let challenge_password = extract_challenge_password(&req);
    Ok(ParsedCsr {
        req,
        der: der.to_vec(),
        challenge_password,
    })
}

fn extract_challenge_password(req: &CertReq) -> Option<String> {
    let attr = req
        .info
        .attributes
        .iter()
        .find(|a| a.oid == ID_CHALLENGE_PASSWORD)?;
    let value = attr.values.iter().next()?;
    if let Ok(ps) = value.decode_as::<PrintableString>() {
        return Some(ps.to_string());
    }
    if let Ok(s) = value.decode_as::<Utf8StringRef<'_>>() {
        return Some(s.as_str().to_owned());
    }
    if let Ok(s) = value.decode_as::<Ia5StringRef<'_>>() {
        return Some(s.as_str().to_owned());
    }
    None
}
