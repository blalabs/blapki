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

#[cfg(test)]
mod tests {
    use super::*;
    use der::Encode;
    use rsa::pkcs1v15::SigningKey;
    use sha2::Sha256;
    use std::str::FromStr;
    use x509_cert::builder::{Builder, RequestBuilder};
    use x509_cert::ext::pkix::name::DirectoryString;
    use x509_cert::name::Name;
    use x509_cert::request::attributes::ChallengePassword;

    fn csr_der(subject: &str, challenge: Option<&str>) -> Vec<u8> {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
        let signer = SigningKey::<Sha256>::new(key);
        let mut builder = RequestBuilder::new(Name::from_str(subject).unwrap(), &signer).unwrap();
        if let Some(c) = challenge {
            builder
                .add_attribute(&ChallengePassword(DirectoryString::Utf8String(
                    c.to_string(),
                )))
                .unwrap();
        }
        builder
            .build::<rsa::pkcs1v15::Signature>()
            .unwrap()
            .to_der()
            .unwrap()
    }

    #[test]
    fn parses_subject_and_challenge_password() {
        let parsed = parse(&csr_der("CN=device-01", Some("s3cr3t"))).unwrap();
        assert_eq!(parsed.subject(), "CN=device-01");
        assert_eq!(parsed.challenge_password.as_deref(), Some("s3cr3t"));
    }

    #[test]
    fn csr_without_challenge_password() {
        let parsed = parse(&csr_der("CN=device-02", None)).unwrap();
        assert!(parsed.challenge_password.is_none());
    }

    #[test]
    fn invalid_der_is_rejected() {
        assert!(parse(&[0x00, 0x01, 0x02, 0x03]).is_err());
    }
}
