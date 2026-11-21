//! PKCS#10 certificate signing request parsing.

use der::asn1::{Ia5StringRef, PrintableString, Utf8StringRef};
use der::{Decode, Header, Reader, SliceReader};
use rsa::traits::PublicKeyParts;
use x509_cert::request::CertReq;

use crate::crypto::{rsa_public_key_from_spki, HashAlg};
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

/// Smallest RSA modulus accepted in a CSR, in bits.
pub const MIN_RSA_BITS: usize = 2048;

/// Parse a DER-encoded PKCS#10 CSR and check that it is acceptable: an RSA
/// key of at least [`MIN_RSA_BITS`], and a valid self-signature (proof that
/// the requester holds the private key).
pub fn parse(der: &[u8]) -> AppResult<ParsedCsr> {
    let req =
        CertReq::from_der(der).map_err(|e| AppError::bad_request(format!("invalid CSR: {e}")))?;
    verify_proof_of_possession(der, &req)?;
    let challenge_password = extract_challenge_password(&req);
    Ok(ParsedCsr {
        req,
        der: der.to_vec(),
        challenge_password,
    })
}

fn verify_proof_of_possession(der: &[u8], req: &CertReq) -> AppResult<()> {
    let key = rsa_public_key_from_spki(&req.info.public_key)
        .map_err(|e| AppError::bad_request(format!("unsupported CSR key: {e}")))?;
    let bits = key.n().bits();
    if bits < MIN_RSA_BITS {
        return Err(AppError::bad_request(format!(
            "CSR key is {bits} bits; at least {MIN_RSA_BITS} are required"
        )));
    }
    let alg = HashAlg::from_rsa_signature_oid(req.algorithm.oid).ok_or_else(|| {
        AppError::bad_request(format!(
            "unsupported CSR signature algorithm {}",
            req.algorithm.oid
        ))
    })?;
    // Verify over the bytes as received rather than a re-encoding.
    let signed = signed_bytes(der)?;
    if !alg.verify_rsa(&key, signed, req.signature.raw_bytes()) {
        return Err(AppError::bad_request("CSR signature is invalid"));
    }
    Ok(())
}

/// The DER of the `CertificationRequestInfo` (the first element of the outer
/// SEQUENCE), exactly as it appears in `der`.
fn signed_bytes(der: &[u8]) -> AppResult<&[u8]> {
    let bad = |e: der::Error| AppError::bad_request(format!("invalid CSR: {e}"));
    let mut reader = SliceReader::new(der).map_err(bad)?;
    Header::decode(&mut reader).map_err(bad)?;
    reader.tlv_bytes().map_err(bad)
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
    fn tampered_csr_fails_proof_of_possession() {
        let mut der = csr_der("CN=device-03", None);
        // Flip a bit in the subject; the signature no longer covers it.
        let pos = der
            .windows(9)
            .position(|w| w == b"device-03")
            .expect("subject present");
        der[pos] ^= 0x01;
        assert!(parse(&der).is_err());
    }

    #[test]
    fn small_keys_are_rejected() {
        let key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 1024).unwrap();
        let signer = SigningKey::<Sha256>::new(key);
        let der = RequestBuilder::new(Name::from_str("CN=weak").unwrap(), &signer)
            .unwrap()
            .build::<rsa::pkcs1v15::Signature>()
            .unwrap()
            .to_der()
            .unwrap();
        assert!(parse(&der).is_err());
    }

    #[test]
    fn invalid_der_is_rejected() {
        assert!(parse(&[0x00, 0x01, 0x02, 0x03]).is_err());
    }
}
