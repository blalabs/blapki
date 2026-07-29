//! Degenerate "certificates-only" `SignedData` (RFC 5652 §5.2, RFC 8894 §3.4).
//!
//! Used by the SCEP `GetCACert` operation and as the payload that gets wrapped
//! in `EnvelopedData` inside a `CertRep`. It is a `SignedData` with no signers
//! and no content, just the certificates.

use cms::content_info::ContentInfo;
use der::Encode;
use x509_cert::{Certificate, PkiPath};

use crate::crypto::der_err;
use crate::error::AppResult;

/// DER-encode a single certificate as a certs-only PKCS#7 message.
pub fn certs_only(cert: &Certificate) -> AppResult<Vec<u8>> {
    let ci = ContentInfo::try_from(cert.clone()).map_err(der_err)?;
    ci.to_der().map_err(der_err)
}

/// DER-encode a certificate chain as a certs-only PKCS#7 message.
pub fn chain_only(chain: &[Certificate]) -> AppResult<Vec<u8>> {
    let path: PkiPath = chain.to_vec();
    let ci = ContentInfo::try_from(path).map_err(der_err)?;
    ci.to_der().map_err(der_err)
}
