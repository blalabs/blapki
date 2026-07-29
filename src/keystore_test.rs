//! Tests for loading CA material from inline base64 (PEM and DER).

use base64::Engine;
use der::pem::LineEnding;
use der::{Encode, EncodePem};
use rsa::pkcs8::EncodePrivateKey;

use crate::ca::keystore::{InlineKeyStore, KeyStore};
use crate::ca::{CertificateAuthority, IssueOptions};

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The loaded CA must be usable: issue a cert and confirm the issuer matches.
fn assert_usable(cert: x509_cert::Certificate, key: rsa::RsaPrivateKey, expected_subject: &str) {
    let ca = CertificateAuthority::new("default", cert, key);
    assert_eq!(ca.subject().to_string(), expected_subject);

    // Build a throwaway CSR and issue from it.
    use std::str::FromStr;
    use x509_cert::builder::{Builder, RequestBuilder};
    use x509_cert::name::Name;
    let device = CertificateAuthority::generate_self_signed("d", "d", 2048).unwrap();
    let csr = RequestBuilder::new(Name::from_str("CN=leaf").unwrap(), &device.signing_key)
        .unwrap()
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap();
    let opts = IssueOptions {
        validity_days: 30,
        key_usage: vec!["digitalSignature".into()],
        extended_key_usage: vec!["clientAuth".into()],
        ocsp_url: None,
        crl_url: None,
    };
    let leaf = ca.issue(&csr, &opts).unwrap();
    assert_eq!(leaf.tbs_certificate.issuer.to_string(), expected_subject);
}

#[test]
fn inline_plain_pem_roundtrip() {
    // The common case: paste the plain PEM (-----BEGIN CERTIFICATE----- and
    // -----BEGIN PRIVATE KEY-----) straight into config.
    let ca = CertificateAuthority::generate_self_signed("default", "Inline PEM CA", 2048).unwrap();
    let cert_pem = ca.cert.to_pem(LineEnding::LF).unwrap();
    let key_pem = ca.private_key.to_pkcs8_pem(LineEnding::LF).unwrap();

    let store = InlineKeyStore::from_material(&cert_pem, key_pem.as_str(), None).unwrap();
    let (cert, key) = store.load().unwrap();
    assert_eq!(cert.to_der().unwrap(), ca.cert.to_der().unwrap());
    assert_usable(cert, key, "CN=Inline PEM CA");
}

#[test]
fn inline_base64_pem_roundtrip() {
    // A base64 blob of PEM is auto-detected and decoded.
    let ca = CertificateAuthority::generate_self_signed("default", "Inline B64 CA", 2048).unwrap();
    let cert_pem = ca.cert.to_pem(LineEnding::LF).unwrap();
    let key_pem = ca.private_key.to_pkcs8_pem(LineEnding::LF).unwrap();

    let store =
        InlineKeyStore::from_material(&b64(cert_pem.as_bytes()), &b64(key_pem.as_bytes()), None)
            .unwrap();
    let (cert, key) = store.load().unwrap();
    assert_eq!(cert.to_der().unwrap(), ca.cert.to_der().unwrap());
    assert_usable(cert, key, "CN=Inline B64 CA");
}

#[test]
fn inline_base64_der_roundtrip() {
    let ca = CertificateAuthority::generate_self_signed("default", "Inline DER CA", 2048).unwrap();
    let cert_der = ca.cert.to_der().unwrap();
    let key_der = ca.private_key.to_pkcs8_der().unwrap();

    let store =
        InlineKeyStore::from_material(&b64(&cert_der), &b64(key_der.as_bytes()), None).unwrap();
    let (cert, key) = store.load().unwrap();
    assert_eq!(cert.to_der().unwrap(), cert_der);
    assert_usable(cert, key, "CN=Inline DER CA");
}
