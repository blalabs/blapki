//! End-to-end crypto round-trip test.
//!
//! Exercises the whole SCEP crypto pipeline without any HTTP or database:
//! a device builds a signed+enveloped `PKCSReq`, the server verifies the
//! signature, decrypts the CSR, issues a certificate, and returns a
//! signed+enveloped `CertRep`, which the device then decrypts. If this passes,
//! the risky hand-written CMS code (sign/verify + envelope open/build) is
//! sound.

use std::str::FromStr;

use der::Encode;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::name::Name;
use x509_cert::request::attributes::ChallengePassword;

use crate::ca::{csr, CertificateAuthority, IssueOptions};
use crate::crypto::{degenerate, envelope, sign, verify};
use crate::scep::attributes::{self as attr, FailInfo, MessageType, PkiStatus};
use crate::scep::nonce;

const CHALLENGE: &str = "s3cr3t-challenge";
const DEVICE_SUBJECT: &str = "CN=intune-device-01";
const TRANSACTION_ID: &str = "transaction-abc-123";

/// Build a DER PKCS#10 CSR for the device, with a challengePassword.
fn build_csr(device: &CertificateAuthority) -> Vec<u8> {
    let subject = Name::from_str(DEVICE_SUBJECT).unwrap();
    let mut builder = RequestBuilder::new(subject, &device.signing_key).unwrap();
    builder
        .add_attribute(&ChallengePassword(DirectoryString::Utf8String(
            CHALLENGE.to_string(),
        )))
        .unwrap();
    let req = builder.build::<rsa::pkcs1v15::Signature>().unwrap();
    req.to_der().unwrap()
}

#[test]
fn scep_enrolment_roundtrip() {
    // --- Setup: a CA, and a device with its own key + self-signed cert. ---
    let ca = CertificateAuthority::generate_self_signed("test-ca", "blapki Test CA", 2048).unwrap();
    let device = CertificateAuthority::generate_self_signed("device", "device-tmp", 2048).unwrap();

    let csr_der = build_csr(&device);

    // --- Device: build a signed + enveloped PKCSReq. ---
    let sender_nonce = nonce::generate();
    let enveloped_csr = envelope::build(&csr_der, &ca.cert).unwrap();
    let enveloped_csr_der = envelope::to_content_info_der(&enveloped_csr).unwrap();

    let request_attrs = vec![
        attr::printable_attribute(attr::ID_MESSAGE_TYPE, MessageType::PkcsReq.as_value()).unwrap(),
        attr::printable_attribute(attr::ID_TRANSACTION_ID, TRANSACTION_ID).unwrap(),
        attr::octet_attribute(attr::ID_SENDER_NONCE, &sender_nonce).unwrap(),
    ];
    // Reuse the signed-message builder to construct the request (signed by the
    // device key rather than the CA).
    let request_der = sign::build_cert_rep(
        &device.signing_key,
        &device.cert,
        Some(&enveloped_csr_der),
        request_attrs,
    )
    .unwrap();

    // --- Server: verify signature, extract SCEP metadata. ---
    let parsed = verify::parse_and_verify(&request_der).unwrap();
    assert_eq!(parsed.message_type, MessageType::PkcsReq);
    assert_eq!(parsed.transaction_id, TRANSACTION_ID);
    assert_eq!(parsed.sender_nonce, sender_nonce);

    // --- Server: decrypt the CSR and check it survived the envelope intact. ---
    let enveloped_in = parsed
        .enveloped
        .as_ref()
        .expect("PKCSReq carries an envelope");
    let recovered_csr = envelope::open(enveloped_in, &ca.cert, &ca.private_key).unwrap();
    assert_eq!(
        recovered_csr, csr_der,
        "decrypted CSR must match the original"
    );

    let parsed_csr = csr::parse(&recovered_csr).unwrap();
    assert_eq!(parsed_csr.challenge_password.as_deref(), Some(CHALLENGE));
    assert_eq!(parsed_csr.subject(), DEVICE_SUBJECT);

    // --- Server: issue the certificate. ---
    let opts = IssueOptions {
        validity_days: 365,
        key_usage: vec!["digitalSignature".into(), "keyEncipherment".into()],
        extended_key_usage: vec!["clientAuth".into()],
        ocsp_url: Some("http://pki.example.com/ocsp".into()),
        crl_url: Some("http://pki.example.com/crl".into()),
    };
    let issued = ca.issue(&parsed_csr.req, &opts).unwrap();
    assert_eq!(issued.tbs_certificate.subject.to_string(), DEVICE_SUBJECT);
    assert_eq!(
        issued.tbs_certificate.issuer.to_string(),
        ca.subject().to_string(),
        "issued cert must be issued by the CA"
    );

    // --- Server: build a signed + enveloped CertRep for the device. ---
    let certs_only = degenerate::certs_only(&issued).unwrap();
    let reply_env = envelope::build(&certs_only, &device.cert).unwrap();
    let reply_env_der = envelope::to_content_info_der(&reply_env).unwrap();

    let reply_attrs = vec![
        attr::printable_attribute(attr::ID_MESSAGE_TYPE, MessageType::CertRep.as_value()).unwrap(),
        attr::printable_attribute(attr::ID_PKI_STATUS, PkiStatus::Success.as_value()).unwrap(),
        attr::printable_attribute(attr::ID_TRANSACTION_ID, &parsed.transaction_id).unwrap(),
        attr::octet_attribute(attr::ID_SENDER_NONCE, &nonce::generate()).unwrap(),
        attr::octet_attribute(attr::ID_RECIPIENT_NONCE, &parsed.sender_nonce).unwrap(),
    ];
    let response_der =
        sign::build_cert_rep(&ca.signing_key, &ca.cert, Some(&reply_env_der), reply_attrs).unwrap();

    // --- Device: verify the CA's signature and decrypt the reply. ---
    let reply = verify::parse_and_verify(&response_der).unwrap();
    assert_eq!(reply.message_type, MessageType::CertRep);
    assert_eq!(reply.transaction_id, TRANSACTION_ID);
    assert_eq!(reply.sender_nonce.len(), nonce::NONCE_LEN);

    let reply_env_in = reply
        .enveloped
        .as_ref()
        .expect("CertRep carries an envelope");
    let recovered_certs = envelope::open(reply_env_in, &device.cert, &device.private_key).unwrap();
    assert_eq!(
        recovered_certs, certs_only,
        "device must recover exactly the certs-only reply"
    );
}

#[test]
fn tampered_signature_is_rejected() {
    let ca = CertificateAuthority::generate_self_signed("ca", "tamper CA", 2048).unwrap();
    let attrs = vec![
        attr::printable_attribute(attr::ID_MESSAGE_TYPE, MessageType::CertRep.as_value()).unwrap(),
        attr::printable_attribute(attr::ID_PKI_STATUS, PkiStatus::Failure.as_value()).unwrap(),
        attr::printable_attribute(attr::ID_FAIL_INFO, FailInfo::BadRequest.as_value()).unwrap(),
        attr::printable_attribute(attr::ID_TRANSACTION_ID, TRANSACTION_ID).unwrap(),
        attr::octet_attribute(attr::ID_SENDER_NONCE, &nonce::generate()).unwrap(),
    ];
    let mut der = sign::build_cert_rep(&ca.signing_key, &ca.cert, None, attrs).unwrap();

    // A valid failure CertRep parses fine.
    assert!(verify::parse_and_verify(&der).is_ok());

    // Flip a byte near the end (inside the signature) and expect rejection.
    let last = der.len() - 5;
    der[last] ^= 0xff;
    assert!(verify::parse_and_verify(&der).is_err());
}
