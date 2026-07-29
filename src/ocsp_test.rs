//! OCSP responder and CRL integration tests.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use axum::body::{to_bytes, Bytes};
use axum::extract::{Path, State};
use der::{Decode, Encode};
use sha1::Sha1;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::name::Name;
use x509_cert::request::attributes::ChallengePassword;
use x509_ocsp::builder::OcspRequestBuilder;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, Request};

use crate::ca::{csr, CertificateAuthority, IssueOptions};
use crate::challenge::NoneValidator;
use crate::db::{self, repo};
use crate::http::crl::crl;
use crate::http::ocsp::ocsp_post;
use crate::http::{AppState, ProfileRuntime, Shared};

async fn state_with_ca(db_name: &str) -> (Shared, Arc<CertificateAuthority>) {
    let ca = Arc::new(
        CertificateAuthority::generate_self_signed("default", "OCSP Test CA", 2048).unwrap(),
    );
    let path = std::env::temp_dir().join(db_name);
    let _ = std::fs::remove_file(&path);
    let pool = db::connect(&format!("sqlite://{}?mode=rwc", path.display()))
        .await
        .unwrap();
    let mut cas = HashMap::new();
    cas.insert("default".to_string(), ca.clone());
    let mut profiles = HashMap::new();
    profiles.insert(
        "test".to_string(),
        ProfileRuntime {
            name: "test".to_string(),
            ca_id: "default".to_string(),
            validator: Arc::new(NoneValidator),
            validity_days: 90,
            key_usage: vec!["digitalSignature".into()],
            extended_key_usage: vec!["clientAuth".into()],
        },
    );
    let state = Arc::new(AppState {
        cas,
        profiles,
        db: pool,
        base_url: "http://localhost".to_string(),
    });
    (state, ca)
}

fn issue_and_store_serial(ca: &CertificateAuthority) -> (x509_cert::Certificate, String) {
    let device = CertificateAuthority::generate_self_signed("dev", "dev", 2048).unwrap();
    let name = Name::from_str("CN=ocsp-target").unwrap();
    let mut builder = RequestBuilder::new(name, &device.signing_key).unwrap();
    builder
        .add_attribute(&ChallengePassword(DirectoryString::Utf8String("x".into())))
        .unwrap();
    let csr_der = builder
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap()
        .to_der()
        .unwrap();
    let parsed = csr::parse(&csr_der).unwrap();
    let opts = IssueOptions {
        validity_days: 90,
        key_usage: vec!["digitalSignature".into()],
        extended_key_usage: vec!["clientAuth".into()],
        ocsp_url: None,
        crl_url: None,
    };
    let cert = ca.issue(&parsed.req, &opts).unwrap();
    let serial = hex::encode(cert.tbs_certificate.serial_number.as_bytes());
    (cert, serial)
}

async fn ocsp_status(
    state: &Shared,
    ca: &CertificateAuthority,
    cert: &x509_cert::Certificate,
) -> CertStatus {
    let req = OcspRequestBuilder::default()
        .with_request(Request::from_cert::<Sha1>(&ca.cert, cert).unwrap())
        .build();
    let req_der = req.to_der().unwrap();
    let resp = ocsp_post(
        State(state.clone()),
        Path("default".to_string()),
        Bytes::from(req_der),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let response = OcspResponse::from_der(&body).unwrap();
    let bytes = response.response_bytes.expect("has response bytes");
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).unwrap();
    basic.tbs_response_data.responses[0].cert_status
}

#[tokio::test]
async fn ocsp_good_then_revoked_and_crl() {
    let (state, ca) = state_with_ca("blapki_ocsp1.db").await;
    let (cert, serial) = issue_and_store_serial(&ca);

    // Record it as issued/valid.
    repo::insert_issued(
        &state.db,
        &repo::IssuedCertificate {
            serial: serial.clone(),
            ca_id: "default".to_string(),
            subject: "CN=ocsp-target".to_string(),
            not_before: "2026-01-01T00:00:00Z".to_string(),
            not_after: "2027-01-01T00:00:00Z".to_string(),
            der_b64: base64_der(&cert),
            thumbprint_sha1: "00".to_string(),
            transaction_id: None,
            profile: Some("test".to_string()),
            status: repo::STATUS_VALID.to_string(),
            created_at: "2026-01-01T00:00:00Z".to_string(),
            revoked_at: None,
            revocation_reason: None,
        },
    )
    .await
    .unwrap();

    // A valid cert is "good".
    assert!(matches!(
        ocsp_status(&state, &ca, &cert).await,
        CertStatus::Good(_)
    ));

    // An unknown serial is "unknown".
    let stranger = CertificateAuthority::generate_self_signed("s", "stranger", 2048).unwrap();
    assert!(matches!(
        ocsp_status(&state, &ca, &stranger.cert).await,
        CertStatus::Unknown(_)
    ));

    // Revoke, then OCSP says "revoked".
    let revoked = repo::revoke(&state.db, "default", &serial, 0, "2026-07-28T00:00:00Z")
        .await
        .unwrap();
    assert!(revoked);
    assert!(matches!(
        ocsp_status(&state, &ca, &cert).await,
        CertStatus::Revoked(_)
    ));

    // The CRL lists the revoked serial.
    let resp = crl(State(state.clone()), Path("default".to_string())).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let list = CertificateList::from_der(&body).unwrap();
    let revoked_serials: Vec<String> = list
        .tbs_cert_list
        .revoked_certificates
        .unwrap_or_default()
        .iter()
        .map(|rc| hex::encode(rc.serial_number.as_bytes()))
        .collect();
    assert!(
        revoked_serials.contains(&serial),
        "CRL must list the revoked serial"
    );
}

fn base64_der(cert: &x509_cert::Certificate) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(cert.to_der().unwrap())
}
