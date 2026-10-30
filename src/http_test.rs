//! End-to-end enrolment test through the HTTP handler: builds a real PKCSReq,
//! drives `scep_post`, and checks the CertRep, DB persistence, and the
//! static-challenge failure path. Uses a temp-file SQLite database.

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;

use axum::body::{to_bytes, Bytes};
use axum::extract::{Path, Query, State};
use cms::content_info::ContentInfo;
use cms::enveloped_data::{EnvelopedData, KeyTransRecipientInfo, RecipientInfo, RecipientInfos};
use cms::signed_data::SignedData;
use der::asn1::{Any, OctetString, SetOfVec};
use der::{Decode, Encode};
use rsa::Pkcs1v15Encrypt;
use sqlx::Row;
use x509_cert::builder::{Builder, RequestBuilder};
use x509_cert::ext::pkix::name::DirectoryString;
use x509_cert::name::Name;
use x509_cert::request::attributes::ChallengePassword;

use crate::ca::CertificateAuthority;
use crate::challenge::StaticSecretValidator;
use crate::crypto::{envelope, oids, rsa_public_key, sign, verify};
use crate::db;
use crate::http::scep::{scep_get, scep_post};
use crate::http::{AppState, ProfileRuntime, Shared};
use crate::scep::attributes::{self as attr, FailInfo, MessageType};
use crate::scep::nonce;

const SECRET: &str = "secret123";

fn build_csr(device: &CertificateAuthority, subject: &str, challenge: &str) -> Vec<u8> {
    let name = Name::from_str(subject).unwrap();
    let mut builder = RequestBuilder::new(name, &device.signing_key).unwrap();
    builder
        .add_attribute(&ChallengePassword(DirectoryString::Utf8String(
            challenge.to_string(),
        )))
        .unwrap();
    builder
        .build::<rsa::pkcs1v15::Signature>()
        .unwrap()
        .to_der()
        .unwrap()
}

fn build_pkcsreq(
    device: &CertificateAuthority,
    ca: &CertificateAuthority,
    csr_der: &[u8],
    txn: &str,
) -> Vec<u8> {
    let env_der = envelope::build(csr_der, &ca.cert).unwrap();
    let attrs = vec![
        attr::printable_attribute(attr::ID_MESSAGE_TYPE, MessageType::PkcsReq.as_value()).unwrap(),
        attr::printable_attribute(attr::ID_TRANSACTION_ID, txn).unwrap(),
        attr::octet_attribute(attr::ID_SENDER_NONCE, &nonce::generate()).unwrap(),
    ];
    sign::build_cert_rep(&device.signing_key, &device.cert, Some(&env_der), attrs).unwrap()
}

async fn test_state(db_name: &str) -> (Shared, Arc<CertificateAuthority>) {
    let ca = Arc::new(
        CertificateAuthority::generate_self_signed("default", "HTTP Test CA", 2048).unwrap(),
    );
    let path = std::env::temp_dir().join(db_name);
    let _ = std::fs::remove_file(&path);
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let pool = db::connect(&url).await.unwrap();

    let mut cas = HashMap::new();
    cas.insert("default".to_string(), ca.clone());
    let mut profiles = HashMap::new();
    profiles.insert(
        "test".to_string(),
        ProfileRuntime {
            name: "test".to_string(),
            ca_id: "default".to_string(),
            validator: Arc::new(StaticSecretValidator::new(SECRET.to_string())),
            validity_days: 90,
            key_usage: vec!["digitalSignature".into(), "keyEncipherment".into()],
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

async fn post(state: &Shared, body: Vec<u8>) -> (u16, Vec<u8>) {
    let resp = scep_post(
        State(state.clone()),
        Path("test".to_string()),
        Query(HashMap::new()),
        Bytes::from(body),
    )
    .await
    .expect("handler returned Err");
    let status = resp.status().as_u16();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

#[tokio::test]
async fn http_enrollment_success_and_persists() {
    let (state, ca) = test_state("blapki_http_ok.db").await;
    let device = CertificateAuthority::generate_self_signed("dev", "dev", 2048).unwrap();
    let csr = build_csr(&device, "CN=device-http-01", SECRET);
    let request = build_pkcsreq(&device, &ca, &csr, "txn-ok-1");

    let (status, body) = post(&state, request).await;
    assert_eq!(status, 200);

    let reply = verify::parse_and_verify(&body).unwrap();
    assert_eq!(reply.message_type, MessageType::CertRep);
    let env = reply
        .enveloped
        .as_ref()
        .expect("success reply is enveloped");
    let certs_only = envelope::open(env, &device.cert, &device.private_key).unwrap();
    assert!(!certs_only.is_empty());

    // The issued certificate was recorded.
    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM issued_certificate")
        .fetch_one(&state.db)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn http_enrollment_wrong_challenge_fails_in_band() {
    let (state, ca) = test_state("blapki_http_bad.db").await;
    let device = CertificateAuthority::generate_self_signed("dev", "dev", 2048).unwrap();
    let csr = build_csr(&device, "CN=device-http-02", "wrong-secret");
    let request = build_pkcsreq(&device, &ca, &csr, "txn-bad-1");

    let (status, body) = post(&state, request).await;
    // SCEP failures are returned in-band with HTTP 200.
    assert_eq!(status, 200);

    let reply = verify::parse_and_verify(&body).unwrap();
    assert_eq!(reply.message_type, MessageType::CertRep);
    // A FAILURE CertRep carries no enveloped certificate.
    assert!(reply.enveloped.is_none(), "failure reply must have no cert");

    let count: i64 = sqlx::query("SELECT COUNT(*) AS n FROM issued_certificate")
        .fetch_one(&state.db)
        .await
        .unwrap()
        .try_get("n")
        .unwrap();
    assert_eq!(count, 0, "no certificate should be issued on failure");
}

fn query(operation: &str) -> Query<HashMap<String, String>> {
    Query(HashMap::from([(
        "operation".to_string(),
        operation.to_string(),
    )]))
}

#[tokio::test]
async fn get_ca_caps_and_ca_cert() {
    let (state, _ca) = test_state("blapki_http_get.db").await;

    let resp = scep_get(
        State(state.clone()),
        Path("test".to_string()),
        query("GetCACaps"),
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let caps = String::from_utf8(body.to_vec()).unwrap();
    assert!(caps.contains("POSTPKIOperation"));
    assert!(caps.contains("SHA-256"));

    let resp = scep_get(
        State(state.clone()),
        Path("test".to_string()),
        query("GetCACert"),
    )
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 200);
    let body = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    assert!(!body.is_empty());
}

#[tokio::test]
async fn get_with_unknown_operation_errors() {
    let (state, _ca) = test_state("blapki_http_badop.db").await;
    let result = scep_get(State(state), Path("test".to_string()), query("Nope")).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn get_ca_cert_for_unknown_profile_errors() {
    let (state, _ca) = test_state("blapki_http_noprofile.db").await;
    let result = scep_get(State(state), Path("ghost".to_string()), query("GetCACert")).await;
    assert!(result.is_err());
}

// --- Padding-oracle regression tests ---------------------------------------
//
// An attacker only needs the CA certificate to send RSA ciphertexts of their
// choosing. Whatever the PKCS#1 v1.5 unwrap does with them, the reply must look
// the same: an in-band FAILURE with failInfo badMessageCheck.

/// Decode an envelope and return it with its single key-transport recipient.
fn split_envelope(env_der: &[u8]) -> (EnvelopedData, KeyTransRecipientInfo) {
    let ed = envelope::parse(env_der).unwrap();
    let ktri = match ed.recip_infos.0.iter().next().unwrap() {
        RecipientInfo::Ktri(ktri) => ktri.clone(),
        _ => panic!("expected a key-transport recipient"),
    };
    (ed, ktri)
}

/// Re-encode an envelope with the given recipients, as a `ContentInfo`.
fn rebuild_envelope(mut ed: EnvelopedData, ktris: Vec<KeyTransRecipientInfo>) -> Vec<u8> {
    let infos: Vec<RecipientInfo> = ktris.into_iter().map(RecipientInfo::Ktri).collect();
    ed.recip_infos = RecipientInfos(SetOfVec::try_from(infos).unwrap());
    ContentInfo {
        content_type: oids::ID_ENVELOPED_DATA,
        content: Any::encode_from(&ed).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn with_enc_key(ktri: &KeyTransRecipientInfo, enc_key: Vec<u8>) -> KeyTransRecipientInfo {
    let mut ktri = ktri.clone();
    ktri.enc_key = OctetString::new(enc_key).unwrap();
    ktri
}

fn sign_pkcsreq(device: &CertificateAuthority, env_der: &[u8], txn: &str) -> Vec<u8> {
    let attrs = vec![
        attr::printable_attribute(attr::ID_MESSAGE_TYPE, MessageType::PkcsReq.as_value()).unwrap(),
        attr::printable_attribute(attr::ID_TRANSACTION_ID, txn).unwrap(),
        attr::octet_attribute(attr::ID_SENDER_NONCE, &nonce::generate()).unwrap(),
    ];
    sign::build_cert_rep(&device.signing_key, &device.cert, Some(env_der), attrs).unwrap()
}

/// The failInfo of a CertRep, or `None` when it carries none.
fn fail_info(reply_der: &[u8]) -> Option<String> {
    let ci = ContentInfo::from_der(reply_der).unwrap();
    let sd: SignedData = ci.content.decode_as().unwrap();
    let signer = sd.signer_infos.0.iter().next().unwrap();
    attr::read_string(signer.signed_attrs.as_ref().unwrap(), attr::ID_FAIL_INFO).ok()
}

async fn issued_count(state: &Shared) -> i64 {
    sqlx::query("SELECT COUNT(*) AS n FROM issued_certificate")
        .fetch_one(&state.db)
        .await
        .unwrap()
        .try_get("n")
        .unwrap()
}

#[tokio::test]
async fn rsa_unwrap_failures_are_indistinguishable() {
    let (state, ca) = test_state("blapki_http_oracle.db").await;
    let device = CertificateAuthority::generate_self_signed("dev", "dev", 2048).unwrap();
    let ca_key = rsa_public_key(&ca.cert).unwrap();
    // An AES-256 envelope addressed to the CA; only the wrapped CEK is varied.
    let env = envelope::build(b"not a csr", &ca.cert).unwrap();
    let (ed, ktri) = split_envelope(&env);

    let mut bad_padding = vec![0x42u8; 256];
    bad_padding[0] = 0x00;
    let probes = [
        ("bad padding", bad_padding),
        (
            "good padding, wrong key length",
            ca_key
                .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &[7u8; 16])
                .unwrap(),
        ),
        (
            "good padding, right key length",
            ca_key
                .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, &[7u8; 32])
                .unwrap(),
        ),
    ];

    for (case, enc_key) in probes {
        let env_der = rebuild_envelope(ed.clone(), vec![with_enc_key(&ktri, enc_key)]);
        let (status, body) = post(&state, sign_pkcsreq(&device, &env_der, "txn-oracle")).await;
        assert_eq!(status, 200, "{case}: must fail in band");
        let reply = verify::parse_and_verify(&body).unwrap();
        assert_eq!(reply.message_type, MessageType::CertRep, "{case}");
        assert!(reply.enveloped.is_none(), "{case}: no cert in a failure");
        assert_eq!(
            fail_info(&body).as_deref(),
            Some(FailInfo::BadMessageCheck.as_value()),
            "{case}: failInfo must be badMessageCheck"
        );
    }
    assert_eq!(issued_count(&state).await, 0);
}

#[tokio::test]
async fn unwrap_result_cannot_steer_recipient_choice() {
    let (state, ca) = test_state("blapki_http_two_recips.db").await;
    let device = CertificateAuthority::generate_self_signed("dev", "dev", 2048).unwrap();
    let csr = build_csr(&device, "CN=device-two-recips", SECRET);

    // Two recipients that both use the CA key but do not name the CA cert: a
    // probe with bad padding, then a correctly wrapped CEK. Falling through
    // to the second recipient on a padding failure would issue a cert and so
    // reveal the probe's padding result.
    let ca_key = rsa_public_key(&ca.cert).unwrap();
    let other_issuer = Name::from_str("CN=someone else").unwrap();
    let other_serial = envelope::RawSerial::new(&[0x01, 0x02]).unwrap();
    let env = envelope::build_for(
        &csr,
        &envelope::Recipient {
            public_key: &ca_key,
            issuer: &other_issuer,
            serial: &other_serial,
        },
    )
    .unwrap();
    let (ed, good) = split_envelope(&env);
    let mut probe_key = vec![0x42u8; 256];
    probe_key[0] = 0x00;
    let probe = with_enc_key(&good, probe_key);
    let env_der = rebuild_envelope(ed, vec![probe, good]);

    let (status, body) = post(&state, sign_pkcsreq(&device, &env_der, "txn-two")).await;
    assert_eq!(status, 200);
    assert_eq!(
        fail_info(&body).as_deref(),
        Some(FailInfo::BadMessageCheck.as_value())
    );
    assert_eq!(issued_count(&state).await, 0);
}

#[tokio::test]
async fn lone_unrecognised_recipient_still_enrols() {
    let (state, ca) = test_state("blapki_http_lone_recip.db").await;
    let device = CertificateAuthority::generate_self_signed("dev", "dev", 2048).unwrap();
    let csr = build_csr(&device, "CN=device-lone-recip", SECRET);

    let ca_key = rsa_public_key(&ca.cert).unwrap();
    let other_issuer = Name::from_str("CN=someone else").unwrap();
    let other_serial = envelope::RawSerial::new(&[0x01, 0x02]).unwrap();
    let env_der = envelope::build_for(
        &csr,
        &envelope::Recipient {
            public_key: &ca_key,
            issuer: &other_issuer,
            serial: &other_serial,
        },
    )
    .unwrap();

    let (status, body) = post(&state, sign_pkcsreq(&device, &env_der, "txn-lone")).await;
    assert_eq!(status, 200);
    assert!(fail_info(&body).is_none(), "expected a SUCCESS CertRep");
    assert_eq!(issued_count(&state).await, 1);
}
