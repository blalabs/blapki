//! Interop regression test against a real sscep-generated `PKCSReq`.
//!
//! sscep (built on OpenSSL) puts a 32-octet serial (its hex transaction id) in
//! the self-signed signer certificate it embeds. The strict `cms`/`x509-cert`
//! decoders reject serials over 20 octets, which broke enrolment until the
//! relaxed parser landed. The fixture is a request captured from
//! `sscep enroll` (RSA-2048, AES-256, SHA-256); it contains no private keys.

use crate::crypto::verify;
use crate::scep::attributes::MessageType;

const SSCEP_PKCSREQ: &[u8] = include_bytes!("testdata/sscep_pkcsreq.der");

#[test]
fn parses_sscep_request_with_oversized_serial() {
    let parsed =
        verify::parse_and_verify(SSCEP_PKCSREQ).expect("real sscep PKCSReq must parse and verify");

    assert_eq!(parsed.message_type, MessageType::PkcsReq);
    assert!(!parsed.transaction_id.is_empty());
    assert!(
        parsed.enveloped.is_some(),
        "PKCSReq carries an enveloped CSR"
    );

    // The whole point of the fix: the >20-octet serial is preserved verbatim so
    // the reply's recipient will match at the client.
    let serial_len = parsed.recipient.serial.as_bytes().len();
    assert!(
        serial_len > 20,
        "expected the oversized sscep serial to be preserved, got {serial_len} bytes"
    );
}
