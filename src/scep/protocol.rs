//! SCEP protocol helpers: capability advertisement and response attributes.

use x509_cert::attr::Attribute;

use crate::error::AppResult;
use crate::scep::attributes::{self as attr, FailInfo, MessageType, PkiStatus};
use crate::scep::nonce;

/// Capabilities advertised by `GetCACaps`, newline-separated.
///
/// We advertise SHA-256 and AES (modern SCEP), keep SHA-1/DES3 for older
/// clients, and support POST and renewal.
pub const CA_CAPS: &str =
    "Renewal\nSHA-512\nSHA-256\nSHA-1\nDES3\nAES\nPOSTPKIOperation\nSCEPStandard";

/// Signed attributes for a successful `CertRep`.
pub fn success_attrs(transaction_id: &str, recipient_nonce: &[u8]) -> AppResult<Vec<Attribute>> {
    Ok(vec![
        attr::printable_attribute(attr::ID_MESSAGE_TYPE, MessageType::CertRep.as_value())?,
        attr::printable_attribute(attr::ID_PKI_STATUS, PkiStatus::Success.as_value())?,
        attr::printable_attribute(attr::ID_TRANSACTION_ID, transaction_id)?,
        attr::octet_attribute(attr::ID_SENDER_NONCE, &nonce::generate())?,
        attr::octet_attribute(attr::ID_RECIPIENT_NONCE, recipient_nonce)?,
    ])
}

/// Signed attributes for a failed `CertRep`.
pub fn failure_attrs(
    transaction_id: &str,
    recipient_nonce: &[u8],
    fail_info: FailInfo,
) -> AppResult<Vec<Attribute>> {
    Ok(vec![
        attr::printable_attribute(attr::ID_MESSAGE_TYPE, MessageType::CertRep.as_value())?,
        attr::printable_attribute(attr::ID_PKI_STATUS, PkiStatus::Failure.as_value())?,
        attr::printable_attribute(attr::ID_FAIL_INFO, fail_info.as_value())?,
        attr::printable_attribute(attr::ID_TRANSACTION_ID, transaction_id)?,
        attr::octet_attribute(attr::ID_SENDER_NONCE, &nonce::generate())?,
        attr::octet_attribute(attr::ID_RECIPIENT_NONCE, recipient_nonce)?,
    ])
}
