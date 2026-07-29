//! SCEP message attributes: OIDs, message types, and the signed-attribute
//! encoding/decoding defined by RFC 8894 (and the older draft-nourse-scep).
//!
//! SCEP carries its protocol metadata as CMS *signed attributes* on the outer
//! `SignedData`. The attribute values use the Verisign OID arc
//! `2.16.840.1.113733.1.9.*`. `messageType`, `pkiStatus` and `failInfo` are
//! `PrintableString`s holding a decimal number; `transactionID` is a
//! `PrintableString`; `senderNonce`/`recipientNonce` are 16-byte `OCTET STRING`s.

use const_oid::ObjectIdentifier;
use der::asn1::{Any, OctetString, PrintableString, SetOfVec};
use x509_cert::attr::{Attribute, AttributeValue};

use crate::error::{AppError, AppResult};

/// `messageType`: the SCEP message type (PrintableString decimal).
pub const ID_MESSAGE_TYPE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.2");
/// `pkiStatus`: success/failure/pending of a `CertRep` (PrintableString decimal).
pub const ID_PKI_STATUS: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.3");
/// `failInfo`: failure reason when `pkiStatus = FAILURE` (PrintableString decimal).
pub const ID_FAIL_INFO: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.4");
/// `senderNonce`: 16-byte OCTET STRING chosen by the sender.
pub const ID_SENDER_NONCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.5");
/// `recipientNonce`: echoes the peer's `senderNonce`.
pub const ID_RECIPIENT_NONCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.6");
/// `transactionID`: PrintableString correlating request and response.
pub const ID_TRANSACTION_ID: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.7");
/// `failInfoText`: optional human-readable failure text (RFC 8894).
pub const ID_FAIL_INFO_TEXT: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.16.840.1.113733.1.9.8");

/// PKCS#9 `challengePassword` attribute carried inside the CSR.
pub const ID_CHALLENGE_PASSWORD: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.7");

/// SCEP message type (RFC 8894 §3.2.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// Response to any of the request messages (value 3).
    CertRep,
    /// Certificate enrolment request (value 19).
    PkcsReq,
    /// Certificate renewal request (value 17).
    RenewalReq,
    /// Poll for a pending request (value 20).
    GetCertInitial,
    /// Retrieve an issued certificate by issuer + serial (value 21).
    GetCert,
    /// Retrieve a CRL (value 22).
    GetCrl,
}

impl MessageType {
    pub fn as_value(self) -> &'static str {
        match self {
            MessageType::CertRep => "3",
            MessageType::RenewalReq => "17",
            MessageType::PkcsReq => "19",
            MessageType::GetCertInitial => "20",
            MessageType::GetCert => "21",
            MessageType::GetCrl => "22",
        }
    }

    pub fn from_value(s: &str) -> AppResult<Self> {
        Ok(match s.trim() {
            "3" => MessageType::CertRep,
            "17" => MessageType::RenewalReq,
            "19" => MessageType::PkcsReq,
            "20" => MessageType::GetCertInitial,
            "21" => MessageType::GetCert,
            "22" => MessageType::GetCrl,
            other => {
                return Err(AppError::bad_request(format!(
                    "unknown SCEP messageType '{other}'"
                )))
            }
        })
    }
}

/// SCEP `pkiStatus` values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkiStatus {
    Success,
    Failure,
    Pending,
}

impl PkiStatus {
    pub fn as_value(self) -> &'static str {
        match self {
            PkiStatus::Success => "0",
            PkiStatus::Failure => "2",
            PkiStatus::Pending => "3",
        }
    }
}

/// SCEP `failInfo` values (reason for a FAILURE response).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailInfo {
    BadAlg,
    BadMessageCheck,
    BadRequest,
    BadTime,
    BadCertId,
}

impl FailInfo {
    pub fn as_value(self) -> &'static str {
        match self {
            FailInfo::BadAlg => "0",
            FailInfo::BadMessageCheck => "1",
            FailInfo::BadRequest => "2",
            FailInfo::BadTime => "3",
            FailInfo::BadCertId => "4",
        }
    }
}

/// Build a signed attribute whose single value is a `PrintableString`.
pub fn printable_attribute(oid: ObjectIdentifier, value: &str) -> AppResult<Attribute> {
    let ps = PrintableString::new(value)
        .map_err(|e| AppError::crypto(format!("invalid PrintableString: {e}")))?;
    let any = Any::encode_from(&ps).map_err(der_err)?;
    single_value_attribute(oid, any)
}

/// Build a signed attribute whose single value is an `OCTET STRING`.
pub fn octet_attribute(oid: ObjectIdentifier, value: &[u8]) -> AppResult<Attribute> {
    let os = OctetString::new(value).map_err(der_err)?;
    let any = Any::encode_from(&os).map_err(der_err)?;
    single_value_attribute(oid, any)
}

fn single_value_attribute(oid: ObjectIdentifier, value: AttributeValue) -> AppResult<Attribute> {
    let mut values = SetOfVec::<AttributeValue>::new();
    values.insert(value).map_err(der_err)?;
    Ok(Attribute { oid, values })
}

/// Find an attribute by OID within a set of signed attributes.
pub fn find(attrs: &SetOfVec<Attribute>, oid: ObjectIdentifier) -> Option<&Attribute> {
    attrs.iter().find(|a| a.oid == oid)
}

/// Read a `PrintableString`/`UTF8String`/`IA5String` attribute value as a `String`.
pub fn read_string(attrs: &SetOfVec<Attribute>, oid: ObjectIdentifier) -> AppResult<String> {
    let attr = find(attrs, oid)
        .ok_or_else(|| AppError::bad_request(format!("missing SCEP attribute {oid}")))?;
    let value = attr
        .values
        .iter()
        .next()
        .ok_or_else(|| AppError::bad_request(format!("empty SCEP attribute {oid}")))?;
    // SCEP mandates PrintableString, but tolerate the common string tags.
    if let Ok(ps) = value.decode_as::<PrintableString>() {
        return Ok(ps.to_string());
    }
    if let Ok(s) = value.decode_as::<der::asn1::Utf8StringRef<'_>>() {
        return Ok(s.as_str().to_owned());
    }
    if let Ok(s) = value.decode_as::<der::asn1::Ia5StringRef<'_>>() {
        return Ok(s.as_str().to_owned());
    }
    Err(AppError::bad_request(format!(
        "SCEP attribute {oid} is not a recognised string type"
    )))
}

/// Read an `OCTET STRING` attribute value as raw bytes (e.g. a nonce).
pub fn read_octets(attrs: &SetOfVec<Attribute>, oid: ObjectIdentifier) -> AppResult<Vec<u8>> {
    let attr = find(attrs, oid)
        .ok_or_else(|| AppError::bad_request(format!("missing SCEP attribute {oid}")))?;
    let value = attr
        .values
        .iter()
        .next()
        .ok_or_else(|| AppError::bad_request(format!("empty SCEP attribute {oid}")))?;
    let os = value.decode_as::<OctetString>().map_err(|e| {
        AppError::bad_request(format!("SCEP attribute {oid} not OCTET STRING: {e}"))
    })?;
    Ok(os.as_bytes().to_vec())
}

fn der_err(e: der::Error) -> AppError {
    AppError::crypto(format!("DER error: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_type_round_trips() {
        for mt in [
            MessageType::CertRep,
            MessageType::PkcsReq,
            MessageType::RenewalReq,
            MessageType::GetCertInitial,
            MessageType::GetCert,
            MessageType::GetCrl,
        ] {
            assert_eq!(MessageType::from_value(mt.as_value()).unwrap(), mt);
        }
    }

    #[test]
    fn message_type_tolerates_whitespace() {
        assert_eq!(
            MessageType::from_value(" 19 ").unwrap(),
            MessageType::PkcsReq
        );
    }

    #[test]
    fn message_type_unknown_is_error() {
        assert!(MessageType::from_value("99").is_err());
        assert!(MessageType::from_value("").is_err());
    }

    #[test]
    fn status_and_fail_info_values() {
        assert_eq!(PkiStatus::Success.as_value(), "0");
        assert_eq!(PkiStatus::Failure.as_value(), "2");
        assert_eq!(PkiStatus::Pending.as_value(), "3");
        assert_eq!(FailInfo::BadAlg.as_value(), "0");
        assert_eq!(FailInfo::BadRequest.as_value(), "2");
        assert_eq!(FailInfo::BadCertId.as_value(), "4");
    }

    #[test]
    fn printable_attribute_round_trips() {
        let mut set = SetOfVec::new();
        set.insert(printable_attribute(ID_TRANSACTION_ID, "abc-123").unwrap())
            .unwrap();
        assert_eq!(read_string(&set, ID_TRANSACTION_ID).unwrap(), "abc-123");
    }

    #[test]
    fn octet_attribute_round_trips() {
        let nonce = vec![9u8, 8, 7, 6, 5];
        let mut set = SetOfVec::new();
        set.insert(octet_attribute(ID_SENDER_NONCE, &nonce).unwrap())
            .unwrap();
        assert_eq!(read_octets(&set, ID_SENDER_NONCE).unwrap(), nonce);
    }

    #[test]
    fn reading_a_missing_attribute_is_an_error() {
        let empty: SetOfVec<Attribute> = SetOfVec::new();
        assert!(read_string(&empty, ID_TRANSACTION_ID).is_err());
        assert!(read_octets(&empty, ID_SENDER_NONCE).is_err());
    }

    #[test]
    fn reading_an_octet_attribute_as_string_fails() {
        let mut set = SetOfVec::new();
        set.insert(octet_attribute(ID_SENDER_NONCE, &[1, 2, 3]).unwrap())
            .unwrap();
        assert!(read_string(&set, ID_SENDER_NONCE).is_err());
    }
}
