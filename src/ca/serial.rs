//! Certificate serial number generation.

use rand::RngCore;
use x509_cert::serial_number::SerialNumber;

/// Generate a random positive 16-byte serial number (RFC 5280 requires a
/// positive integer of at most 20 octets; CA/B Forum requires >= 64 bits of
/// entropy).
pub fn random_serial() -> SerialNumber {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    // Clear the top bit so the DER INTEGER is unambiguously positive, and avoid
    // a zero leading byte.
    bytes[0] &= 0x7f;
    if bytes[0] == 0 {
        bytes[0] = 0x01;
    }
    SerialNumber::new(&bytes).expect("16-byte serial is always valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serial_is_positive_and_sized() {
        let serial = random_serial();
        let bytes = serial.as_bytes();
        assert_eq!(bytes.len(), 16, "serial should be 16 bytes");
        assert_eq!(bytes[0] & 0x80, 0, "top bit must be clear (positive)");
        assert_ne!(bytes[0], 0, "no leading zero byte");
    }

    #[test]
    fn serials_are_unique() {
        assert_ne!(random_serial().as_bytes(), random_serial().as_bytes());
    }
}
