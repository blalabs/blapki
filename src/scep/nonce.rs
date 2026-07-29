//! SCEP nonces.
//!
//! Each SCEP message carries a 16-byte `senderNonce`; a response echoes the
//! request's nonce back as its `recipientNonce`, giving replay protection.

use rand::RngCore;

/// SCEP nonce length in bytes (RFC 8894 recommends 16).
pub const NONCE_LEN: usize = 16;

/// Generate a fresh random nonce.
pub fn generate() -> Vec<u8> {
    let mut buf = vec![0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut buf);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonce_has_expected_length() {
        assert_eq!(generate().len(), NONCE_LEN);
    }

    #[test]
    fn nonces_are_not_repeated() {
        assert_ne!(generate(), generate());
    }
}
