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
