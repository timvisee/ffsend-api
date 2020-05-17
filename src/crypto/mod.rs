pub(crate) mod api;
pub mod b64;
pub mod hkdf;
pub mod key_set;
pub mod sig;

// Re-export the cryptographically secure random bytes generator
#[cfg(feature = "crypto-openssl")]
pub use openssl::rand::rand_bytes;

/// Cryptographically secure random bytes generator.
#[cfg(feature = "crypto-ring")]
pub fn rand_bytes(buf: &mut [u8]) -> Result<(), ring::error::Unspecified> {
    use ring::rand::{SecureRandom, SystemRandom};
    SystemRandom::new().fill(buf)
}
