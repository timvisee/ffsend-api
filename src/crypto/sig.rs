use ring::digest::SHA256;
use ring::hmac::{self, Signature, SigningKey};

use super::b64;

/// Compute the signature for the given data and key.
/// This is done using an HMAC key using the SHA256 digest.
///
/// If computing the signature failed, an error is returned.
// TODO: return the signature struct
pub fn sign(key: &[u8], data: &[u8]) -> Signature {
    hmac::sign(
        &SigningKey::new(&SHA256, key),
        data,
    )
}

/// Compute the signature for the given data and key.
/// This is done using an HMAC key using the SHA256 digest.
///
/// The resulting signature is encoded as base64 string in an URL-safe manner.
///
/// If computing the signature failed, an error is returned.
pub fn sign_encode(key: &[u8], data: &[u8]) -> String {
    b64::encode(sign(key, data).as_ref())
}
