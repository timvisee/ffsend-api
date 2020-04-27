extern crate hkdf;
extern crate sha2;

#[cfg(feature = "crypto-ring")]
use std::num::NonZeroU32;

use self::hkdf::Hkdf;
use self::sha2::Sha256;
#[cfg(feature = "crypto-openssl")]
use openssl::{hash::MessageDigest, pkcs5::pbkdf2_hmac};
#[cfg(feature = "crypto-ring")]
use ring::pbkdf2;
use url::Url;

/// The length of the derived authentication key in bytes.
const KEY_AUTH_SIZE: usize = 64;

/// The number of iterations to do for deriving a passworded authentication
/// key.
const KEY_AUTH_ITERATIONS: usize = 100;

/// Derive a HKDF key.
///
/// # Arguments
/// * salt - Key salt, `None` for no salt
/// * length - Length of the derived key value that is returned.
/// * ikm - The input keying material.
/// * info - Optional context and application specific information to use.
///
/// # Returns
/// The output keying material, with the length as as specified in the `length`
/// argument.
pub fn hkdf(salt: Option<&[u8]>, length: usize, ikm: &[u8], info: Option<&[u8]>) -> Vec<u8> {
    // Unwrap info or use empty info, define output key material
    let info = info.unwrap_or(&[]);
    let mut okm = vec![0u8; length];

    // Derive a HKDF key with the given length
    Hkdf::<Sha256>::extract(salt, &ikm)
        .1
        .expand(&info, &mut okm)
        .unwrap();

    okm
}

/// Derive a key to use for file data encryption, based on the given `secret`.
pub fn derive_file_key(secret: &[u8]) -> Vec<u8> {
    hkdf(None, 16, secret, Some(b"encryption"))
}

/// Derive a key to use for metadata encryption, based on the given `secret`.
pub fn derive_meta_key(secret: &[u8]) -> Vec<u8> {
    hkdf(None, 16, secret, Some(b"metadata"))
}

/// Derive a key used for authentication, based on the given `secret`.
///
/// A `password` and `url` may be given for special key deriving.
/// At this time this is not implemented however.
pub fn derive_auth_key(secret: &[u8], password: Option<&str>, url: Option<&Url>) -> Vec<u8> {
    // Nothing, or both a password and URL must be given
    assert_eq!(
        password.is_none(),
        url.is_none(),
        "unable to derive authentication key, missing password or URL",
    );

    // Derive a key without a password
    if password.is_none() {
        return hkdf(None, KEY_AUTH_SIZE, secret, Some(b"authentication"));
    }

    // Derive a key with a password and URL
    let mut key = vec![0u8; KEY_AUTH_SIZE];

    // TODO: do not expect/unwrap here
    #[cfg(feature = "crypto-openssl")]
    pbkdf2_hmac(
        password.unwrap().as_bytes(),
        url.unwrap().as_str().as_bytes(),
        KEY_AUTH_ITERATIONS,
        MessageDigest::sha256(),
        &mut key,
    )
    .expect("failed to derive passworded authentication key");

    #[cfg(feature = "crypto-ring")]
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(KEY_AUTH_ITERATIONS as u32)
            .expect("key authentication iteration count cannot be 0"),
        url.unwrap().as_str().as_bytes(),
        password.unwrap().as_bytes(),
        &mut key,
    );

    key
}
