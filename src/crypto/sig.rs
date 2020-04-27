#[cfg(feature = "crypto-openssl")]
use openssl::{error::ErrorStack, hash::MessageDigest, pkey::PKey, sign::Signer};
#[cfg(feature = "crypto-ring")]
use ring::hmac;

use super::b64;

/// Compute the signature for the given data and key.
/// This is done using an HMAC key using the SHA256 digest.
///
/// If computing the signature failed, an error is returned.
#[cfg(feature = "crypto-openssl")]
fn signature_openssl(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    // Build the key, and signer
    let pkey = PKey::hmac(&key)?;
    let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;

    // Feed the data
    signer.update(&data)?;

    // Compute the signature
    Ok(signer.sign_to_vec()?)
}

/// Compute the signature for the given data and key.
/// This is done using an HMAC key using the SHA256 digest.
#[cfg(feature = "crypto-ring")]
fn signature_ring(key: &[u8], data: &[u8]) -> Vec<u8> {
    let skey = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&skey, data).as_ref().to_owned()
}

/// Compute the signature for the given data and key.
/// This is done using an HMAC key using the SHA256 digest.
///
/// The resulting signature is encoded as base64 string in an URL-safe manner.
///
/// If computing the signature failed, an error is returned.
pub fn signature_encoded(key: &[u8], data: &[u8]) -> Result<String, ()> {
    #[cfg(feature = "crypto-openssl")]
    {
        signature_openssl(key, data)
            .map(|sig| b64::encode(&sig))
            .map_err(|_| ())
    }

    #[cfg(feature = "crypto-ring")]
    {
        Ok(b64::encode(&signature_ring(key, data)))
    }
}
