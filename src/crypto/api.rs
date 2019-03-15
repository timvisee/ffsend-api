#[cfg(feature = "crypto-openssl")]
use openssl;
#[cfg(feature = "crypto-ring")]
use ring::aead;
use serde_json;

use crate::config::TAG_LEN;
use crate::crypto::{b64, key_set::KeySet};
use crate::file::metadata::Metadata;

/// Encrypt the given `metadata` object.
///
/// The encrypted data includes a verification tag.
pub fn encrypt_metadata(metadata: Metadata, key_set: &KeySet) -> Result<String, MetadataError> {
    // Obtain the raw metadata
    let raw = metadata.to_json().into_bytes();

    // Encrypt the metadata
    let payload: Vec<u8> = encrypt_aead(key_set, &raw).map_err(MetadataError::Encrypt)?;

    // Encode the metadata
    Ok(b64::encode(&payload))
}

/// Get and decrypt the given raw `metadata` string.
///
/// The decrypted data is verified using an included tag.
/// If verification failed, an error is returned.
pub fn decrypt_metadata(metadata: &str, key_set: &KeySet) -> Result<Metadata, MetadataError> {
    // Decode the metadata
    let mut raw = b64::decode(metadata)?;

    // Decrypt the metadata
    let meta: Vec<u8> = decrypt_aead(key_set, &mut raw).map_err(MetadataError::Decrypt)?;

    // Parse the metadata, and return
    Ok(serde_json::from_slice(&meta)?)
}

/// Encrypt the given `plaintext`.
///
/// A key set must be given for the metadata key and input vector.
/// The default cipher for Firefox Send is used.
// TODO: do not drop errors here
fn encrypt_aead(key_set: &KeySet, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "crypto-openssl")]
    {
        // Encrypt the metadata, append the tag
        let mut metadata_tag = vec![0u8; 16];
        let mut metadata = openssl::symm::encrypt_aead(
            openssl::symm::Cipher::aes_128_gcm(),
            key_set.meta_key().unwrap(),
            Some(&[0u8; 12]),
            &[],
            &plaintext,
            &mut metadata_tag,
        )
        .map_err(|_| Error::Encrypt)?;
        metadata.append(&mut metadata_tag);
        Ok(metadata)
    }

    #[cfg(feature = "crypto-ring")]
    {
        // Own the plaintext buffer
        let mut buf = plaintext.to_vec();

        // Allocate space for tag
        // TODO: this can be improved!
        buf.reserve(TAG_LEN);
        for _ in 0..TAG_LEN {
            buf.push(0);
        }

        // Encrypt the metadata
        // TODO: do not unwrap here
        let key = aead::SealingKey::new(&aead::AES_128_GCM, key_set.meta_key().unwrap()).unwrap();
        let nonce = aead::Nonce::try_assume_unique_for_key(key_set.nonce()).unwrap();
        let encrypted = aead::seal_in_place(&key, nonce, aead::Aad::empty(), &mut buf, TAG_LEN);

        // Verify seal byte count, map data into actual payload
        encrypted.map_err(|_| Error::Encrypt).and_then(|len| {
            if len != buf.len() {
                Err(Error::Encrypt)
            } else {
                Ok(buf)
            }
        })
    }
}

/// Decrypt the given AEAD `payload` including the verification tag.
///
/// A key set must be given for the metadata key and input vector.
/// The default cipher for Firefox Send is used.
// TODO: do not drop errors here
fn decrypt_aead(key_set: &KeySet, payload: &mut [u8]) -> Result<Vec<u8>, Error> {
    #[cfg(feature = "crypto-openssl")]
    {
        // Get the encrypted metadata, and it's tag
        let (encrypted, tag) = payload.split_at(payload.len() - TAG_LEN);
        assert_eq!(tag.len(), TAG_LEN);

        // Decrypt
        openssl::symm::decrypt_aead(
            openssl::symm::Cipher::aes_128_gcm(),
            key_set.meta_key().unwrap(),
            Some(key_set.nonce()),
            &[],
            encrypted,
            tag,
        )
        .map_err(|_| Error::Decrypt)
    }

    #[cfg(feature = "crypto-ring")]
    {
        // TODO: do not unwrap here
        let key = aead::OpeningKey::new(&aead::AES_128_GCM, key_set.meta_key().unwrap())
            .map_err(|_| Error::Decrypt)?;
        let nonce =
            aead::Nonce::try_assume_unique_for_key(key_set.nonce()).map_err(|_| Error::Decrypt)?;
        aead::open_in_place(&key, nonce, aead::Aad::empty(), 0, payload)
            .map(|plaintext| plaintext.to_vec())
            .map_err(|_| Error::Decrypt)
    }
}

#[derive(Fail, Debug)]
pub enum MetadataError {
    /// An error occurred while encrypting metadata.
    #[fail(display = "failed to encrypt file metadata")]
    Encrypt(#[cause] Error),

    /// An error occurred while decoding the metadata.
    #[fail(display = "failed to decrypt file metadata")]
    Decode(#[cause] b64::DecodeError),

    /// An error occurred while decrypting metadata.
    #[fail(display = "failed to decrypt file metadata")]
    Decrypt(#[cause] Error),

    /// An error occurred while parsing the decrypted metadata.
    #[fail(display = "failed to parse decrypted file metadata")]
    Parse(#[cause] serde_json::Error),
}

impl From<b64::DecodeError> for MetadataError {
    fn from(err: b64::DecodeError) -> Self {
        MetadataError::Decode(err)
    }
}

impl From<serde_json::Error> for MetadataError {
    fn from(err: serde_json::Error) -> Self {
        MetadataError::Parse(err)
    }
}

#[derive(Fail, Debug)]
pub enum Error {
    /// An error occurred while decrypting the given plaintext.
    #[fail(display = "failed to encrypt given plaintext")]
    Encrypt,

    /// An error occurred while decrypting the given ciphertext.
    #[fail(display = "failed to decrypt given ciphertext")]
    Decrypt,
}
