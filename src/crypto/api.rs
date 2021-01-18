#[cfg(feature = "crypto-openssl")]
use openssl;
#[cfg(feature = "crypto-ring")]
use ring::aead;
use serde_json;
use thiserror::Error;

#[cfg(feature = "crypto-openssl")]
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
    let nonce = [0u8; 12];

    #[cfg(feature = "crypto-openssl")]
    {
        // Encrypt the metadata, append the tag
        let mut metadata_tag = vec![0u8; 16];
        let mut metadata = openssl::symm::encrypt_aead(
            openssl::symm::Cipher::aes_128_gcm(),
            key_set.meta_key().unwrap(),
            Some(&nonce),
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
        // We need to own the buffer to seal in place, make room for appended tag
        let mut buf = plaintext.to_vec();

        // Prepare sealing key
        let nonce = aead::Nonce::assume_unique_for_key(nonce);
        let aad = aead::Aad::empty();
        let unbound_key =
            aead::UnboundKey::new(&aead::AES_128_GCM, key_set.meta_key().unwrap()).unwrap();
        let key = aead::LessSafeKey::new(unbound_key);

        // Seal in place, return sealed
        key.seal_in_place_append_tag(nonce, aad, &mut buf)
            .map_err(|_| Error::Encrypt)?;
        Ok(buf.to_vec())
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
        // Prepare sealing key
        let nonce =
            aead::Nonce::try_assume_unique_for_key(key_set.nonce()).map_err(|_| Error::Decrypt)?;
        let aad = aead::Aad::empty();
        let unbound_key =
            aead::UnboundKey::new(&aead::AES_128_GCM, key_set.meta_key().unwrap()).unwrap();
        let key = aead::LessSafeKey::new(unbound_key);

        // Open in place and return data
        Ok(key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::Decrypt)?
            .to_vec())
    }
}

#[derive(Error, Debug)]
pub enum MetadataError {
    /// An error occurred while encrypting metadata.
    #[error("failed to encrypt file metadata")]
    Encrypt(#[source] Error),

    /// An error occurred while decoding the metadata.
    #[error("failed to decrypt file metadata")]
    Decode(#[from] b64::DecodeError),

    /// An error occurred while decrypting metadata.
    #[error("failed to decrypt file metadata")]
    Decrypt(#[source] Error),

    /// An error occurred while parsing the decrypted metadata.
    #[error("failed to parse decrypted file metadata")]
    Parse(#[from] serde_json::Error),
}

impl From<Error> for MetadataError {
    fn from(e: Error) -> Self {
        match e {
            Error::Encrypt => Self::Encrypt(e),
            Error::Decrypt => Self::Decrypt(e),
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    /// An error occurred while decrypting the given plaintext.
    #[error("failed to encrypt given plaintext")]
    Encrypt,

    /// An error occurred while decrypting the given ciphertext.
    #[error("failed to decrypt given ciphertext")]
    Decrypt,
}
