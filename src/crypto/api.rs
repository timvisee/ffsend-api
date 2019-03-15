#[cfg(feature = "crypto-openssl")]
use openssl;
#[cfg(feature = "crypto-ring")]
use ring::aead;
use serde_json;

#[cfg(feature = "crypto-openssl")]
use crate::config::TAG_LEN;
use crate::crypto::{b64, key_set::KeySet};
use crate::file::metadata::Metadata as MetadataData;

/// Get and decrypt the given raw `metadata` string.
///
/// The decrypted data is verified using an included tag.
/// If verification failed, an error is returned.
pub fn decrypt_metadata(metadata: &str, key_set: &KeySet) -> Result<MetadataData, MetadataError> {
    // Decode the metadata
    let mut raw = b64::decode(metadata)?;

    // Decrypt the metadata
    let meta: Vec<u8> = decrypt_aead(key_set, &mut raw)?;

    // Parse the metadata, and return
    Ok(serde_json::from_slice(&meta)?)
}

/// Decrypt the given AEAD `payload` including the verification tag.
///
/// A key set must be given for the metadata key and input vector.
/// The default cipher used for Firefox Send is used.
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
            Some(key_set.iv()),
            &[],
            encrypted,
            tag,
        ).map_err(|_| Error::Decrypt)
    }

    #[cfg(feature = "crypto-ring")]
    {
        let key = aead::OpeningKey::new(&aead::AES_128_GCM, key_set.meta_key().unwrap()).map_err(|_| Error::Decrypt)?;
        let nonce = aead::Nonce::try_assume_unique_for_key(key_set.iv()).map_err(|_| Error::Decrypt)?;
        aead::open_in_place(
            &key,
            nonce,
            aead::Aad::empty(),
            0,
            payload,
        ).map(|plaintext| plaintext.to_vec()).map_err(|_| Error::Decrypt)
    }
}

#[derive(Fail, Debug)]
pub enum MetadataError {
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

impl From<Error> for MetadataError {
    fn from(err: Error) -> Self {
        MetadataError::Decrypt(err)
    }
}

impl From<serde_json::Error> for MetadataError {
    fn from(err: serde_json::Error) -> Self {
        MetadataError::Parse(err)
    }
}

#[derive(Fail, Debug)]
pub enum Error {
    /// An error occurred while decrypting the given data.
    #[fail(display = "failed to decrypt given raw data")]
    Decrypt,
}
