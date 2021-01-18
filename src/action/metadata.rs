use reqwest::header::AUTHORIZATION;
use serde::{
    de::{Error as SerdeError, Unexpected},
    Deserialize, Deserializer,
};
use serde_json::{self, Value as JsonValue};
use thiserror::Error;

use super::exists::{Error as ExistsError, Exists as ExistsAction};
use crate::api::nonce::{header_nonce, request_nonce, NonceError};
use crate::api::request::{ensure_success, ResponseError};
use crate::api::url::UrlBuilder;
use crate::client::Client;
use crate::crypto::key_set::KeySet;
use crate::crypto::sig::signature_encoded;
use crate::crypto::{self, api::MetadataError};
use crate::file::metadata::Metadata as MetadataData;
use crate::file::remote_file::RemoteFile;

/// An action to fetch file metadata.
///
/// This API specification for this action is compatible with both Firefox Send v2 and v3.
/// Depending on the server API version, a different metadata enum variant is returned.
pub struct Metadata<'a> {
    /// The remote file to fetch the metadata for.
    file: &'a RemoteFile,

    /// An optional password to decrypt a protected file.
    password: Option<String>,

    /// Check whether the file exists (recommended).
    check_exists: bool,
}

impl<'a> Metadata<'a> {
    /// Construct a new metadata action.
    pub fn new(file: &'a RemoteFile, password: Option<String>, check_exists: bool) -> Self {
        Self {
            file,
            password,
            check_exists,
        }
    }

    /// Invoke the metadata action.
    pub fn invoke(self, client: &Client) -> Result<MetadataResponse, Error> {
        // Make sure the given file exists
        if self.check_exists {
            let exist_response = ExistsAction::new(&self.file).invoke(&client)?;

            // Return an error if the file does not exist
            if !exist_response.exists() {
                return Err(Error::Expired);
            }

            // Make sure a password is given when it is required
            if self.password.is_none() && exist_response.requires_password() {
                return Err(Error::PasswordRequired);
            }
        }

        // Create a key set for the file
        let key = KeySet::from(self.file, self.password.as_ref());

        // Fetch the authentication nonce
        let auth_nonce = self.fetch_auth_nonce(client)?;

        // Fetch the metadata and the metadata nonce, return the result
        self.fetch_metadata(&client, &key, &auth_nonce)
            .map_err(|err| err.into())
    }

    /// Fetch the authentication nonce for the file from the remote server.
    fn fetch_auth_nonce(&self, client: &Client) -> Result<Vec<u8>, Error> {
        request_nonce(client, UrlBuilder::download(self.file, false)).map_err(|err| err.into())
    }

    /// Create a metadata nonce, and fetch the metadata for the file from the
    /// Send server.
    ///
    /// The key set, along with the authentication nonce must be given.
    ///
    /// The metadata, with the meta nonce is returned.
    fn fetch_metadata(
        &self,
        client: &Client,
        key: &KeySet,
        auth_nonce: &[u8],
    ) -> Result<MetadataResponse, MetaError> {
        // Compute the cryptographic signature for authentication
        let sig = signature_encoded(key.auth_key().unwrap(), &auth_nonce)
            .map_err(|_| MetaError::ComputeSignature)?;

        // Build the request, fetch the encrypted metadata
        let response = client
            .get(UrlBuilder::api_metadata(self.file))
            .header(AUTHORIZATION.as_str(), format!("send-v1 {}", sig))
            .send()
            .map_err(|_| MetaError::NonceRequest)?;

        // Ensure the status code is successful
        ensure_success(&response).map_err(MetaError::NonceResponse)?;

        // Get the metadata nonce
        let nonce = header_nonce(&response).map_err(MetaError::Nonce)?;

        // Parse the metadata response
        MetadataResponse::from(
            &response
                .json::<RawMetadataResponse>()
                .map_err(|_| MetaError::Malformed)?,
            &key,
            nonce,
        )
        .map_err(|_| MetaError::Decrypt)
    }
}

/// The metadata response from the server, when fetching the data through
/// the API.
/// This response contains raw metadata, which is still encrypted.
// TODO: rename this into EncryptedMetadataResponse?
// TODO: don't use enum, make size field optional
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum RawMetadataResponse {
    /// Raw metadata using in Send v2.
    V2 {
        /// The encrypted metadata.
        #[serde(rename = "metadata")]
        meta: String,

        /// The file size in bytes.
        #[serde(deserialize_with = "deserialize_u64")]
        size: u64,
    },

    /// Raw metadata using in Send v3.
    V3 {
        /// The encrypted metadata.
        #[serde(rename = "metadata")]
        meta: String,
    },
    // TODO: Use `finalDownload` field?
    // TODO: Use `ttl` field?
}

impl RawMetadataResponse {
    /// Get and decrypt the metadata, based on the raw data in this response.
    ///
    /// The decrypted data is verified using an included tag.
    /// If verification failed, an error is returned.
    pub fn decrypt_metadata(&self, key_set: &KeySet) -> Result<MetadataData, MetadataError> {
        crypto::api::decrypt_metadata(self.meta(), key_set)
    }

    /// Get the encrypted metadata.
    fn meta(&self) -> &str {
        match self {
            RawMetadataResponse::V2 { meta, .. } => &meta,
            RawMetadataResponse::V3 { meta } => &meta,
        }
    }

    /// Get the file size in bytes, if provided by the server (`= Send v2`).
    // TODO: use proper size
    // pub fn size(&self) -> Option<u64> {
    //     self.size
    // }
    pub fn size(&self) -> Option<u64> {
        match self {
            RawMetadataResponse::V2 { size, .. } => Some(*size),
            RawMetadataResponse::V3 { .. } => None,
        }
    }
}

/// A more forgiving deserializer for u64 values than the strict default.
/// This is used when deserializing raw metadata,
/// as the file size u64 is formatted as a string.
fn deserialize_u64<'d, D>(d: D) -> Result<u64, D::Error>
where
    D: Deserializer<'d>,
{
    Deserialize::deserialize(d).and_then(|value: JsonValue| match value {
        JsonValue::Number(n) => n.as_u64().ok_or_else(|| {
            if let Some(n) = n.as_i64() {
                SerdeError::invalid_type(Unexpected::Signed(n), &"a positive integer")
            } else if let Some(n) = n.as_f64() {
                SerdeError::invalid_type(Unexpected::Float(n), &"a positive integer")
            } else {
                SerdeError::invalid_type(Unexpected::Str(&n.to_string()), &"a positive integer")
            }
        }),
        JsonValue::String(s) => s
            .parse()
            .map_err(|_| SerdeError::invalid_type(Unexpected::Str(&s), &"a positive integer")),
        o => Err(SerdeError::invalid_type(
            Unexpected::Other(&o.to_string()),
            &"a positive integer",
        )),
    })
}

/// The decoded and decrypted metadata response, holding all the properties.
/// This response object is returned from this action.
pub struct MetadataResponse {
    /// The actual metadata.
    metadata: MetadataData,

    /// The file size in bytes, if provided by the server (`< send v3`).
    size: Option<u64>,

    /// The metadata nonce.
    nonce: Vec<u8>,
}

impl<'a> MetadataResponse {
    /// Construct a new response with the given metadata and nonce.
    pub fn new(metadata: MetadataData, size: Option<u64>, nonce: Vec<u8>) -> Self {
        MetadataResponse {
            metadata,
            size,
            nonce,
        }
    }

    // Construct a new metadata response from the given raw metadata response,
    // with an additional key set and nonce.
    //
    // This internally decrypts the metadata from the raw response.
    // An error is returned if decrypting the metadata failed.
    pub fn from(
        raw: &RawMetadataResponse,
        key_set: &KeySet,
        nonce: Vec<u8>,
    ) -> Result<Self, MetadataError> {
        Ok(Self::new(raw.decrypt_metadata(key_set)?, raw.size(), nonce))
    }

    /// Get the metadata.
    pub fn metadata(&self) -> &MetadataData {
        &self.metadata
    }

    /// Get the file size in bytes.
    pub fn size(&self) -> u64 {
        // TODO: return proper error if not set, should never happen with current API
        self.size
            .unwrap_or_else(|| self.metadata.size().expect("file size unknown, newer API?"))
    }

    /// Get the nonce.
    pub fn nonce(&self) -> &Vec<u8> {
        &self.nonce
    }
}

#[derive(Error, Debug)]
pub enum Error {
    /// An error occurred while checking whether the file exists on the
    /// server.
    #[error("failed to check whether the file exists")]
    Exists(#[from] ExistsError),

    /// A general error occurred while requesting the file data.
    /// This may be because authentication failed, because decrypting the
    /// file metadata didn't succeed, or due to some other reason.
    #[error("failed to request file data")]
    Request(#[from] RequestError),

    /// The given Send file has expired, or did never exist in the first place.
    /// Therefore the file could not be downloaded.
    #[error("the file has expired or did never exist")]
    Expired,

    /// A password is required, but was not given.
    #[error("missing password, password required")]
    PasswordRequired,
}

impl From<MetaError> for Error {
    fn from(err: MetaError) -> Error {
        Error::Request(RequestError::Meta(err))
    }
}

impl From<NonceError> for Error {
    fn from(err: NonceError) -> Error {
        match err {
            NonceError::Expired => Error::Expired,
            err => Error::Request(RequestError::Auth(err)),
        }
    }
}

#[derive(Error, Debug)]
pub enum RequestError {
    /// Failed authenticating, in order to fetch the file data.
    #[error("failed to authenticate")]
    Auth(#[from] NonceError),

    /// Failed to retrieve the file metadata.
    #[error("failed to retrieve file metadata")]
    Meta(#[from] MetaError),
}

#[derive(Error, Debug)]
pub enum MetaError {
    /// An error occurred while computing the cryptographic signature used for
    /// decryption.
    #[error("failed to compute cryptographic signature")]
    ComputeSignature,

    /// Sending the request to gather the metadata encryption nonce failed.
    #[error("failed to request metadata nonce")]
    NonceRequest,

    /// The server responded with an error while fetching the metadata
    /// encryption nonce.
    #[error("bad response from server while fetching metadata nonce")]
    NonceResponse(#[from] ResponseError),

    /// Couldn't parse the metadata encryption nonce.
    #[error("failed to parse the metadata encryption nonce")]
    Nonce(#[from] NonceError),

    /// The received metadata is malformed, and couldn't be decoded or
    /// interpreted.
    #[error("received malformed metadata")]
    Malformed,

    /// Failed to decrypt the received metadata.
    #[error("failed to decrypt received metadata")]
    Decrypt,
}
