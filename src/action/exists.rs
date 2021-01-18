use thiserror::Error;

use crate::api::request::{ensure_success, ResponseError};
use crate::api::url::UrlBuilder;
use crate::client::Client;
use crate::file::remote_file::RemoteFile;

/// An action to check whether a remote file exists.
/// This aciton returns an `ExistsResponse`, that defines whether the file
/// exists, and whether it is protected by a password.
///
/// This API specification for this action is compatible with both Firefox Send v2 and v3.
pub struct Exists<'a> {
    /// The remote file to check.
    file: &'a RemoteFile,
}

impl<'a> Exists<'a> {
    /// Construct a new exists action.
    pub fn new(file: &'a RemoteFile) -> Self {
        Self { file }
    }

    /// Invoke the exists action.
    pub fn invoke(self, client: &Client) -> Result<ExistsResponse, Error> {
        self.check_exists(&client)
    }

    /// Send a request to check whether the file exists
    fn check_exists(&self, client: &Client) -> Result<ExistsResponse, Error> {
        // Get the download url, and parse the nonce
        let exists_url = UrlBuilder::api_exists(self.file);
        let response = client.get(exists_url).send().map_err(|_| Error::Request)?;

        // Ensure the status code is successful, check the expiry state
        match ensure_success(&response) {
            Ok(_) => {}
            Err(ResponseError::Expired) => return Ok(ExistsResponse::new(false, false)),
            Err(err) => return Err(Error::Response(err)),
        }

        // Parse the response
        let mut response = response
            .json::<ExistsResponse>()
            .map_err(|_| Error::Malformed)?;
        response.set_exists(true);

        // TODO: fetch the metadata nonce from the response headers

        Ok(response)
    }
}

/// The exists response.
#[derive(Debug, Deserialize)]
pub struct ExistsResponse {
    /// Whether the file exists.
    #[serde(skip)]
    exists: bool,

    /// Whether this file requires a password.
    // This field is named `password` in Send v2
    #[serde(rename = "requiresPassword", alias = "password")]
    requires_password: bool,
}

impl ExistsResponse {
    /// Construct a new response.
    pub fn new(exists: bool, requires_password: bool) -> Self {
        ExistsResponse {
            exists,
            requires_password,
        }
    }

    /// Whether the remote file exists on the server.
    pub fn exists(&self) -> bool {
        self.exists
    }

    /// Set whether the remote file exists.
    pub fn set_exists(&mut self, exists: bool) {
        self.exists = exists;
    }

    /// Whether the remote file is protected by a password.
    #[deprecated(since = "0.2", note = "please use `requires_password` instead")]
    pub fn has_password(&self) -> bool {
        self.requires_password()
    }

    /// Whether the remote file is protected by a password.
    pub fn requires_password(&self) -> bool {
        self.requires_password
    }
}

impl Default for ExistsResponse {
    fn default() -> Self {
        ExistsResponse {
            exists: false,
            requires_password: false,
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    /// Sending the request to check whether the file exists failed.
    #[error("failed to send request whether the file exists")]
    Request,

    /// The server responded with an error while checking whether the file
    /// exists.
    #[error("bad response from server while checking file existence")]
    Response(#[from] ResponseError),

    /// The response from the server when checking if the file exists was
    /// malformed.
    /// Maybe the server responded with a new format that isn't supported yet
    /// by this client.
    #[error("received malformed authentication nonce")]
    Malformed,
}
