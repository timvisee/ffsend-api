use std::cmp::max;

use reqwest::Error as ReqwestError;
use thiserror::Error;

use crate::api::data::{Error as DataError, OwnedData};
use crate::api::nonce::{request_nonce, NonceError};
use crate::api::request::{ensure_success, ResponseError};
use crate::api::url::UrlBuilder;
use crate::client::Client;
use crate::file::remote_file::RemoteFile;

/// An action to fetch info of a shared file.
///
/// This API specification for this action is compatible with both Firefox Send v2 and v3.
pub struct Info<'a> {
    /// The remote file to fetch the info for.
    file: &'a RemoteFile,

    /// The authentication nonce.
    /// May be an empty vector if the nonce is unknown.
    nonce: Vec<u8>,
}

impl<'a> Info<'a> {
    /// Construct a new info action for the given remote file.
    pub fn new(file: &'a RemoteFile, nonce: Option<Vec<u8>>) -> Self {
        Self {
            file,
            nonce: nonce.unwrap_or_default(),
        }
    }

    /// Invoke the info action.
    pub fn invoke(mut self, client: &Client) -> Result<InfoResponse, Error> {
        // Fetch the authentication nonce if not set yet
        if self.nonce.is_empty() {
            self.nonce = self.fetch_auth_nonce(client)?;
        }

        // Create owned data, to send to the server for authentication
        let data = OwnedData::from(InfoData::new(), &self.file)
            .map_err(|err| -> PrepareError { err.into() })?;

        // Send the info request
        self.fetch_info(client, &data)
    }

    /// Fetch the authentication nonce for the file from the remote server.
    fn fetch_auth_nonce(&self, client: &Client) -> Result<Vec<u8>, Error> {
        request_nonce(client, UrlBuilder::download(self.file, false)).map_err(|err| err.into())
    }

    /// Send the request for fetching the remote file info.
    fn fetch_info(
        &self,
        client: &Client,
        data: &OwnedData<InfoData>,
    ) -> Result<InfoResponse, Error> {
        // Get the info URL, and send the request
        let url = UrlBuilder::api_info(self.file);
        let response = client
            .post(url)
            .json(&data)
            .send()
            .map_err(|_| InfoError::Request)?;

        // Ensure the response is successful
        ensure_success(&response)?;

        // Decode the JSON response
        let response: InfoResponse = match response.json() {
            Ok(response) => response,
            Err(err) => return Err(InfoError::Decode(err).into()),
        };

        Ok(response)
    }
}

/// The info data object.
/// This object is currently empty, as no additional data is sent to the
/// server.
#[derive(Debug, Serialize, Default)]
pub struct InfoData {}

impl InfoData {
    /// Constructor.
    pub fn new() -> Self {
        InfoData::default()
    }
}

/// The file info response.
#[derive(Debug, Deserialize)]
pub struct InfoResponse {
    /// The download limit.
    #[serde(rename = "dlimit")]
    download_limit: usize,

    /// The total number of times the file has been downloaded.
    #[serde(rename = "dtotal")]
    download_count: usize,

    /// The time to live for this file in milliseconds.
    #[serde(rename = "ttl")]
    ttl: u64,
}

impl InfoResponse {
    /// Get the number of times this file has been downloaded.
    pub fn download_count(&self) -> usize {
        self.download_count
    }

    /// Get the maximum number of times the file may be downloaded.
    pub fn download_limit(&self) -> usize {
        self.download_limit
    }

    /// Get the number of times this file may still be downloaded.
    pub fn download_left(&self) -> usize {
        max(self.download_limit() - self.download_count(), 0)
    }

    /// Get the time to live for this file, in milliseconds from the time the
    /// request was made.
    pub fn ttl_millis(&self) -> u64 {
        self.ttl
    }
}

#[derive(Error, Debug)]
pub enum Error {
    /// An error occurred while preparing the action.
    #[error("failed to prepare the action")]
    Prepare(#[from] PrepareError),

    /// The given Send file has expired, or did never exist in the first place.
    /// Therefore the file could not be downloaded.
    #[error("the file has expired or did never exist")]
    Expired,

    /// An error has occurred while sending the info request to the server.
    #[error("failed to send the file info request")]
    Info(#[from] InfoError),
}

impl From<NonceError> for Error {
    fn from(err: NonceError) -> Error {
        match err {
            NonceError::Expired => Error::Expired,
            err => Error::Prepare(PrepareError::Auth(err)),
        }
    }
}

impl From<ResponseError> for Error {
    fn from(err: ResponseError) -> Error {
        match err {
            ResponseError::Expired => Error::Expired,
            err => Error::Info(InfoError::Response(err)),
        }
    }
}

#[derive(Debug, Error)]
pub enum InfoDataError {
    /// Some error occurred while trying to wrap the info data in an
    /// owned object, which is required for authentication on the server.
    /// The wrapped error further described the problem.
    #[error("")]
    Owned(#[from] DataError),
}

#[derive(Error, Debug)]
pub enum PrepareError {
    /// Failed authenticating, needed to fetch the info
    #[error("failed to authenticate")]
    Auth(#[from] NonceError),

    /// An error occurred while building the info data that will be
    /// send to the server.
    #[error("invalid parameters")]
    InfoData(#[from] InfoDataError),
}

impl From<DataError> for PrepareError {
    fn from(err: DataError) -> PrepareError {
        PrepareError::InfoData(InfoDataError::Owned(err))
    }
}

#[derive(Error, Debug)]
pub enum InfoError {
    /// Sending the request to fetch the file info failed.
    #[error("failed to send file info request")]
    Request,

    /// The server responded with an error while fetching the file info.
    #[error("bad response from server while fetching file info")]
    Response(#[from] ResponseError),

    /// Failed to decode the info response from the server.
    /// Maybe the server responded with data from a newer API version.
    #[error("failed to decode info response")]
    Decode(#[from] ReqwestError),
}
