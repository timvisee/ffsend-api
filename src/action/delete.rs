use thiserror::Error;

use crate::api::data::{Error as DataError, OwnedData};
use crate::api::nonce::{request_nonce, NonceError};
use crate::api::request::{ensure_success, ResponseError};
use crate::api::url::UrlBuilder;
use crate::client::Client;
use crate::file::remote_file::RemoteFile;

/// An action to delete a remote file.
///
/// This API specification for this action is compatible with both Firefox Send v2 and v3.
pub struct Delete<'a> {
    /// The remote file to delete.
    file: &'a RemoteFile,

    /// The authentication nonce.
    /// May be an empty vector if the nonce is unknown.
    nonce: Vec<u8>,
}

impl<'a> Delete<'a> {
    /// Construct a new delete action for the given file.
    pub fn new(file: &'a RemoteFile, nonce: Option<Vec<u8>>) -> Self {
        Self {
            file,
            nonce: nonce.unwrap_or_default(),
        }
    }

    /// Invoke the delete action.
    pub fn invoke(mut self, client: &Client) -> Result<(), Error> {
        // Fetch the authentication nonce if not set yet
        if self.nonce.is_empty() {
            self.nonce = self.fetch_auth_nonce(client)?;
        }

        // Create owned data, to send to the server for authentication
        let data = OwnedData::from(DeleteData::new(), &self.file)
            .map_err(|err| PrepareError::DeleteData(DeleteDataError::Owned(err)))?;

        // Send the delete request
        self.request_delete(client, &data)
    }

    /// Fetch the authentication nonce for the file from the remote server.
    fn fetch_auth_nonce(&self, client: &Client) -> Result<Vec<u8>, Error> {
        request_nonce(client, UrlBuilder::download(self.file, false)).map_err(|err| err.into())
    }

    /// Send a request to delete the remote file, with the given data.
    fn request_delete(&self, client: &Client, data: &OwnedData<DeleteData>) -> Result<(), Error> {
        // Get the delete URL, and send the request
        let url = UrlBuilder::api_delete(self.file);
        let response = client
            .post(url)
            .json(&data)
            .send()
            .map_err(|_| DeleteError::Request)?;

        // Ensure the status code is successful
        ensure_success(&response).map_err(|err| err.into())
    }
}

/// The delete data object.
/// This object is currently empty, as no additional data is sent to the
/// server.
#[derive(Debug, Serialize, Default)]
pub struct DeleteData {}

impl DeleteData {
    /// Constructor.
    pub fn new() -> Self {
        DeleteData::default()
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

    /// An error has occurred while sending the file deletion request.
    #[error("failed to send the file deletion request")]
    Delete(#[from] DeleteError),
}

impl From<NonceError> for Error {
    fn from(err: NonceError) -> Error {
        match err {
            NonceError::Expired => Error::Expired,
            err => Error::Prepare(PrepareError::Auth(err)),
        }
    }
}

#[derive(Debug, Error)]
pub enum DeleteDataError {
    /// Some error occurred while trying to wrap the deletion data in an
    /// owned object, which is required for authentication on the server.
    /// The wrapped error further described the problem.
    #[error("")]
    Owned(#[from] DataError),
}

#[derive(Error, Debug)]
pub enum PrepareError {
    /// Failed to authenticate
    #[error("failed to authenticate")]
    Auth(#[from] NonceError),

    /// An error occurred while building the deletion data that will be
    /// send to the server.
    #[error("invalid parameters")]
    DeleteData(#[from] DeleteDataError),
}

#[derive(Error, Debug)]
pub enum DeleteError {
    /// Sending the file deletion request failed.
    #[error("failed to send file deletion request")]
    Request,

    /// The server responded with an error while requesting file deletion.
    #[error("bad response from server while deleting file")]
    Response(#[from] ResponseError),
}

impl From<ResponseError> for Error {
    fn from(err: ResponseError) -> Self {
        match err {
            ResponseError::Expired => Error::Expired,
            err => Error::Delete(DeleteError::Response(err)),
        }
    }
}
