use thiserror::Error;

use crate::api::data::{Error as DataError, OwnedData};
use crate::api::nonce::{request_nonce, NonceError};
use crate::api::request::{ensure_success, ResponseError};
use crate::api::url::UrlBuilder;
use crate::api::Version;
use crate::client::Client;
use crate::file::remote_file::RemoteFile;

/// The minimum allowed number of downloads, enforced by the server.
// TODO: remove parameter, use from config
pub const PARAMS_DOWNLOAD_MIN: u8 = 1;

/// The maximum (inclusive) allowed number of downloads,
/// enforced by the server.
// TODO: remove parameter, use from config
pub const PARAMS_DOWNLOAD_MAX: u8 = 20;

/// An action to set parameters for a shared file.
///
/// This API specification for this action is compatible with both Firefox Send v2 and v3.
pub struct Params<'a> {
    /// The remote file to change the parameters for.
    file: &'a RemoteFile,

    /// The parameter data that is sent to the server.
    params: ParamsData,

    /// The authentication nonce.
    /// May be an empty vector if the nonce is unknown.
    nonce: Vec<u8>,
}

impl<'a> Params<'a> {
    /// Construct a new parameters action for the given remote file.
    pub fn new(file: &'a RemoteFile, params: ParamsData, nonce: Option<Vec<u8>>) -> Self {
        Self {
            file,
            params,
            nonce: nonce.unwrap_or_default(),
        }
    }

    /// Invoke the parameters action.
    pub fn invoke(mut self, client: &Client) -> Result<(), Error> {
        // TODO: validate that the parameters object isn't empty

        // Fetch the authentication nonce if not set yet
        if self.nonce.is_empty() {
            self.nonce = self.fetch_auth_nonce(client)?;
        }

        // Wrap the parameters data
        let data = OwnedData::from(self.params.clone(), &self.file)
            .map_err(|err| -> PrepareError { err.into() })?;

        // Send the request to change the parameters
        self.change_params(client, &data)
    }

    /// Fetch the authentication nonce for the file from the remote server.
    fn fetch_auth_nonce(&self, client: &Client) -> Result<Vec<u8>, Error> {
        request_nonce(client, UrlBuilder::download(self.file, false)).map_err(|err| err.into())
    }

    /// Send the request for changing the parameters.
    fn change_params(&self, client: &Client, data: &OwnedData<ParamsData>) -> Result<(), Error> {
        // Get the params URL, and send the change
        let url = UrlBuilder::api_params(self.file);
        let response = client
            .post(url)
            .json(&data)
            .send()
            .map_err(|_| ChangeError::Request)?;

        // Ensure the response is successful
        ensure_success(&response).map_err(|err| err.into())
    }
}

/// The parameters data object, that is sent to the server.
// TODO: make sure builder parameters are in-bound as well
#[derive(Clone, Debug, Builder, Serialize)]
pub struct ParamsData {
    /// The number of times this file may be downloaded.
    /// This value must be within a specific range, as enforced by Send servers.
    #[serde(default)]
    #[builder(default)]
    pub download_limit: Option<u8>,

    /// The time in seconds after when the file expires.
    /// This value must be within a specific range, as enforced by Send servers.
    /// Only used with Send v3.
    #[serde(default)]
    #[builder(default)]
    #[serde(rename = "timeLimit")]
    pub expiry_time: Option<usize>,
}

impl ParamsData {
    /// Construct a new parameters object, that is empty.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new parameters data object, with the given parameters.
    // TODO: the values must be between bounds
    pub fn from(download_limit: Option<u8>, expiry_time: Option<usize>) -> Self {
        ParamsData {
            download_limit,
            expiry_time,
        }
    }

    /// Set the maximum number of allowed downloads, after which the file
    /// will be removed.
    ///
    /// `None` may be given, to keep this parameter as is.
    ///
    /// An error may be returned if the download value is out of the allowed
    /// bound. These bounds are fixed and enforced by the server.
    /// See `PARAMS_DOWNLOAD_MIN` and `PARAMS_DOWNLOAD_MAX`.
    pub fn set_download_limit(
        &mut self,
        download_limit: Option<u8>,
    ) -> Result<(), ParamsDataError> {
        // TODO: use better bound check based on version

        // Check the download limit bounds
        if let Some(d) = download_limit {
            if d < PARAMS_DOWNLOAD_MIN || d > PARAMS_DOWNLOAD_MAX {
                return Err(ParamsDataError::DownloadBounds);
            }
        }

        // Set the download limit
        self.download_limit = download_limit;
        Ok(())
    }

    /// Set the expiry time in seconds for files.
    ///
    /// `None` may be given, to keep this parameter as is.
    ///
    /// An error may be returned if the expiry time value is out of the allowed
    /// bound. These bounds are fixed and enforced by the server.
    #[cfg(feature = "send3")]
    pub fn set_expiry_time(&mut self, expiry_time: Option<usize>) -> Result<(), ParamsDataError> {
        // TODO: do proper bound check based on version

        // // Check the download limit bounds
        // if let Some(d) = expiry_time {
        //     if d < PARAMS_DOWNLOAD_MIN || d > PARAMS_DOWNLOAD_MAX {
        //         return Err(ParamsDataError::DownloadBounds);
        //     }
        // }

        // Set the expiry time
        self.expiry_time = expiry_time;
        Ok(())
    }

    /// Check whether this parameters object is empty,
    /// and wouldn't change any parameter on the server when sent.
    /// Sending an empty parameter data object would thus be useless.
    pub fn is_empty(&self) -> bool {
        self.download_limit.is_none() && self.expiry_time.is_none()
    }

    /// Normalize this data for the given version.
    ///
    /// For example, Send v2 does not support the expiry time field. If normalizing for this
    /// version this field is dropped from the struct.
    #[allow(unused_variables)]
    pub fn normalize(&mut self, version: Version) {
        #[cfg(feature = "send2")]
        {
            #[allow(unreachable_patterns)]
            match version {
                Version::V2 => self.expiry_time = None,
                _ => {}
            }
        }
    }
}

impl Default for ParamsData {
    fn default() -> ParamsData {
        ParamsData {
            download_limit: None,
            expiry_time: None,
        }
    }
}

#[derive(Error, Debug)]
pub enum Error {
    /// An error occurred while preparing the action.
    #[error("failed to prepare setting the parameters")]
    Prepare(#[from] PrepareError),

    /// The given Send file has expired, or did never exist in the first place.
    /// Therefore the file could not be downloaded.
    #[error("the file has expired or did never exist")]
    Expired,

    /// An error has occurred while sending the parameter change request to
    /// the server.
    #[error("failed to send the parameter change request")]
    Change(#[from] ChangeError),
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
            err => Error::Change(ChangeError::Response(err)),
        }
    }
}

#[derive(Debug, Error)]
pub enum ParamsDataError {
    /// The number of downloads is invalid, as it was out of the allowed
    /// bounds. See `PARAMS_DOWNLOAD_MIN` and `PARAMS_DOWNLOAD_MAX`.
    // TODO: use bound values from constants, don't hardcode them here
    #[error("invalid number of downloads, must be between 1 and 20")]
    DownloadBounds,

    /// Some error occurred while trying to wrap the parameter data in an
    /// owned object, which is required for authentication on the server.
    /// The wrapped error further described the problem.
    #[error("")]
    Owned(#[from] DataError),
}

#[derive(Error, Debug)]
pub enum PrepareError {
    /// Failed authenticating, needed to change the parameters.
    #[error("failed to authenticate")]
    Auth(#[from] NonceError),

    /// An error occurred while building the parameter data that will be send
    /// to the server.
    #[error("invalid parameters")]
    ParamsData(#[from] ParamsDataError),
}

impl From<DataError> for PrepareError {
    fn from(err: DataError) -> PrepareError {
        PrepareError::ParamsData(ParamsDataError::Owned(err))
    }
}

#[derive(Error, Debug)]
pub enum ChangeError {
    /// Sending the request to change the parameters failed.
    #[error("failed to send parameter change request")]
    Request,

    /// The server responded with an error while changing the file parameters.
    #[error("bad response from server while changing parameters")]
    Response(#[from] ResponseError),
}
