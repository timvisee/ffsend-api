use thiserror::Error;
use url::Url;

use crate::api;
use crate::api::request::ensure_success;
use crate::client::Client;
#[cfg(feature = "send3")]
use crate::config;

/// The Firefox Send version data endpoint.
const VERSION_ENDPOINT: &str = "__version__";

/// The endpoint we can probe to determine if the server is running Firefox Send v2.
#[cfg(feature = "send2")]
const V2_PROBE_ENDPOINT: &str = "jsconfig.js";

/// The endpoint we can probe to determine if the server is running Firefox Send v3.
#[cfg(feature = "send3")]
const V3_PROBE_ENDPOINT: &str = "app.webmanifest";

/// An action to attempt to find the API version of a Send server.
///
/// This returns a `Version` as probed, and will return an error if failed to properly determine
/// the server API version.
///
/// This API specification for this action is compatible with both Firefox Send v2 and v3.
pub struct Version {
    /// The server host.
    host: Url,
}

impl Version {
    /// Construct a new version action.
    pub fn new(host: Url) -> Self {
        Self { host }
    }

    /// Invoke the version action.
    pub fn invoke(self, client: &Client) -> Result<api::Version, Error> {
        // Attempt to fetch the version from the version endpoint
        let mut result = self.fetch_version(client);

        // Probe some server URLs to determine the API version if still unknown
        if let Err(Error::Unknown) = result {
            result = self.probe(client);
        }

        result
    }

    /// Fetch the version from the endpoint defined as `VERSION_ENDPOINT`.
    ///
    /// The internal request might fail, or the response provided by the server might hold an
    /// unsupported version. In these situations a corresponding `Error` is returned.
    ///
    /// This method does not work for development versions of Firefox Send, as the version
    /// configuration is not included with it.
    /// For those instances, use the `probe` method instead.
    fn fetch_version(&self, client: &Client) -> Result<api::Version, Error> {
        // Build the version URL, request the version
        let version_url = self.host.join(VERSION_ENDPOINT).expect("invalid host");
        let response = client.get(version_url).send().map_err(|_| Error::Request)?;

        // Endpoint is removed since ~2020-07, assume V3
        #[cfg(feature = "send3")]
        {
            if response.status() == config::HTTP_STATUS_EXPIRED {
                return Ok(api::Version::V3);
            }
        }

        // Ensure the status code is successful
        match ensure_success(&response) {
            Ok(_) => {}
            Err(_) => return Err(Error::Unknown),
        }

        // Parse the response and attempt to determine the version number
        let response = response
            .json::<VersionResponse>()
            .map_err(|_| Error::Unknown)?;
        response.determine_version()
    }

    /// Attempt to determine the server version by probing some known URLs.
    ///
    /// This method is not super reliable, but good enough for guessing the server version.
    /// `Error::Unknown` will be returned if the version could not be probed.
    ///
    /// Internally, this method will make some requests which might fail.
    /// These are cached and not immediately returned.
    ///
    /// # Panics
    ///
    /// This method panics if the host was invalid.
    fn probe(&self, client: &Client) -> Result<api::Version, Error> {
        // Probe Firefox Send v3
        #[cfg(feature = "send3")]
        {
            if self.exists(client, V3_PROBE_ENDPOINT) {
                return Ok(api::Version::V3);
            }
        }

        // Probe Firefox Send v2
        #[cfg(feature = "send2")]
        {
            if self.exists(client, V2_PROBE_ENDPOINT) {
                return Ok(api::Version::V2);
            }
        }

        // Unknown or unsupported version
        Err(Error::Unknown)
    }

    /// Check if a host endpoint exists.
    ///
    /// A GET request to the URL will be made, if the server responds with success or with a
    /// redirection (see [`StatusCode::is_success`](StatusCode::is_success) and
    /// [`StatusCode::is_redirection`](StatusCode::is_redirection)) true is returned,
    /// false otherwise.
    ///
    /// # Panics
    ///
    /// This method panics if the host was invalid.
    fn exists(&self, client: &Client, endpoint: &str) -> bool {
        let url = self.host.join(endpoint).expect("invalid host");
        client
            .get(url)
            .send()
            .map(|r| r.status())
            .map(|s| s.is_success() || s.is_redirection())
            .unwrap_or(false)
    }
}

/// The version response.
///
/// The server responds with this JSON object when accessing `/__version__`.
/// Unused fields are omitted.
#[derive(Debug, Deserialize)]
pub struct VersionResponse {
    /// The version string.
    version: String,
}

impl VersionResponse {
    /// Attempt to determine the API version for this response.
    ///
    /// If the API version is unsupported (or not compiled due to a missing compiler feature) an
    /// `Error::Unsupported` is returned holding the version number string.
    pub fn determine_version<'a>(&'a self) -> Result<api::Version, Error> {
        api::Version::parse(&self.version).map_err(|v| Error::Unsupported(v.into()))
    }
}

#[derive(Error, Debug)]
pub enum Error {
    /// Sending the request to check whether the file exists failed.
    #[error("failed to send request to fetch server version")]
    Request,

    /// The server was not able to respond with any version identifiable information, the server
    /// version is unknown.
    #[error("failed to determine server version")]
    Unknown,

    /// The server responded with the given version string that is currently not supported and is
    /// unknown.
    /// This might be the result of a missing compiler feature for a given Firefox Send version.
    #[error("failed to determine server version, unsupported version")]
    Unsupported(String),
}
