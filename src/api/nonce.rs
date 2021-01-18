use reqwest::{
    blocking::Response,
    header::{HeaderName, WWW_AUTHENTICATE},
};
use thiserror::Error;
use url::Url;

use crate::api::request::{ensure_success, ResponseError};
use crate::client::Client;
use crate::crypto::b64;

/// The name of the header the nonce is delivered in.
const HEADER_NONCE: HeaderName = WWW_AUTHENTICATE;

/// Do a new request, and extract the nonce from a header in the given
/// response.
pub fn request_nonce(client: &Client, url: Url) -> Result<Vec<u8>, NonceError> {
    // Make the request
    let response = client.get(url).send().map_err(|_| NonceError::Request)?;

    // Ensure the response is successful
    ensure_success(&response)?;

    // Extract the nonce
    header_nonce(&response)
}

/// Extract the nonce from a header in the given response.
pub fn header_nonce(response: &Response) -> Result<Vec<u8>, NonceError> {
    // Get the authentication nonce
    b64::decode(
        response
            .headers()
            .get(HEADER_NONCE)
            .ok_or(NonceError::NoNonceHeader)?
            .to_str()
            .map_err(|_| NonceError::MalformedNonce)?
            .split_terminator(' ')
            .nth(1)
            .ok_or(NonceError::MalformedNonce)?,
    )
    .map_err(|_| NonceError::MalformedNonce)
}

#[derive(Error, Debug)]
pub enum NonceError {
    /// Sending the request to fetch a nonce failed,
    /// as the file has expired or did never exist.
    #[error("the file has expired or did never exist")]
    Expired,

    /// Sending the request to fetch a nonce failed.
    #[error("failed to request encryption nonce")]
    Request,

    /// The server responded with an error while requesting the encryption nonce,
    /// required for some operations.
    #[error("bad response from server while requesting encryption nonce")]
    Response(#[from] ResponseError),

    /// The nonce header was missing from the request.
    #[error("missing nonce in server response")]
    NoNonceHeader,

    /// The received nonce could not be parsed, because it was malformed.
    /// Maybe the server responded with a new format that isn't supported yet
    /// by this client.
    #[error("received malformed nonce")]
    MalformedNonce,
}
