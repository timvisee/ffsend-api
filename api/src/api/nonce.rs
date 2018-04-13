use url::Url;
use reqwest::{Client, Response};

use api::request::{ensure_success, ResponseError};
use crypto::b64;

/// The name of the header the nonce is delivered in.
const HEADER_NONCE: &'static str = "WWW-Authenticate";

/// Do a new request, and extract the nonce from a header in the given
/// response.
pub fn request_nonce(client: &Client, url: Url)
    -> Result<Vec<u8>, NonceError>
{
    // Make the request
    let response = client.get(url)
        .send()
        .map_err(|_| NonceError::Request)?;

    // Ensure the response is successful
    ensure_success(&response)
        .map_err(|err| NonceError::Response(err))?;

    // Extract the nonce
    header_nonce(&response)
}

/// Extract the nonce from a header in the given response.
pub fn header_nonce(response: &Response)
    -> Result<Vec<u8>, NonceError>
{
    // Get the authentication nonce
    b64::decode(
        response.headers()
            .get_raw(HEADER_NONCE)
            .ok_or(NonceError::NoNonceHeader)?
            .one()
            .ok_or(NonceError::MalformedNonce)
            .and_then(|line| String::from_utf8(line.to_vec())
                .map_err(|_| NonceError::MalformedNonce)
            )?
            .split_terminator(" ")
            .skip(1)
            .next()
            .ok_or(NonceError::MalformedNonce)?
    ).map_err(|_| NonceError::MalformedNonce.into())
}

#[derive(Fail, Debug)]
pub enum NonceError {
    /// Sending the request to fetch a nonce failed.
    #[fail(display = "Failed to request encryption nonce")]
    Request,

    /// The server responded with an error while requesting the encryption nonce,
    /// required for some operations.
    #[fail(display = "Bad response from server while requesting encryption nonce")]
    Response(#[cause] ResponseError),

    /// The nonce header was missing from the request.
    #[fail(display = "Missing nonce in server response")]
    NoNonceHeader,

    /// The received nonce could not be parsed, because it was malformed.
    /// Maybe the server responded with a new format that isn't supported yet
    /// by this client.
    #[fail(display = "Received malformed nonce")]
    MalformedNonce,
}
