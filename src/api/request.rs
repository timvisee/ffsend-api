use reqwest::{blocking::Response, StatusCode};
use thiserror::Error;

use crate::config::{HTTP_STATUS_EXPIRED, HTTP_STATUS_UNAUTHORIZED};
use crate::ext::status_code::StatusCodeExt;

/// Ensure the given response is successful. If it isn't, a corresponding `ResponseError` is returned.
pub fn ensure_success(response: &Response) -> Result<(), ResponseError> {
    // Get the status
    let status = response.status();

    // Stop if successful
    if status.is_success() {
        return Ok(());
    }

    // Handle the expired file error
    if status == HTTP_STATUS_EXPIRED {
        return Err(ResponseError::Expired);
    }

    // Handle the authentication issue error
    if status == HTTP_STATUS_UNAUTHORIZED {
        return Err(ResponseError::Unauthorized);
    }

    // Return the other error
    Err(ResponseError::OtherHttp(status, status.err_text()))
}

#[derive(Error, Debug)]
pub enum ResponseError {
    /// This request lead to an expired file, or a file that never existed.
    #[error("this file has expired or did never exist")]
    Expired,

    /// We were unauthorized to make this request.
    /// This is usually because of an incorrect password.
    #[error("unauthorized, are the credentials correct?")]
    Unauthorized,

    /// Some undefined error occurred with this response.
    #[error("bad HTTP response: {}", _1)]
    OtherHttp(StatusCode, String),

    /// An undefined error message.
    #[error("server responded with undefined error")]
    Undefined,
}
