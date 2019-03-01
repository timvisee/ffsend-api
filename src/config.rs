use reqwest::StatusCode;

use crate::api::Version;

/// The Send host to use by default.
pub const SEND_DEFAULT_HOST: &str = "https://send.firefox.com/";

/// The default time after which uploaded files expire after, in seconds.
pub const SEND_DEFAULT_EXPIRE_TIME: usize = 24 * 60 * 60;

/// The HTTP status code that is returned for expired or non existant files.
pub const HTTP_STATUS_EXPIRED: StatusCode = StatusCode::NOT_FOUND;

/// The HTTP status code that is returned on authentication failure.
pub const HTTP_STATUS_UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;

/// The recommended maximum upload size in bytes.
pub const UPLOAD_SIZE_MAX_RECOMMENDED: u64 = 1024 * 1024 * 1024;

/// The maximum upload size in bytes for Firefox Send v2.
#[cfg(feature = "send2")]
const SEND2_UPLOAD_SIZE_MAX: u64 = 1024 * 1024 * 1024 * 2;

/// The maximum upload size in bytes for Firefox Send v3 non-authenticated users.
#[cfg(feature = "send3")]
const SEND3_UPLOAD_SIZE_MAX: u64 = 1024 * 1024 * 512;

/// The maximum upload size in bytes for Firefox Send v3 authenticated users.
#[cfg(feature = "send3")]
const SEND3_UPLOAD_SIZE_MAX_AUTH: u64 = 1024 * 1024 * 1024 * 4;

/// The length of the tag in bytes we're using for cryptography.
pub const TAG_LEN: usize = 16;

/// The ECE record size that is used (`>= Send v2`).
pub const ECE_RECORD_SIZE: u32 = 1024 * 64;

/// Get the maximum file upload size.
pub fn upload_size_max(version: Version, auth: bool) -> u64{
    match version {
        #[cfg(feature = "send2")]
        Version::V2 => SEND2_UPLOAD_SIZE_MAX,
        #[cfg(feature = "send3")]
        Version::V3 => if auth { SEND3_UPLOAD_SIZE_MAX } else { SEND3_UPLOAD_SIZE_MAX_AUTH },
    }
}
