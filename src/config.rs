use reqwest::StatusCode;

use crate::api::Version;

/// The Send host to use by default.
pub const SEND_DEFAULT_HOST: &str = "https://send.vis.ee/";

/// The default time after which uploaded files expire after, in seconds.
pub const SEND_DEFAULT_EXPIRE_TIME: usize = 24 * 60 * 60;

/// The HTTP status code that is returned for expired or non existant files.
pub const HTTP_STATUS_EXPIRED: StatusCode = StatusCode::NOT_FOUND;

/// The HTTP status code that is returned on authentication failure.
pub const HTTP_STATUS_UNAUTHORIZED: StatusCode = StatusCode::UNAUTHORIZED;

/// The recommended maximum upload size in bytes.
pub const UPLOAD_SIZE_MAX_RECOMMENDED: u64 = ((1024 * 1024 * 1024) as f64 * 2.5f64) as u64;

/// The maximum upload size in bytes for Firefox Send v2.
#[cfg(feature = "send2")]
const SEND2_MAX_UPLOAD_SIZE: u64 = 1024 * 1024 * 1024 * 2;

/// The maximum upload size in bytes for Firefox Send v3 non-authenticated users.
#[cfg(feature = "send3")]
const SEND3_MAX_UPLOAD_SIZE: u64 = ((1024 * 1024 * 1024) as f64 * 2.5f64) as u64;

/// The maximum upload size in bytes for Firefox Send v3 authenticated users.
#[cfg(feature = "send3")]
const SEND3_MAX_UPLOAD_SIZE_AUTH: u64 = SEND3_MAX_UPLOAD_SIZE;

/// Default number of maximum downloads for a Send v2 file.
#[cfg(feature = "send2")]
const SEND2_DEFAULT_DOWNLOADS: usize = 20;

/// Default number of maximum downloads for a Send v3 file.
#[cfg(feature = "send3")]
const SEND3_DEFAULT_DOWNLOADS: usize = 1;

/// Default number of maximum downloads for a Send v3 file when authenticated.
#[cfg(feature = "send3")]
const SEND3_DEFAULT_DOWNLOADS_AUTH: usize = SEND3_DEFAULT_DOWNLOADS;

/// Supported maximum number of download values for a file for Firefox Send v2.
#[cfg(feature = "send2")]
const SEND2_MAX_DOWNLOADS: [usize; 6] = [1, 2, 3, 4, 5, 20];

/// Supported maximum number of download values for Firefox Send v3 non-authenticated users.
#[cfg(feature = "send3")]
const SEND3_MAX_DOWNLOADS: [usize; 6] = [1, 2, 3, 4, 5, 20];

/// Supported maximum number of download values for Firefox Send v3 authenticated users.
#[cfg(feature = "send3")]
const SEND3_MAX_DOWNLOADS_AUTH: [usize; 8] = [1, 2, 3, 4, 5, 20, 50, 100];

/// The default expriy time in seconds for a file.
pub const SEND_EXPIRY_DEFAULT: usize = 86_400;

/// Supported maximum file expiry time values in seconds for a file for Firefox Send v2.
#[cfg(feature = "send2")]
const SEND2_EXPIRY_MAX: [usize; 1] = [86_400];

/// Supported maximum file expiry time values in seconds for a file for Firefox Send v3 non-authenticated users.
// TODO: use single biggest value, can use any expiry time now
#[cfg(feature = "send3")]
const SEND3_EXPIRY_MAX: [usize; 4] = [300, 3600, 86_400, 604_800];

/// Supported maximum file expiry time values in seconds for a file for Firefox Send v3 authenticated users.
#[cfg(feature = "send3")]
const SEND3_EXPIRY_MAX_AUTH: [usize; 4] = SEND3_EXPIRY_MAX;

/// The length of the tag in bytes we're using for cryptography.
pub const TAG_LEN: usize = 16;

/// The ECE record size that is used (`>= Send v2`).
pub const ECE_RECORD_SIZE: u32 = 1024 * 64;

/// Get the maximum file upload size.
pub fn upload_size_max(version: Version, _auth: bool) -> u64 {
    match version {
        #[cfg(feature = "send2")]
        Version::V2 => SEND2_MAX_UPLOAD_SIZE,
        #[cfg(feature = "send3")]
        Version::V3 => {
            if _auth {
                SEND3_MAX_UPLOAD_SIZE_AUTH
            } else {
                SEND3_MAX_UPLOAD_SIZE
            }
        }
    }
}

/// Get supported maximum number of download values for a Send file.
///
/// The remote server only accepts any of these specific values, and nothing in between.
pub fn downloads_default(version: Version, _auth: bool) -> usize {
    match version {
        #[cfg(feature = "send2")]
        Version::V2 => SEND2_DEFAULT_DOWNLOADS,
        #[cfg(feature = "send3")]
        Version::V3 => {
            if _auth {
                SEND3_DEFAULT_DOWNLOADS_AUTH
            } else {
                SEND3_DEFAULT_DOWNLOADS
            }
        }
    }
}

/// Get supported maximum number of download values for a Send file.
///
/// The remote server only accepts any of these specific values, and nothing in between.
pub fn downloads_max(version: Version, _auth: bool) -> &'static [usize] {
    match version {
        #[cfg(feature = "send2")]
        Version::V2 => &SEND2_MAX_DOWNLOADS,
        #[cfg(feature = "send3")]
        Version::V3 => {
            if _auth {
                &SEND3_MAX_DOWNLOADS_AUTH
            } else {
                &SEND3_MAX_DOWNLOADS
            }
        }
    }
}

/// Get supported maximum file expiry time values in seconds for a Send file.
///
/// The remote server only accepts any of these specific values, and nothing in between.
pub fn expiry_max(version: Version, _auth: bool) -> &'static [usize] {
    match version {
        #[cfg(feature = "send2")]
        Version::V2 => &SEND2_EXPIRY_MAX,
        #[cfg(feature = "send3")]
        Version::V3 => {
            if _auth {
                &SEND3_EXPIRY_MAX_AUTH
            } else {
                &SEND3_EXPIRY_MAX
            }
        }
    }
}
