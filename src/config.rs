use reqwest::StatusCode;

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

/// The maximum upload size in bytes.
pub const UPLOAD_SIZE_MAX: u64 = 1024 * 1024 * 1024 * 2;

/// The ECE record size that is used (`>= Send v2`).
pub const ECE_RECORD_SIZE: u32 = 1024 * 64;
