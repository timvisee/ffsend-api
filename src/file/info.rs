use serde_json;

use crate::config;
use crate::crypto::key_set::KeySet;

/// File information, sent to the server before uploading.
///
/// This is used for Firefox Send v3.
#[derive(Debug, Serialize, Deserialize)]
pub struct FileInfo {
    /// The expirey time in seconds.
    ///
    /// Must be in any of these bounds:
    /// - Not authenticated: `[0, 86400]`
    /// - Authenticated: `[0, 86400 * 7]`
    #[serde(rename = "timeLimit")]
    expire: usize,

    /// The download limit.
    ///
    /// Must be in any of these bounds:
    /// - Not authenticated: `[0, 20]`
    /// - Authenticated: `[0, 200]`
    #[serde(rename = "dlimit")]
    download_limit: Option<u8>,

    /// File metadata.
    #[serde(rename = "fileMetadata")]
    metadata: String,

    /// File authorization.
    // TODO: what is this?
    #[serde(rename = "authorization")]
    auth: String,

    /// Firefox Account user authentication information.
    // TODO: what is this?
    #[serde(rename = "bearer")]
    _firefox_user: Option<String>,
}

impl FileInfo {
    /// Constructor.
    ///
    /// Parameters:
    /// * `expire`: optional file expiry time in seconds.
    /// * `download_limit`: optional download limit.
    /// * `metadata`: encrypted and base64 encoded file metadata
    /// * `auth`: authorization data
    pub fn from(
        expire: Option<usize>,
        download_limit: Option<u8>,
        metadata: String,
        key_set: &KeySet,
    ) -> Self {
        Self {
            expire: expire.unwrap_or(config::SEND_DEFAULT_EXPIRE_TIME),
            download_limit,
            metadata,
            auth: format!("send-v1 {}", key_set.auth_key_encoded().unwrap()),
            _firefox_user: None,
        }
    }

    /// Convert this structure to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }
}
