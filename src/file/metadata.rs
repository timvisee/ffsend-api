extern crate hyper;

use mime_guess::Mime;
use serde_json;

use crate::crypto::b64;

/// The MIME type string for a tar file.
const MIME_TAR: &str = "application/x-tar";

/// File metadata, which is send to the server.
#[derive(Debug, Serialize, Deserialize)]
pub struct Metadata {
    /// The input vector.
    iv: String,

    /// The file name.
    name: String,

    /// The file mimetype.
    #[serde(rename = "type")]
    mime: String,
}

impl Metadata {
    /// Construct metadata from the given properties.
    ///
    /// Parameters:
    /// * iv: initialisation vector
    /// * name: file name
    /// * mime: file mimetype
    pub fn from(iv: &[u8], name: String, mime: &Mime) -> Self {
        Metadata {
            iv: b64::encode(iv),
            name,
            mime: mime.to_string(),
        }
    }

    /// Convert this structure to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    /// Get the file name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the file MIME type.
    pub fn mime(&self) -> &str {
        &self.mime
    }

    /// Get the input vector
    // TODO: use an input vector length from a constant
    pub fn iv(&self) -> [u8; 12] {
        // Decode the input vector
        let decoded = b64::decode(&self.iv).unwrap();

        // Create a sized array
        *array_ref!(decoded, 0, 12)
    }

    /**
     * Check whether this MIME type is recognized as supported archive type.
     * `true` is returned if it's an archive, `false` if not.
     */
    pub fn is_archive(&self) -> bool {
        self.mime.to_lowercase() == MIME_TAR.to_lowercase()
    }
}
