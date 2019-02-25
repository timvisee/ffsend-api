use mime_guess::Mime;
use serde_json;

use crate::crypto::b64;

/// The MIME type string for a tar file.
const MIME_TAR: &str = "application/x-tar";

/// File metadata, which is send to the server.
#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Metadata {
    /// Metadata using in Send v1.
    V1 {
        /// The file name.
        name: String,

        /// The input vector.
        iv: String,

        /// The file mimetype.
        /// TODO: can we use the `Mime` type here?
        #[serde(rename = "type")]
        mime: String,
    },

    /// Metadata using in Send v2.
    V2 {
        /// The file name.
        name: String,

        /// The file mimetype.
        /// TODO: can we use the `Mime` type here?
        #[serde(rename = "type")]
        mime: String,

        /// The file size.
        size: u64,

        /// The share manifest.
        manifest: Manifest,
    },
}

impl Metadata {
    /// Construct metadata from the given properties.
    ///
    /// Parameters:
    /// * `iv`: initialisation vector
    /// * `name`: file name
    /// * `mime`: file mimetype
    pub fn from_send1(iv: &[u8], name: String, mime: &Mime) -> Self {
        Metadata::V1 {
            iv: b64::encode(iv),
            name,
            mime: mime.to_string(),
        }
    }

    /// Construct metadata from the given properties.
    ///
    /// Parameters:
    /// * `name`: file name
    /// * `mime`: file mimetype
    /// * `size`: file size
    pub fn from_send2(name: String, mime: String, size: u64) -> Self {
        Metadata::V2 {
            name: name.clone(),
            mime: mime.clone(),
            size,
            manifest: Manifest::from_file(name, mime, size),
        }
    }

    /// Convert this structure to a JSON string.
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    /// Get the file name.
    pub fn name(&self) -> &str {
        match self {
            Metadata::V1 { name, iv: _, mime: _ } => &name,
            Metadata::V2 { name, mime: _, size: _, manifest: _ } => &name,
        }
    }

    /// Get the file MIME type.
    pub fn mime(&self) -> &str {
        match self {
            Metadata::V1 { name: _, iv: _, mime } => &mime,
            Metadata::V2 { name: _, mime, size: _, manifest: _ } => &mime,
        }
    }

    /// Get the input vector if set (`< Send v2`).
    // TODO: use an input vector length from a constant
    pub fn iv(&self) -> [u8; 12] {
        // TODO: do not panic here
        let iv = match self {
            Metadata::V1 { name: _, iv, mime: _ } => iv,
            Metadata::V2 { name: _, mime: _, size: _, manifest: _ } => panic!("no iv, send v2 data"),
        };

        // Decode the input vector
        let decoded = b64::decode(iv).unwrap();

        // Create a sized array
        *array_ref!(decoded, 0, 12)
    }

    /// Get the file size if set (`>= Send v2`).
    pub fn size(&self) -> Option<u64> {
        match self {
            Metadata::V1 { name: _, iv: _, mime: _ } => None,
            Metadata::V2 { name: _, mime: _, size, manifest: _ } => Some(*size),
        }
    }

    /**
     * Check whether this MIME type is recognized as supported archive type.
     * `true` is returned if it's an archive, `false` if not.
     */
    pub fn is_archive(&self) -> bool {
        self.mime().to_lowercase() == MIME_TAR.to_lowercase()
    }
}

/// Metadata manifest, used in Send v2.
#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    /// Files part of a share.
    files: Vec<ManifestFile>,
}

impl Manifest {
    /// Construct a new manifest for the given list of files.
    pub fn from(files: Vec<ManifestFile>) -> Self {
        Self {
            files,
        }
    }

    /// Construct a manifest for a single file, with the given properties.
    pub fn from_file(name: String, mime: String, size: u64) -> Self {
        Self::from(vec![ManifestFile::from(name, mime, size)])
    }
}

/// Metadata manifest file, used in Send v2.
#[derive(Debug, Serialize, Deserialize)]
pub struct ManifestFile {
    /// The file name.
    name: String,

    /// The file mimetype.
    /// TODO: can we use the `Mime` type here?
    #[serde(rename = "type")]
    mime: String,

    /// The file size.
    size: u64,
}

impl ManifestFile {
    /// Construct a new manifest file.
    pub fn from(name: String, mime: String, size: u64) -> Self {
        ManifestFile {
            name,
            mime,
            size,
        }
    }
}
