use url::Url;

use super::hkdf::{derive_auth_key, derive_file_key, derive_meta_key};
use super::{b64, rand_bytes};
use crate::api::url::UrlBuilder;
use crate::file::remote_file::RemoteFile;

/// The length of an input vector.
const KEY_NONCE_LEN: usize = 12;

pub struct KeySet {
    /// A secret.
    secret: Vec<u8>,

    /// Nonce.
    nonce: [u8; KEY_NONCE_LEN],

    /// A derived file encryption key.
    file_key: Option<Vec<u8>>,

    /// A derived authentication key.
    auth_key: Option<Vec<u8>>,

    /// A derived metadata key.
    meta_key: Option<Vec<u8>>,
}

impl KeySet {
    /// Construct a new key, with the given `secret` and `nonce`.
    pub fn new(secret: Vec<u8>, nonce: [u8; 12]) -> Self {
        Self {
            secret,
            nonce,
            file_key: None,
            auth_key: None,
            meta_key: None,
        }
    }

    /// Create a key set from the given file ID and secret.
    /// This method may be used to create a key set based on a share URL.
    // TODO: add a parameter for the password and URL
    // TODO: return a result?
    // TODO: supply a client instance as parameter
    pub fn from(file: &RemoteFile, password: Option<&String>) -> Self {
        // Create a new key set instance
        let mut set = Self::new(file.secret_raw().clone(), [0; 12]);

        // Derive all keys
        set.derive();

        // Derive a pasworded key
        if let Some(password) = password {
            set.derive_auth_password(password, &UrlBuilder::download(&file, true));
        }

        set
    }

    /// Generate a secure new key.
    ///
    /// If `derive` is `true`, file, authentication and metadata keys will be
    /// derived from the generated secret.
    pub fn generate(derive: bool) -> Self {
        // Allocate two keys
        let mut secret = vec![0u8; 16];
        let mut iv = [0u8; 12];

        // Generate the secrets
        rand_bytes(&mut secret).expect("failed to generate crypto secure random secret");
        rand_bytes(&mut iv).expect("failed to generate crypto secure random input vector");

        // Create the key
        let mut key = Self::new(secret, iv);

        // Derive
        if derive {
            key.derive();
        }

        key
    }

    /// Derive a file, authentication and metadata key.
    // TODO: add support for deriving with a password and URL
    pub fn derive(&mut self) {
        self.file_key = Some(derive_file_key(&self.secret));
        self.auth_key = Some(derive_auth_key(&self.secret, None, None));
        self.meta_key = Some(derive_meta_key(&self.secret));
    }

    /// Derive an authentication key, with the given password and file URL.
    /// This method does not derive a (new) file and metadata key.
    pub fn derive_auth_password(&mut self, pass: &str, url: &Url) {
        self.auth_key = Some(derive_auth_key(&self.secret, Some(pass), Some(url)));
    }

    /// Get the secret key.
    pub fn secret(&self) -> &[u8] {
        &self.secret
    }

    /// Get the secret key as URL-safe base64 encoded string.
    pub fn secret_encoded(&self) -> String {
        b64::encode(self.secret())
    }

    /// Get the nonce.
    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    /// Set the input vector.
    pub fn set_nonce(&mut self, nonce: [u8; KEY_NONCE_LEN]) {
        self.nonce = nonce;
    }

    /// Get the file encryption key, if derived.
    pub fn file_key(&self) -> Option<&Vec<u8>> {
        self.file_key.as_ref()
    }

    /// Get the authentication encryption key, if derived.
    pub fn auth_key(&self) -> Option<&Vec<u8>> {
        self.auth_key.as_ref()
    }

    /// Get the authentication encryption key, if derived,
    /// as URL-safe base64 encoded string.
    pub fn auth_key_encoded(&self) -> Option<String> {
        self.auth_key().map(|key| b64::encode(key))
    }

    /// Get the metadata encryption key, if derived.
    pub fn meta_key(&self) -> Option<&Vec<u8>> {
        self.meta_key.as_ref()
    }
}
