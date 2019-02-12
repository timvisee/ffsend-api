//! Provides pipes specific to cryptography.

use openssl::symm::Mode as OpenSslMode;

mod ece;
mod gcm;
mod traits;

// Re-export modules
pub use self::ece::{EceCrypt, EceReader, EceWriter};
pub use gcm::{GcmCrypt, GcmReader, GcmWriter};
pub use traits::Crypt;

// Re-export common traits for prelude
pub mod prelude {
    pub use super::Crypt;
}

/// The cryptographic mode for a crypter: encrypt or decrypt.
#[derive(Debug, Clone, Copy)]
pub enum CryptMode {
    /// Encrypt data while transforming.
    Encrypt,

    /// Decrypt data while transforming.
    Decrypt,
}

impl Into<OpenSslMode> for CryptMode {
    fn into(self) -> OpenSslMode {
        match self {
            CryptMode::Encrypt => OpenSslMode::Encrypt,
            CryptMode::Decrypt => OpenSslMode::Decrypt,
        }
    }
}
