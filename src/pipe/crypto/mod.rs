//! Provides pipes specific to cryptography.

#[cfg(feature = "crypto-openssl")]
use openssl::symm::Mode as OpenSslMode;

#[cfg(feature = "send3")]
pub mod ece;
#[cfg(feature = "send2")]
pub mod gcm;
mod traits;

// Re-export modules
#[cfg(feature = "send3")]
pub use self::ece::{EceCrypt, EceReader, EceWriter};
#[cfg(feature = "send2")]
pub use gcm::{GcmCrypt, GcmReader, GcmWriter};
pub use traits::Crypt;

/// Prelude for common crypto pipe traits.
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

#[cfg(feature = "crypto-openssl")]
impl Into<OpenSslMode> for CryptMode {
    fn into(self) -> OpenSslMode {
        match self {
            CryptMode::Encrypt => OpenSslMode::Encrypt,
            CryptMode::Decrypt => OpenSslMode::Decrypt,
        }
    }
}
