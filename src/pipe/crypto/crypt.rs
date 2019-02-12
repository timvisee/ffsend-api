use openssl::symm::Mode as OpenSslMode;

use crate::pipe::Pipe;

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

/// Pipe specialisation trait for cryptographic pipes.
pub trait Crypt: Pipe {
    /// Encrypt/decrypt bytes from `input`, return the result.
    ///
    /// Read bytes from the given input buffer, transform it using the configured cryptography and
    /// return transformed data when available.
    ///
    /// This returns a tuple with the number of bytes read from the `input`, along with transformed
    /// data if available in the following format: `(read_bytes, transformed_data)`.
    #[inline(always)]
    fn crypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        self.pipe(input)
    }
}
