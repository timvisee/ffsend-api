//! Cryptographic pipe traits.

use crate::pipe::Pipe;

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
