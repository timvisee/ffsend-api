//! Pipe traits.

use std::io::{Read, Write};

/// Something that can pipe given data.
///
/// A pipe may monitor, but also transform data flowing through it.
///
/// From this pipe, a reader or writer can be created using the corresponding `reader` and `writer`
/// functions to wrap an existing reader or writer.
pub trait Pipe: Sized {
    /// The wrapping reader type used for this pipe.
    type Reader: PipeRead<Self>;

    /// The wrapping writer type used for this pipe.
    type Writer: PipeWrite<Self>;

    /// Wrap the `inner` reader, bytes that are read are transformed through this pipe.
    fn reader(self, inner: Box<dyn Read>) -> Self::Reader {
        Self::Reader::new(self, inner)
    }

    /// Wrap the `inner` writer, bytes that are read are transformed through this pipe.
    fn writer(self, inner: Box<dyn Write>) -> Self::Writer {
        Self::Writer::new(self, inner)
    }

    /// Pipe bytes from `input`, monitor/transform it, return the output.
    ///
    /// This should not be used directly, and is automatically used by a `PipeRead` or `PipeWrite`
    /// object for the actual piping.
    ///
    /// This returns a tuple with the number of bytes read from the `input`, along with transformed
    /// data if available in the following format: `(read_bytes, transformed_data)`.
    ///
    /// Pipes that just monitor data, immediately return the input.
    /// The `pipe_transparent` helper function can be used for this inside the implementation.
    fn pipe(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>);

    /// Transparently pipe `input` by immediately returning it.
    ///
    /// This should not be used directly, and is automatically used by a `PipeRead` or `PipeWrite`
    /// object for the actual piping.
    ///
    /// This can be used as helper function inside the `pipe` function if data is only monitored
    /// and not transformed.
    #[inline(always)]
    fn pipe_transparent(&self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        (input.len(), Some(input.to_vec()))
    }
}

/// A reader wrapping another reader, to encrypt or decrypt data read from it.
pub trait PipeRead<P>: Read
where
    P: Pipe,
{
    /// Wrap the given `inner` reader, transform data using `crypt`.
    fn new(pipe: P, inner: Box<dyn Read>) -> Self;
}

/// A writer wrapping another writher, to encrypt or decrypt data it is writen to.
pub trait PipeWrite<P>: Write
where
    P: Pipe,
{
    /// Wrap the given `inner` writer, transform data using `crypt`.
    fn new(pipe: P, inner: Box<dyn Write>) -> Self;
}

/// Defines number of bytes transformed into/out of pipe if fixed.
///
/// For example, the AES-GCM cryptography pipe adds 16 bytes to the encrypted payload for the
/// verification tag. When transforming a file the length is known.
/// Then, the `len_out` for an AES-GCM encrypter is 16 bytes larger than `len_in`.
/// For a decrypter this is the other way around.
pub trait PipeLen {
    /// The number of bytes that are transfered into the pipe if fixed.
    fn len_in(&self) -> usize;

    /// The number of bytes that are transfered out of the pipe if fixed.
    fn len_out(&self) -> usize;
}

pub trait ReadLen: Read + PipeLen + Send {}
pub trait WriteLen: Write + PipeLen + Send {}

// TODO: use automatic implementation for crypt reader and writer wrapping crypt having pipelen
// impl<R, C> PipeLen for R
//     where R: CryptRead<C>,
//           C: Crypt + PipeLen,
// {
//     fn len_in(&self) -> usize {
//         self.crypt.len_in()
//     }
//
//     fn len_out(&self) -> usize {
//         self.crypt.len_out()
//     }
// }
