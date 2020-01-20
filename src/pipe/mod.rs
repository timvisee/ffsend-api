//! Provides IO stream pipe functionality.
//!
//! This module provides piping functionality for IO streams implementing `Read` or `Write`.
//! A pipe can be used to wrap an existing reader or writer, monitoring or transforming data read
//! from or written to it.
//!
//! You may use a pipe for archiving (zipping) or to encrypt/decrypt bytes flowing through the
//! pipe reader or writer.

use bytes::BytesMut;
use std::cmp::min;
use std::io::{self, Read, Write};

pub mod crypto;
pub mod progress;
mod traits;

// Re-export modules
pub use progress::{ProgressPipe, ProgressReader, ProgressReporter, ProgressWriter};
pub use traits::{Pipe, PipeLen, PipeRead, PipeWrite, ReadLen, WriteLen};

/// Prelude for common pipe traits.
pub mod prelude {
    pub use super::{crypto::prelude::*, Pipe, PipeLen, PipeRead, PipeWrite, ReadLen, WriteLen};
}

/// The default size of byte buffers.
const DEFAULT_BUF_SIZE: usize = 8 * 1024;

/// A simple generic reader implementation for a pipe.
///
/// This type may be used as simple reader implementation for any pipe.
/// For better performance it is better to implement a custom reader in some situations.
///
/// It is recommended to expose a custom reader type definition for each of your pipes like this:
///
/// ```ignore
/// pub type MyReader = PipeReader<MyPipe>;
/// ```
pub struct PipeReader<P>
where
    P: Pipe,
{
    pipe: P,
    inner: Box<dyn Read>,
    buf: BytesMut,
}

/// A simple generic writer implementation for a pipe.
///
/// This type may be used as simple writer implementation for any pipe.
/// For better performance it is better to implement a custom writer in some situations.
///
/// It is recommended to expose a custom writer type definition for each of your pipes like this:
///
/// ```ignore
/// pub type MyWriter = PipeWriter<MyPipe>;
/// ```
pub struct PipeWriter<P>
where
    P: Pipe,
{
    pipe: P,
    inner: Box<dyn Write>,
}

impl<P> PipeRead<P> for PipeReader<P>
where
    P: Pipe,
{
    fn new(pipe: P, inner: Box<dyn Read>) -> Self {
        Self {
            pipe,
            inner,
            buf: BytesMut::with_capacity(DEFAULT_BUF_SIZE),
        }
    }
}

impl<P> PipeWrite<P> for PipeWriter<P>
where
    P: Pipe,
{
    fn new(pipe: P, inner: Box<dyn Write>) -> Self {
        Self { pipe, inner }
    }
}

impl<P> Read for PipeReader<P>
where
    P: Pipe,
{
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        // Attempt to fill input buffer if has capacity upto default buffer size and output length
        let capacity = min(DEFAULT_BUF_SIZE, buf.len()) - self.buf.len();
        if capacity > 0 {
            // Read from inner to input buffer
            let mut inner_buf = vec![0u8; capacity];
            let read = self.inner.read(&mut inner_buf)?;
            self.buf.extend_from_slice(&inner_buf[..read]);

            // If nothing is read, return the same
            if read == 0 {
                return Ok(0);
            }
        }

        // Move input buffer into the pipe
        let (read, out) = self.pipe.pipe(&self.buf);
        let _ = self.buf.split_to(read);

        // Number of bytes written to given buffer
        let mut total = 0;

        // Write any pipe output to given buffer and remaining to output buffer
        if let Some(out) = out {
            // Copy as much data as possible from pipe output to read buffer
            let write = min(out.len(), buf.len());
            total += write;
            buf[..write].copy_from_slice(&out[..write]);

            // Assert there are no unwritten output bytes
            assert_eq!(
                write,
                out.len(),
                "failed to write all pipe output bytes to output buffer"
            );

            // Return if given buffer is full, or slice to unwritten buffer
            if write == buf.len() {
                return Ok(total);
            }
            buf = &mut buf[write..];
        }

        // Try again with remaining given buffer
        self.read(buf).map(|n| n + total)
    }
}

impl<P> Write for PipeWriter<P>
where
    P: Pipe,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Transform input data through crypter, write result to inner writer
        let (read, data) = self.pipe.pipe(buf);
        if let Some(data) = data {
            self.inner.write_all(&data)?;
        }

        Ok(read)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
