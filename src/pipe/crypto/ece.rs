//! ECE encrypter/decrypter pipe implementation.

use std::io::{self, Read, Write};
use std::cmp::min;

use bytes::{BufMut, BytesMut};
use ece::Aes128GcmEceWebPush;

use crate::pipe::{
    DEFAULT_BUF_SIZE,
    prelude::*,
};
use super::{Crypt, CryptMode};

// TODO: specify this somewhere else
const RS: usize = 1024 * 64;

/// Something that can encrypt or decrypt given data using ECE.
pub struct EceCrypt {
    mode: CryptMode,

    /// Chunk sequence.
    seq: usize,

    /// The total size in bytes of the plain text payload, excluding any encryption overhead.
    len: usize,

    // TODO: remove this buffer, obsolete?
    /// Input buffer.
    buf: BytesMut,
}

impl EceCrypt {
    /// Construct a new ECE crypter pipe.
    pub fn new(mode: CryptMode, len: usize, input_size: usize) -> Self {
        Self {
            mode,
            seq: 0,
            len,
            buf: BytesMut::with_capacity(input_size),
        }
    }

    /// Get the size of the payload chunk.
    ///
    /// Data passed to the crypter must match the chunk size.
    ///
    /// The chunk size might change during encryption/decryption due to prefixed data.
    fn chunk_size(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => RS - 17,
            // TODO: shouldn't this be `21`?
            CryptMode::Decrypt => if self.seq == 0 {
                    21
                } else {
                    RS
                },
        }
    }
}

impl Pipe for EceCrypt {
    type Reader = EceReader;
    type Writer = EceWriter;

    fn pipe(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // Match the chunk size
        assert_eq!(
            input.len(),
            self.chunk_size(),
            "input data passed to ECE cryptor does not match chunk size",
        );

        // How much to read, based on capacity that is left and given bytes
        let size = min(self.buf.capacity() - self.buf.len(), input.len());

        // Read bytes into the buffer
        self.buf.put(&input[0..size]);

        // TODO: encrypt/decrypt bytes, produce the result
        // panic!("not yet implemented");

        dbg!(input.len());

        // Increase the sequence count
        self.seq += 1;

        self.pipe_transparent(input)
    }
}

impl Crypt for EceCrypt {}

impl PipeLen for EceCrypt {
    fn len_in(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => self.len,
            // TODO: implement this!
            CryptMode::Decrypt => panic!("failed to calculate size of ECE decrypted payload"),
        }
    }

    fn len_out(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => 21 + self.len + 16 * (self.len as f64 / (RS as f64 - 17f64)).floor() as usize,
            CryptMode::Decrypt => self.len,
        }
    }
}

pub struct EceReader {
    crypt: EceCrypt,
    inner: Box<dyn Read>,
    buf_in: BytesMut,
    buf_out: BytesMut,
}

pub struct EceWriter {
    crypt: EceCrypt,
    inner: Box<dyn Write>,
    buf: BytesMut,
}

impl PipeRead<EceCrypt> for EceReader {
    fn new(crypt: EceCrypt, inner: Box<dyn Read>) -> Self {
        let chunk_size = crypt.chunk_size();

        Self {
            crypt,
            inner,
            buf_in: BytesMut::with_capacity(chunk_size),
            buf_out: BytesMut::with_capacity(DEFAULT_BUF_SIZE),
        }
    }
}

impl PipeWrite<EceCrypt> for EceWriter {
    fn new(crypt: EceCrypt, inner: Box<dyn Write>) -> Self {
        let chunk_size = crypt.chunk_size();

        Self {
            crypt,
            inner,
            buf: BytesMut::with_capacity(chunk_size),
        }
    }
}

impl Read for EceReader {
    fn read(&mut self, mut buf: &mut [u8]) -> io::Result<usize> {
        // Number of bytes written to given buffer
        let mut total = 0;

        // Write any output buffer bytes first
        if !self.buf_out.is_empty() {
            // Copy as much as possible from inner to output buffer, increase total
            let write = min(self.buf_out.len(), buf.len());
            total += write;
            buf[..write].copy_from_slice(&self.buf_out.split_to(write));

            // Return if given buffer is full, or slice to unwritten buffer
            if total >= buf.len() {
                return Ok(total);
            }
            buf = &mut buf[write..];
        }

        // Attempt to fill input buffer if has capacity upto the chunk size
        let capacity = self.crypt.chunk_size() - self.buf_in.len();
        if capacity > 0 {
            // Read from inner to input buffer
            let mut inner_buf = vec![0u8; capacity];
            let read = self.inner.read(&mut inner_buf)?;
            self.buf_in.extend_from_slice(&inner_buf[..read]);

            // If not enough input buffer data, we can't crypt, read nothing
            // TODO: is this correct? can we return or should we keep trying? use read_exact?
            if read != capacity {
                return Ok(0);
            }
        }

        // Move input buffer into the crypter
        let (read, out) = self.crypt.crypt(&self.buf_in);
        self.buf_in.split_to(read);

        // Write any crypter output to given buffer and remaining to output buffer
        if let Some(out) = out {
            // Copy as much data as possible from crypter output to read buffer
            let write = min(out.len(), buf.len());
            total += write;
            buf[..write].copy_from_slice(&out[..write]);

            // Copy remaining bytes into output buffer
            if write < out.len() {
                self.buf_out.extend_from_slice(&out[write..]);
            }

            // Return if given buffer is full, or slice to unwritten buffer
            if write >= buf.len() {
                return Ok(total);
            }
            buf = &mut buf[write..];
        }

        // Try again with remaining given buffer
        self.read(buf).map(|n| n + total)
    }
}

impl Write for EceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Get the chunk size to use
        let chunk_size = self.crypt.chunk_size();

        // Attempt to fill input buffer if has capacity upto the chunk size
        let capacity = chunk_size - self.buf.len();
        let mut read = min(capacity, buf.len());
        if capacity > 0 {
            self.buf.extend_from_slice(&buf[..read]);
        }

        // Transform input data through crypter if chunk data is available
        if self.buf.len() == chunk_size {
            let (read, data) = self.crypt.crypt(&self.buf.split_off(0));
            assert_eq!(read, chunk_size, "ECE crypto did not transform full chunk");
            if let Some(data) = data {
                self.inner.write_all(&data)?;
            }
        }

        // Rerun if there's data left in the input buffer
        if read < capacity {
            read += self.write(&buf[read..])?;
        }

        Ok(read)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl PipeLen for EceReader {
    fn len_in(&self) -> usize {
        self.crypt.len_in()
    }

    fn len_out(&self) -> usize {
        self.crypt.len_out()
    }
}

impl PipeLen for EceWriter {
    fn len_in(&self) -> usize {
        self.crypt.len_in()
    }

    fn len_out(&self) -> usize {
        self.crypt.len_out()
    }
}
