use std::io::{self, Read, Write};
use std::cmp::min;

use bytes::{BufMut, BytesMut};
use ece::Aes128GcmEceWebPush;

use crate::pipe::{
    DEFAULT_BUF_SIZE,
    prelude::*,
};
use super::{Crypt, CryptMode};

/// Something that can encrypt or decrypt given data using ECE.
pub struct EceCrypt {
    mode: CryptMode,
    seq: usize,

    // TODO: remove this buffer, obsolete?
    /// Input buffer.
    buf: BytesMut,
}

impl EceCrypt {
    pub fn new(mode: CryptMode, input_size: usize) -> Self {
        Self {
            mode,
            seq: 0,
            buf: BytesMut::with_capacity(input_size),
        }
    }
}

impl Pipe for EceCrypt {
    type Reader = EceReader;
    type Writer = EceWriter;

    fn pipe(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // How much to read, based on capacity that is left and given bytes
        let size = min(self.buf.capacity() - self.buf.len(), input.len());

        // Read bytes into the buffer
        self.buf.put(&input[0..size]);

        // TODO: encrypt/decrypt bytes, produce the result
        panic!("not yet implemented");
    }
}

impl Crypt for EceCrypt {}

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
        Self {
            crypt,
            inner,
            buf_in: BytesMut::with_capacity(DEFAULT_BUF_SIZE),
            buf_out: BytesMut::with_capacity(DEFAULT_BUF_SIZE),
        }
    }
}

impl PipeWrite<EceCrypt> for EceWriter {
    fn new(crypt: EceCrypt, inner: Box<dyn Write>) -> Self {
        Self {
            crypt,
            inner,
            buf: BytesMut::with_capacity(DEFAULT_BUF_SIZE),
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

        // Attempt to fill input buffer if has capacity
        let capacity = self.buf_in.capacity() - self.buf_in.len();
        if capacity > 0 {
            // Read from inner to input buffer
            let mut inner_buf = vec![0u8; capacity];
            let read = self.inner.read(&mut inner_buf)?;
            self.buf_in.put(inner_buf);

            // If not enough input buffer data, we can't crypt, read nothing
            if read < capacity {
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
        // TODO: implement reader
        panic!("not yet implemented");
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
