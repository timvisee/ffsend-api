// TODO: remove this when publishing
#![allow(unused)]

use std::cmp;
use std::io::{self, BufRead, BufReader, Cursor, Error as IoError, Read, Write};

use bytes::{BufMut, BytesMut};
use ece::Aes128GcmEceWebPush;

/// The cryptographic mode for a crypter: encrypt or decrypt.
pub enum CryptMode {
    /// Encrypt data while transforming.
    Encrypt,

    /// Decrypt data while transforming.
    Decrypt,
}

/// Something that can encrypt or decrypt given data.
pub trait Crypt: Sized {
    /// The wrapping reader type used for this cryptographic type.
    type Reader: CryptRead<Self>;

    /// The wrapping writer type used for this cryptographic type.
    type Writer: CryptWrite<Self>;

    /// Wrap the `inner` reader, bytes that are read are transformed with this cryptographic configuration.
    fn reader(self, inner: Box<dyn Read>) -> Self::Reader {
        Self::Reader::new(self, inner)
    }

    /// Wrap the `inner` writer, bytes that are read are transformed with this cryptographic configuration.
    fn writer(self, inner: Box<dyn Write>) -> Self::Writer {
        Self::Writer::new(self, inner)
    }

    /// Read bytes from the given input buffer, transform it using the configured cryptography and
    /// return transformed data when available.
    ///
    /// This returns a tuple with the number of bytes read from the `input`, along with transformed
    /// data if available in the following format: `(read_bytes, transformed_data)`.
    fn crypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>);
}

/// A reader wrapping another reader, to encrypt or decrypt data read from it.
pub trait CryptRead<C>: Read
    where C: Crypt,
{
    /// Wrap the given `inner` reader, transform data using `crypt`.
    fn new(crypt: C, inner: Box<dyn Read>) -> Self;
}

/// A writer wrapping another writher, to encrypt or decrypt data it is writen to.
pub trait CryptWrite<C>: Write
    where C: Crypt,
{
    /// Wrap the given `inner` writer, transform data using `crypt`.
    fn new(crypt: C, inner: Box<dyn Write>) -> Self;
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

impl CryptRead<EceCrypt> for EceReader {
    fn new(crypt: EceCrypt, inner: Box<dyn Read>) -> Self {
        Self {
            crypt,
            inner,
            // TODO: use proper buffer size
            buf_in: BytesMut::new(),
            buf_out: BytesMut::new(),
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
            let write = cmp::min(self.buf_out.len(), buf.len());
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
            let write = cmp::min(out.len(), buf.len());
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

impl CryptWrite<EceCrypt> for EceWriter {
    fn new(crypt: EceCrypt, inner: Box<dyn Write>) -> Self {
        Self {
            crypt,
            inner,
            // TODO: use proper buffer size
            buf: BytesMut::new(),
        }
    }
}

impl Write for EceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // TODO: implement reader
        panic!("not yet implemented");
    }

    fn flush(&mut self) -> io::Result<()> {
        // TODO: implement this, flush as much as possible from buffer
        self.inner.flush()
    }
}

/// Something that can encrypt or decrypt given data using ECE.
pub struct EceCrypt {
    mode: CryptMode,
    seq: usize,

    // TODO: remove this buffer, not needed anymore?
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

impl Crypt for EceCrypt {
    type Reader = EceReader;
    type Writer = EceWriter;

    fn crypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // How much to read, based on capacity that is left and given bytes
        let size = cmp::min(self.buf.capacity() - self.buf.len(), input.len());

        // Read bytes into the buffer
        self.buf.put(&input[0..size]);

        // TODO: encrypt/decrypt bytes, produce the result
        panic!("not yet implemented");
    }
}







// /// The writer trait implementation.
// impl Write for EceEncrypter {
//     fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
//         // Do not write anything if the tag was already written
//         if self.verified() || self.has_tag() {
//             return Ok(0);
//         }

//         // Determine how many file and tag bytes we still need to process
//         let file_bytes = max(self.len - TAG_LEN - self.cur, 0);
//         let tag_bytes = TAG_LEN - self.tag_buf.len();

//         // Split the input buffer
//         let (file_buf, tag_buf) = buf.split_at(min(file_bytes, buf.len()));

//         // Read from the file buf
//         if !file_buf.is_empty() {
//             // Create a decrypted buffer, with the proper size
//             let block_size = self.cipher.block_size();
//             let mut decrypted = vec![0u8; file_bytes + block_size];

//             // Decrypt bytes
//             // TODO: catch error in below statement
//             let len = self.crypter.update(file_buf, &mut decrypted)?;

//             // Write to the file
//             self.file.write_all(&decrypted[..len])?;
//         }

//         // Read from the tag part to fill the tag buffer
//         if !tag_buf.is_empty() {
//             self.tag_buf.extend(tag_buf.iter().take(tag_bytes));
//         }

//         // Verify the tag once it has been buffered completely
//         if self.has_tag() {
//             // Set the tag
//             self.crypter.set_tag(&self.tag_buf)?;

//             // Create a buffer for any remaining data
//             let block_size = self.cipher.block_size();
//             let mut extra = vec![0u8; block_size];

//             // Finalize, write all remaining data
//             let len = self.crypter.finalize(&mut extra)?;
//             self.file.write_all(&extra[..len])?;

//             // Set the verified flag
//             self.verified = true;
//         }

//         // Compute how many bytes were written
//         let len = file_buf.len() + min(tag_buf.len(), TAG_LEN);
//         self.cur += len;
//         Ok(len)
//     }

//     fn flush(&mut self) -> Result<(), io::Error> {
//         self.file.flush()
//     }
// }
