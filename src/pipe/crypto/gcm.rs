//! AES-GCM 128 encrypter/decrypter pipe implementation for Firefox Send v2.

use std::cmp::min;
use std::io::{self, Read, Write};

use bytes::BytesMut;
use openssl::symm::{Cipher as OpenSslCipher, Crypter as OpenSslCrypter};

use super::{Crypt, CryptMode};
use crate::config::TAG_LEN;
use crate::pipe::{prelude::*, DEFAULT_BUF_SIZE};

/// Something that can encrypt or decrypt given data using AES-GCM.
pub struct GcmCrypt {
    /// The crypto mode, make this encrypt or decrypt data.
    mode: CryptMode,

    /// The cipher type used for encryping or decrypting.
    cipher: OpenSslCipher,

    /// The crypter used for encryping or decrypting feeded data.
    crypter: OpenSslCrypter,

    /// The number of encrypted/decrypted plaintext bytes.
    cur: usize,

    /// The total size in bytes of the plaintext.
    len: usize,

    /// Data tag, used for verification.
    /// This is generated during encryption, and consumed during decryption.
    tag: Vec<u8>,
}

impl GcmCrypt {
    /// Construct a new AES-GCM crypter.
    ///
    /// It is highly recommended to use the [`encrypt()`](Self::encrypt) and
    /// [`decrypt()`](Self::decrypt) methods instead for constructing a new crypter.
    ///
    /// The `mode` parameter defines whether this encrypts or decrypts.
    /// The length of the payload to encrypt or decrypt must be given to `len`, this excludes the
    /// appended verification tag on the encrypted payload.
    ///
    /// The crypto `key` and input vector `iv` must also be given.
    pub fn new(mode: CryptMode, len: usize, key: &[u8], iv: &[u8]) -> Self {
        // Select the cipher and crypter to use
        // TODO: do not unwrap here
        let cipher = OpenSslCipher::aes_128_gcm();
        let crypter = OpenSslCrypter::new(cipher, mode.into(), key, Some(iv))
            .expect("failed to create AES-GCM crypter");

        Self {
            mode,
            cipher,
            crypter,
            cur: 0,
            len,
            tag: Vec::with_capacity(TAG_LEN),
        }
    }

    /// Create an AES-GCM encryptor.
    ///
    /// The size in bytes of the data to encrypt must be given as `len`.
    ///
    /// The encryption `key` and input vector `iv` must also be given.
    pub fn encrypt(len: usize, key: &[u8], iv: &[u8]) -> Self {
        Self::new(CryptMode::Encrypt, len, key, iv)
    }

    /// Create an AES-GCM decryptor.
    ///
    /// The size in bytes of the data to decrypt must be given as `len`, including the size of the
    /// suffixed tag.
    ///
    /// The decryption `key` and input vector `iv` must also be given.
    pub fn decrypt(len: usize, key: &[u8], iv: &[u8]) -> Self {
        assert!(
            len > TAG_LEN,
            "failed to create AES-GCM decryptor, encrypted payload too small"
        );
        Self::new(CryptMode::Decrypt, len - TAG_LEN, key, iv)
    }

    /// Check if the AES-GCM cryptographic tag is known.
    ///
    /// When decrypting, this means all data has been processed and the suffixed tag was obtained.
    pub fn has_tag(&self) -> bool {
        self.tag.len() >= TAG_LEN
    }

    /// Encrypt the given `input` data using this configured crypter.
    ///
    /// This function returns `(read, out)` where `read` represents the number of read bytes from
    /// `input`, and `out` is a vector of now encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter.
    fn pipe_encrypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // Don't allow encrypting more than specified, when tag is obtained
        if self.has_tag() && !input.is_empty() {
            panic!("could not write to AES-GCM encrypter, exceeding specified length");
        }

        // Find input length and block size, increase current bytes counter
        let len = input.len();
        let block_size = self.cipher.block_size();
        self.cur += len;

        // Transform input data through crypter, collect output
        // TODO: do not unwrap here, but try error
        let mut out = vec![0u8; len + block_size];
        let out_len = self
            .crypter
            .update(&input, &mut out)
            .expect("failed to update AES-GCM encrypter with new data");
        out.truncate(out_len);

        // Finalize the crypter when all data is encrypted, append finalized to output
        // TODO: do not unwrap in here, but try error
        if self.cur >= self.len && !self.has_tag() {
            // Allocate tag space
            self.tag = vec![0u8; TAG_LEN];

            let mut out_final = vec![0u8; block_size];
            let final_len = self
                .crypter
                .finalize(&mut out_final)
                .expect("failed to finalize AES-GCM encrypter");
            out.extend_from_slice(&out_final[..final_len]);
            self.crypter
                .get_tag(&mut self.tag)
                .expect("failed to get AES-GCM encrypter tag for validation");

            // Append tag to output
            out.extend_from_slice(&self.tag);
        }

        (len, Some(out))
    }

    /// Decrypt the given `input` payload using this configured crypter.
    ///
    /// This function returns `(read, plaintext)` where `read` represents the number of read bytes from
    /// `input`, and `plaintext` is a vector of the produced plaintext.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter.
    fn pipe_decrypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // Don't allow decrypting more than specified, when tag is obtained
        if self.has_tag() && !input.is_empty() {
            panic!("could not write to AES-GCM decrypter, exceeding specified lenght");
        }

        // How many data and tag bytes we need to read, read chunks from input
        let data_len = self.len - self.cur;
        let tag_len = TAG_LEN - self.tag.len();
        let consumed = min(data_len + tag_len, input.len());
        let (data_buf, tag_buf) = input.split_at(min(data_len, input.len()));
        self.cur += min(consumed, self.len);

        let mut plaintext = Vec::new();

        // Read from the data buffer
        if !data_buf.is_empty() {
            // Create a decrypted buffer, with the proper size
            let block_size = self.cipher.block_size();
            let mut decrypted = vec![0u8; data_len + block_size];

            // Decrypt bytes
            // TODO: do not unwrap, but try error
            let len = self
                .crypter
                .update(data_buf, &mut decrypted)
                .expect("failed to update AES-GCM decrypter with new data");

            // Add decrypted bytes to output
            plaintext.extend_from_slice(&decrypted[..len]);
        }

        // Read from the tag part to fill the tag buffer
        if !tag_buf.is_empty() {
            self.tag.extend_from_slice(&tag_buf[..tag_len]);
        }

        // Verify the tag once available
        if self.has_tag() {
            // Set the tag
            // TODO: do not unwrap, but try error
            self.crypter
                .set_tag(&self.tag)
                .expect("failed to set AES-GCM decrypter tag for validation");

            // Create a buffer for any remaining data
            let block_size = self.cipher.block_size();
            let mut extra = vec![0u8; block_size];

            // Finalize, write all remaining data
            // TODO: do not unwrap, but try error
            let len = self
                .crypter
                .finalize(&mut extra)
                .expect("failed to finalize AES-GCM decrypter");
            plaintext.extend_from_slice(&extra[..len]);
        }

        let plaintext = if !plaintext.is_empty() {
            Some(plaintext)
        } else {
            None
        };
        (consumed, plaintext)
    }
}

impl Pipe for GcmCrypt {
    type Reader = GcmReader;
    type Writer = GcmWriter;

    fn pipe(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        match self.mode {
            CryptMode::Encrypt => self.pipe_encrypt(input),
            CryptMode::Decrypt => self.pipe_decrypt(input),
        }
    }
}

impl Crypt for GcmCrypt {}

impl PipeLen for GcmCrypt {
    fn len_in(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => self.len,
            CryptMode::Decrypt => self.len + TAG_LEN,
        }
    }

    fn len_out(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => self.len + TAG_LEN,
            CryptMode::Decrypt => self.len,
        }
    }
}

unsafe impl Send for GcmCrypt {}

pub struct GcmReader {
    crypt: GcmCrypt,
    inner: Box<dyn Read>,
    buf_in: BytesMut,
    buf_out: BytesMut,
}

pub struct GcmWriter {
    crypt: GcmCrypt,
    inner: Box<dyn Write>,
}

impl PipeRead<GcmCrypt> for GcmReader {
    fn new(crypt: GcmCrypt, inner: Box<dyn Read>) -> Self {
        Self {
            crypt,
            inner,
            buf_in: BytesMut::with_capacity(DEFAULT_BUF_SIZE),
            buf_out: BytesMut::with_capacity(DEFAULT_BUF_SIZE),
        }
    }
}

impl PipeWrite<GcmCrypt> for GcmWriter {
    fn new(crypt: GcmCrypt, inner: Box<dyn Write>) -> Self {
        Self { crypt, inner }
    }
}

impl Read for GcmReader {
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

        // Attempt to fill input buffer if has capacity up to default buffer size
        let capacity = DEFAULT_BUF_SIZE - self.buf_in.len();
        if capacity > 0 {
            // Read from inner to input buffer
            let mut inner_buf = vec![0u8; capacity];
            let read = self.inner.read(&mut inner_buf)?;
            self.buf_in.extend_from_slice(&inner_buf[..read]);

            // If nothing is read, return the same
            if read == 0 {
                return Ok(0);
            }
        }

        // Move input buffer into the crypter
        let (read, out) = self.crypt.crypt(&self.buf_in);
        let _ = self.buf_in.split_to(read);

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

impl Write for GcmWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Transform input data through crypter, write result to inner writer
        let (read, data) = self.crypt.crypt(buf);
        if let Some(data) = data {
            self.inner.write_all(&data)?;
        }

        Ok(read)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl PipeLen for GcmReader {
    fn len_in(&self) -> usize {
        self.crypt.len_in()
    }

    fn len_out(&self) -> usize {
        self.crypt.len_out()
    }
}

impl ReadLen for GcmReader {}

impl PipeLen for GcmWriter {
    fn len_in(&self) -> usize {
        self.crypt.len_in()
    }

    fn len_out(&self) -> usize {
        self.crypt.len_out()
    }
}

impl WriteLen for GcmWriter {}

unsafe impl Send for GcmReader {}
unsafe impl Send for GcmWriter {}
