//! ECE encrypter/decrypter pipe implementation.

use std::io::{self, Read, Write};
use std::cmp::min;

use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, Bytes, BytesMut};
use openssl::symm;

use crate::crypto::hkdf::hkdf;
use crate::pipe::{
    DEFAULT_BUF_SIZE,
    prelude::*,
};
use super::{Crypt, CryptMode};

// TODO: specify this somewhere else?
const RS: u32 = 1024 * 64;

const SALT_LENGTH: usize = 16;
const KEY_LENGTH: usize = 16;
const TAG_LENGTH: usize = 16;
const RS_LENGTH: usize = 4;

// Defined by ECE standard
const ECE_AES_KEY_LENGTH: usize = 16;
const ECE_NONCE_LENGTH: usize = 12;

const ECE_AES128GCM_HEADER_LENGTH: u32 = 21;
const ECE_AES128GCM_KEY_INFO: &str = "Content-Encoding: aes128gcm\0";
const ECE_AES128GCM_NONCE_INFO: &str = "Content-Encoding: nonce\0";

/// Something that can encrypt or decrypt given data using ECE.
pub struct EceCrypt {
    mode: CryptMode,

    ikm: Vec<u8>,
    key: Option<Vec<u8>>,
    // This is the base nonce
    nonce: Option<Vec<u8>>,

    salt: Option<Vec<u8>>,

    /// Chunk sequence, limited to `u32::MAX`.
    seq: u32,

    cur_in: usize,

    cur: usize,

    /// The total size in bytes of the plain text payload, excluding any encryption overhead.
    len: usize,

    /// The used ECE cryptographic record size.
    rs: u32,

    // TODO: remove this buffer, obsolete?
    // /// Input buffer.
    // buf: BytesMut,
}

impl EceCrypt {
    /// Construct a new ECE crypter pipe.
    pub fn new(mode: CryptMode, ikm: Vec<u8>, len: usize) -> Self {
        Self {
            mode,
            ikm,
            // TODO: define key
            key: None,
            // TODO: define nonce
            nonce: None,
            // TODO: define salt
            salt: None,
            seq: 0,
            cur_in: 0,
            cur: 0,
            len,
            rs: RS,
            // buf: BytesMut::with_capacity(DEFAULT_BUF_SIZE),
        }
    }

    // TODO: create encrypt and decrypt specific constructor, like in the AES-GCM pipe

    /// Get the size of the payload chunk.
    ///
    /// Data passed to the crypter must match the chunk size.
    ///
    /// The chunk size might change during encryption/decryption due to prefixed data.
    fn chunk_size(&self) -> u32 {
        match self.mode {
            CryptMode::Encrypt => self.rs - 17,
            // TODO: shouldn't this be `21`? Use `ECE_AES128GCM_HEADER_LENGTH` instead?
            CryptMode::Decrypt => if self.has_header() {
                    self.rs
                } else {
                    21
                },
        }
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
        // // Don't allow encrypting more than specified, when tag is obtained
        // if self.has_tag() && !input.is_empty() {
        //     panic!("could not write to AES-GCM encrypter, exceeding specified length");
        // }

        // // Find input length and block size, increase current bytes counter
        // let len = input.len();
        // let block_size = self.cipher.block_size();
        // self.cur += len;

        // // Transform input data through crypter, collect output
        // // TODO: do not unwrap here, but try error
        // let mut out = vec![0u8; len + block_size];
        // let out_len = self.crypter.update(&input, &mut out)
        //     .expect("failed to update AES-GCM encrypter with new data");
        // out.truncate(out_len);

        // // Finalize the crypter when all data is encrypted, append finalized to output
        // // TODO: do not unwrap in here, but try error
        // if self.cur >= self.len && !self.has_tag() {
        //     // Allocate tag space
        //     self.tag = vec![0u8; GCM_TAG_SIZE];

        //     let mut out_final = vec![0u8; block_size];
        //     let final_len = self.crypter.finalize(&mut out_final)
        //         .expect("failed to finalize AES-GCM encrypter");
        //     out.extend_from_slice(&out_final[..final_len]);
        //     self.crypter.get_tag(&mut self.tag)
        //         .expect("failed to get AES-GCM encrypter tag for validation");

        //     // Append tag to output
        //     out.extend_from_slice(&self.tag);
        // }

        // (len, Some(out))

        panic!("not yet implemented");
    }

    /// Decrypt the given `input` payload using this configured crypter.
    ///
    /// This function returns `(read, out)` where `read` represents the number of read bytes from
    /// `input`, and `out` is a vector of now encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter.
    fn pipe_decrypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // // Don't allow decrypting more than specified, when tag is obtained
        // if self.has_tag() && !input.is_empty() {
        //     panic!("could not write to AES-GCM decrypter, exceeding specified lenght");
        // }

        // Generate the decryption nonce
        let nonce = self.generate_nonce(self.seq);

        // Split input into data and tag parts
        let data = &input[..input.len() - TAG_LENGTH];
        let tag = &input[input.len() - TAG_LENGTH..input.len()];

        // Decrypt the chunk
        let out = symm::decrypt_aead(
            symm::Cipher::aes_128_gcm(),
            self.key.as_ref().expect("no key"),
            Some(&nonce),
            &[],
            data,
            tag,
        ).expect("failed to decrypt ECE chunk");

        let last = self.is_last();
        // TODO: do unpadding

        // Update transformed length
        self.cur += out.len();

        (input.len(), Some(out))
    }

    // TODO: actually return the header
    fn pipe_decrypt_header(&mut self, input: &[u8]) {
        // Assert the header chunk size
        // TODO: is bigger than 21 because of key size
        assert!(
            input.len() as u32 >= ECE_AES128GCM_HEADER_LENGTH,
            "failed to decrypt, ECE header is too short",
        );

        // Easily handle input data as bytes
        let mut input = Bytes::from(input);

        // Parse the salt, record size and length
        self.salt = Some(input.split_to(SALT_LENGTH).to_vec());
        self.rs = BigEndian::read_u32(&input.split_to(RS_LENGTH));
        let key_id_len = input.split_to(1)[0] as usize;

        let length = key_id_len + KEY_LENGTH + 5;

        // Derive the key and nonce
        self.key = Some(hkdf(
            self.salt.as_ref().map(|s| s.as_slice()),
            ECE_AES_KEY_LENGTH,
            &self.ikm,
            Some(ECE_AES128GCM_KEY_INFO.as_bytes()),
        ));
        self.nonce = Some(hkdf(
            self.salt.as_ref().map(|s| s.as_slice()),
            ECE_NONCE_LENGTH,
            &self.ikm,
            Some(ECE_AES128GCM_NONCE_INFO.as_bytes()),
        ));

        // TODO: remove after debugging
        dbg!(&self.salt);
        dbg!(self.rs);
        dbg!(key_id_len);
        dbg!(length);
        dbg!(&self.key);
        dbg!(&self.nonce);

        // Assert all header bytes have been consumed
        // TODO: Not valid? Header may be longer?
        assert!(input.is_empty(), "failed to decrypt, not all ECE header bytes are used");
    }

    /// Generate crypto nonce for sequence with index `seq`.
    ///
    /// Each payload chunk uses a different nonce.
    /// This method generates the nonce to use.
    fn generate_nonce(&self, seq: u32) -> Vec<u8> {
        // Get the base nonce which we need to modify
        let mut nonce = self.nonce.clone().expect("failed to generate nonce, no base nonce available");

        let nonce_len = nonce.len();
        let m = BigEndian::read_u32(&nonce[nonce_len - 4..nonce_len]);
        let xor = m ^ seq;

        // TODO: remove after debugging
        dbg!(xor);

        BigEndian::write_u32(&mut nonce[nonce_len - 4..nonce_len], xor);

        nonce
    }

    /// Check whehter the header is read.
    ///
    /// This checks whether the header has been read from the input while decrypting.
    /// The header contains important information for the rest of the decryption process and must
    /// be obtained and parsed first.
    fn has_header(&self) -> bool {
        self.salt.is_some()
    }

    fn len_encrypted(&self) -> usize {
        21 + self.len + 16 * (self.len as f64 / (RS as f64 - 17f64)).floor() as usize
    }

    // If ready to process last chunk
    fn is_last(&self) -> bool {
        self.cur_in >= self.len_in()
    }
}

impl Pipe for EceCrypt {
    type Reader = EceReader;
    type Writer = EceWriter;

    fn pipe(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // Increase input byte counter
        self.cur_in += input.len();

        // Assert the chunk size
        if !self.is_last() {
            assert_eq!(
                input.len() as u32,
                self.chunk_size(),
                "input data passed to ECE cryptor does not match chunk size",
            );
        }

        // Get the header first before decrypting
        match self.mode {
            CryptMode::Decrypt if !self.has_header() => {
                self.pipe_decrypt_header(input);
                return (input.len(), None);
            },
            _ => {},
        }

        // Encrypt or decrypt depending on the mode
        let result = match self.mode {
            CryptMode::Encrypt => self.pipe_encrypt(input),
            CryptMode::Decrypt => self.pipe_decrypt(input),
        };

        // Increase the sequence count
        self.seq = self.seq.checked_add(1)
            .expect("failed to crypt ECE payload, record sequence number exceeds limit");

        result
    }
}

impl Crypt for EceCrypt {}

impl PipeLen for EceCrypt {
    fn len_in(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => self.len,
            // TODO: implement this!
            CryptMode::Decrypt => self.len_encrypted(),
        }
    }

    fn len_out(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => self.len_encrypted(),
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

    tmp: usize,
}

impl PipeRead<EceCrypt> for EceReader {
    fn new(crypt: EceCrypt, inner: Box<dyn Read>) -> Self {
        let chunk_size = crypt.chunk_size() as usize;

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
        let chunk_size = crypt.chunk_size() as usize;

        Self {
            crypt,
            inner,
            buf: BytesMut::with_capacity(chunk_size),

            tmp: 0,
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
        let capacity = self.crypt.chunk_size() as usize - self.buf_in.len();
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
        let chunk_size = self.crypt.chunk_size() as usize;

        // Attempt to fill input buffer if has capacity upto the chunk size
        let capacity = chunk_size - self.buf.len();
        let mut read = min(capacity, buf.len());
        if capacity > 0 {
            self.buf.extend_from_slice(&buf[..read]);
            self.tmp += read;
        }

        // Transform input data through crypter if chunk data is available
        if self.buf.len() >= chunk_size {
            let (read, data) = self.crypt.crypt(&self.buf.split_off(0));
            assert_eq!(read, chunk_size, "ECE crypto did not transform full chunk");
            if let Some(data) = data {
                self.inner.write_all(&data)?;
            }
        }

        // If all expected data is provided, make sure to finish the last partial chunk
        // TODO: somehow use is_last
        if self.tmp >= self.len_in() {
            if let (_, Some(data)) = self.crypt.crypt(&self.buf.split_off(0)) {
                self.inner.write_all(&data)?;
            }
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
