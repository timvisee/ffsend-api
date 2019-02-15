//! ECE AES-GCM 128 encrypter/decrypter pipe implementation for Firefox Send v2.

use std::io::{self, Read, Write};
use std::cmp::min;

use byteorder::{BigEndian, ByteOrder};
use bytes::{Bytes, BytesMut};
use openssl::symm;

use crate::crypto::hkdf::hkdf;
use crate::pipe::{
    DEFAULT_BUF_SIZE,
    prelude::*,
};
use super::{Crypt, CryptMode};

/// The default record size in bytes to use for encryption.
///
/// This value matches the default configured in the Firefox Send v2 source code.
const RS: u32 = 1024 * 64;

/// The crypto key length.
const KEY_LEN: usize = 16;

/// The length in bytes of the crypto tag.
const TAG_LEN: usize = 16;

/// The crypto nonce length.
const NONCE_LEN: usize = 12;

/// Thelength in bytes of the header.
const HEADER_LEN: u32 = 21;

/// The length in bytes of the crypto salt.
const SALT_LEN: usize = 16;

/// The length in bytes of the record size, as encoded in the ECE header.
const RS_LEN: usize = 4;

/// The key info text.
const KEY_INFO: &str = "Content-Encoding: aes128gcm\0";

/// The nonce info text.
const NONCE_INFO: &str = "Content-Encoding: nonce\0";

/// Something that can encrypt or decrypt given data using ECE.
pub struct EceCrypt {
    /// The crypto mode, make this encrypt or decrypt data.
    mode: CryptMode,

    /// The crypto input key material.
    ikm: Vec<u8>,

    /// The crypto key if known.
    key: Option<Vec<u8>>,

    /// The crypto base nonce if known, chunk nonces are derived from.
    nonce: Option<Vec<u8>>,

    /// The crypto salt if known.
    salt: Option<Vec<u8>>,

    /// Sequence number of the current chunk.
    ///
    /// This number increases when transforming chunks.
    /// The ciphertext header is excluded from this sequence.
    seq: u32,

    /// The number of bytes fed into this crypter.
    ///
    /// When encrypting, this corresponds to the number of plaintext bytes (matches `cur`).
    /// When decrypting, this corresponds to the number of ciphertext bytes including the header.
    ///
    /// Used to determine when the last chunk is reached.
    /// This value is used to determine 
    cur_in: usize,

    /// The number of encrypted/decrypted plaintext bytes.
    cur: usize,

    /// The total size in bytes of the plaintext.
    len: usize,

    /// The record size used for crypto chunks.
    ///
    /// This value is dynamic and changes depending on the crypto mode and current progress.
    rs: u32,
}

impl EceCrypt {
    /// Construct a new ECE crypter pipe.
    pub fn new(mode: CryptMode, ikm: Vec<u8>, len: usize) -> Self {
        Self {
            mode,
            ikm,
            key: None,
            nonce: None,
            salt: None,
            seq: 0,
            cur_in: 0,
            cur: 0,
            len,
            rs: RS,
        }
    }

    // TODO: create encrypt and decrypt specific constructor, like in the AES-GCM pipe

    /// Get the current desired size of a payload chunk.
    ///
    /// This value is dynamic and changes depending on the crypto mode, and the current stage.
    /// Data passed to the crypter must match the chunk size.
    fn chunk_size(&self) -> u32 {
        match self.mode {
            CryptMode::Encrypt => self.rs - 17,
            CryptMode::Decrypt => if self.has_header() {
                    self.rs
                } else {
                    HEADER_LEN
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
    fn encrypt_chunk(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
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

    /// Decrypt the given `ciphertext` using ECE crypto.
    ///
    /// This function returns `(read, plaintext)` where `read` represents the number of read bytes from
    /// `ciphertext`, and `out` is a vector of the producted plaintext.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter, or if decryption of a chunk failed.
    fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> (usize, Option<Vec<u8>>) {
        // // Don't allow decrypting more than specified, when tag is obtained
        // if self.has_tag() && !ciphertext.is_empty() {
        //     panic!("could not write to AES-GCM decrypter, exceeding specified lenght");
        // }

        // Generate the decryption nonce, split ciphertext into payload and tag
        let nonce = self.generate_nonce(self.seq);
        let (payload, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);

        // Decrypt the chunk, and unpad decrypted payload
        let mut plaintext = symm::decrypt_aead(
            symm::Cipher::aes_128_gcm(),
            self.key.as_ref().expect("no key"),
            Some(&nonce),
            &[],
            payload,
            tag,
        ).expect("failed to decrypt ECE chunk");
        unpad(&mut plaintext, self.is_last());

        // Update transformed length
        self.cur += plaintext.len();

        (ciphertext.len(), Some(plaintext))
    }

    /// Parse the given header bytes as ECE crypto header.
    ///
    /// This function attemts to parse the given header bytes.
    /// A salt and record size is parsed, a key and nonce are derived from them.
    /// The values are set in the inner `EceCrypt` instance and are automatically used for further
    /// decryption.
    ///
    /// # Panics
    ///
    /// Panics if the given header bytes have an invalid size, or if the given header is not fully
    /// parsed.
    fn pipe_decrypt_header(&mut self, header: &[u8]) {
        // Assert the minimum header chunk size
        assert!(
            header.len() as u32 >= HEADER_LEN,
            "failed to decrypt, ECE header is too short",
        );

        // Easily handle header data as bytes
        let mut header = Bytes::from(header);

        // Parse the salt, record size and length
        self.salt = Some(header.split_to(SALT_LEN).to_vec());
        self.rs = BigEndian::read_u32(&header.split_to(RS_LEN));

        // Extracted in Send v2 code, but doesn't seem to be used
        // let key_id_len = header.split_to(1)[0] as usize;
        // let length = key_id_len + KEY_LEN + 5;

        // Derive the key and nonce
        self.key = Some(hkdf(
            self.salt.as_ref().map(|s| s.as_slice()),
            KEY_LEN,
            &self.ikm,
            Some(KEY_INFO.as_bytes()),
        ));
        self.nonce = Some(hkdf(
            self.salt.as_ref().map(|s| s.as_slice()),
            NONCE_LEN,
            &self.ikm,
            Some(NONCE_INFO.as_bytes()),
        ));

        // Assert all header bytes have been consumed
        // TODO: Not valid? Header may include other things?
        assert!(header.is_empty(), "failed to decrypt, not all ECE header bytes are used");
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
            CryptMode::Encrypt => self.encrypt_chunk(input),
            CryptMode::Decrypt => self.decrypt_chunk(input),
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
            CryptMode::Decrypt => len_encrypted(self.len),
        }
    }

    fn len_out(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => len_encrypted(self.len),
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
        let read = min(capacity, buf.len());
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

/// Pad a plaintext chunk for ECE encryption.
///
/// Padding is a required step for ECE encryption.
/// This modifies the block in-place.
///
/// The padding length in number of bytes must be passed to `pad_len`.
/// If this is the last chunk that will be encrypted, `last` must be `true`.
///
/// This internally suffixes a padding delimiter to the block, and the padding bytes itself.
fn pad(block: &mut Vec<u8>, pad_len: usize, last: bool) {
    block.push(if last { 2 } else { 1 });
    block.extend(vec![0u8; pad_len]);
}

/// Unpad an decrypted ECE ciphertext chunk.
///
/// Unpadding is a required step to transform ECE decrypted data into plain text.
/// This modifies the block in-place.
///
/// If this is the last chunk that will be decrypted, `last` must be `false`.
fn unpad(block: &mut Vec<u8>, last: bool) {
    let pos = match block.iter().rposition(|&b| b != 0) {
        Some(pos) => pos,
        None => panic!("ciphertext is zero"),
    };
    let expected_delim = if last { 2 } else { 1 };
    assert_eq!(block[pos], expected_delim, "ECE decrypt unpadding failure");

    // Truncate the padded bytes
    block.truncate(pos);
}

/// Calcualte approximate length of ECE encrypted data.
///
/// This function attempts to approximate the length in bytes of an ECE ciphertext.
/// The length in bytes of the plaintext must be given as `len`.
fn len_encrypted(len: usize) -> usize {
    21 + len + 16 * (len as f64 / (RS as f64 - 17f64)).floor() as usize
}
