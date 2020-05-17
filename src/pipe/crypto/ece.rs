//! ECE AES-GCM 128 encrypter/decrypter pipe implementation for Firefox Send v3.

use std::cmp::min;
use std::io::{self, Read, Write};

use byteorder::{BigEndian, ByteOrder};
use bytes::BytesMut;
#[cfg(feature = "crypto-openssl")]
use openssl::symm;
#[cfg(feature = "crypto-ring")]
use ring::aead;

use super::{Crypt, CryptMode};
use crate::config::{self, TAG_LEN};
use crate::crypto::{hkdf::hkdf, rand_bytes};
use crate::pipe::{prelude::*, DEFAULT_BUF_SIZE};

/// The default record size in bytes to use for encryption.
///
/// This value matches the default configured in the Firefox Send v3 source code.
pub const RS: u32 = config::ECE_RECORD_SIZE;

/// The crypto key length.
const KEY_LEN: usize = 16;

/// The crypto nonce length.
const NONCE_LEN: usize = 12;

/// The length in bytes of the header.
pub const HEADER_LEN: u32 = 21;

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
    ///
    /// It is highly recommended to use the [`encrypt()`](Self::encrypt) and
    /// [`decrypt()`](Self::decrypt) methods instead for constructing a new crypter.
    ///
    /// The size in bytes of the plaintext data must be given as `len`.
    /// The input key material must be given as `ikm`.
    /// When encrypting, a `salt` must be specified.
    pub fn new(mode: CryptMode, len: usize, ikm: Vec<u8>, salt: Option<Vec<u8>>) -> Self {
        Self {
            mode,
            ikm,
            key: None,
            nonce: None,
            salt,
            seq: 0,
            cur_in: 0,
            cur: 0,
            len,
            rs: RS,
        }
    }

    /// Create an ECE encryptor.
    ///
    /// The size in bytes of the plaintext data that is encrypted decrypt must be given as `len`.
    /// The input key material must be given as `ikm`.
    /// The `salt` is optional and will be randomly generated if `None`.
    pub fn encrypt(len: usize, ikm: Vec<u8>, salt: Option<Vec<u8>>) -> Self {
        // Construct the encrypter, generate random salt if not set
        let mut crypt = Self::new(
            CryptMode::Encrypt,
            len,
            ikm,
            salt.or_else(|| Some(generate_salt())),
        );

        // Derive the key and nonce
        crypt.derive_key_and_nonce();

        crypt
    }

    /// Create an ECE decryptor.
    ///
    /// The size in bytes of the plaintext data that is decrypted decrypt must be given as `len`.
    /// The input key material must be given as `ikm`.
    pub fn decrypt(len: usize, ikm: Vec<u8>) -> Self {
        Self::new(CryptMode::Decrypt, len, ikm, None)
    }

    /// Get the current desired size of a payload chunk.
    ///
    /// This value is dynamic and changes depending on the crypto mode, and the current stage.
    /// Data passed to the crypter must match the chunk size.
    #[inline(always)]
    fn chunk_size(&self) -> u32 {
        match self.mode {
            // Record size with tag length and delimiter
            CryptMode::Encrypt => self.rs - TAG_LEN as u32 - 1,

            // Record size, header length for initial header chunk
            CryptMode::Decrypt => {
                if self.has_header() {
                    self.rs
                } else {
                    HEADER_LEN
                }
            }
        }
    }

    /// Encrypt the given `plaintext` data using this configured crypter.
    ///
    /// If a header hasn't been created yet, it is included in the output as well.
    ///
    /// This function returns `(read, out)` where `read` represents the number of read bytes from
    /// `plaintext`, and `out` is a vector of now encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter.
    fn pipe_encrypt(&mut self, input: Vec<u8>) -> (usize, Option<Vec<u8>>) {
        // Encrypt the chunk, if the first chunk, the header must be created and prefixed
        if !self.has_header() {
            // Create header
            let mut ciphertext = self.create_header();

            // Encrypt chunk and append to header base ciphertext
            let (read, chunk) = self.encrypt_chunk(input);
            if let Some(chunk) = chunk {
                ciphertext.extend_from_slice(&chunk)
            }

            // Increase chunk sequence number
            self.increase_seq();

            (read, Some(ciphertext))
        } else {
            // Encrypt chunk, increase chunk sequence number
            let result = self.encrypt_chunk(input);
            self.increase_seq();
            result
        }
    }

    /// Decrypt the given `ciphertext` using ECE crypto.
    ///
    /// If the header has not been read yet, it is parsed first to initialize the proper salt and
    /// record size.
    ///
    /// This function returns `(read, plaintext)` where `read` represents the number of read bytes from
    /// `ciphertext`, and `out` is a vector of the producted plaintext.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter, or if decryption of a chunk failed.
    /// size.
    fn pipe_decrypt(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // Parse the header before decrypting anything
        if !self.has_header() {
            self.parse_header(input);
            return (input.len(), None);
        }

        // Decrypt the chunk, increase chunk sequence number
        let result = self.decrypt_chunk(input);
        self.increase_seq();
        result
    }

    /// Encrypt the given `plaintext` chunk data using this configured crypter.
    ///
    /// This function returns `(read, out)` where `read` represents the number of read bytes from
    /// `plaintext`, and `out` is a vector of now encrypted bytes.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter.
    #[inline(always)]
    fn encrypt_chunk(&mut self, mut plaintext: Vec<u8>) -> (usize, Option<Vec<u8>>) {
        // // Don't allow encrypting more than specified, when tag is obtained
        // if self.has_tag() && !plaintext.is_empty() {
        //     panic!("could not write to AES-GCM encrypter, exceeding specified length");
        // }

        // Update transformed length
        let read = plaintext.len();
        self.cur += read;

        // Generate the encryption nonce
        let nonce = self.generate_nonce(self.seq);

        // Pad the plaintext, encrypt the chunk, append tag
        pad(&mut plaintext, self.rs as usize, self.is_last());

        #[cfg(feature = "crypto-openssl")]
        {
            // Encrypt the chunk, append tag
            let mut tag = vec![0u8; TAG_LEN];
            let mut ciphertext = symm::encrypt_aead(
                symm::Cipher::aes_128_gcm(),
                self.key
                    .as_ref()
                    .expect("failed to encrypt ECE chunk, missing crypto key"),
                Some(&nonce),
                &[],
                &plaintext,
                &mut tag,
            )
            .expect("failed to encrypt ECE chunk");
            ciphertext.extend_from_slice(&tag);

            (read, Some(ciphertext))
        }

        #[cfg(feature = "crypto-ring")]
        {
            // Prepare sealing key
            let nonce = aead::Nonce::try_assume_unique_for_key(&nonce)
                .expect("failed to encrypt ECE chunk, invalid nonce");
            let aad = aead::Aad::empty();
            let key = self
                .key
                .as_ref()
                .expect("failed to encrypt ECE chunk, missing crypto key");
            let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, key).unwrap();
            let key = aead::LessSafeKey::new(unbound_key);

            // Seal in place, return sealed
            key.seal_in_place_append_tag(nonce, aad, &mut plaintext)
                .expect("failed to encrypt ECE chunk");

            (read, Some(plaintext.to_vec()))
        }
    }

    /// Decrypt the given `ciphertext` chunk using ECE crypto.
    ///
    /// This function returns `(read, plaintext)` where `read` represents the number of read bytes
    /// from `ciphertext`, and `out` is a vector of the producted plaintext.
    ///
    /// # Panics
    ///
    /// Panics if attempted to write more bytes than the length specified while configuring the
    /// crypter, or if decryption of a chunk failed.
    #[inline(always)]
    fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> (usize, Option<Vec<u8>>) {
        // // Don't allow decrypting more than specified, when tag is obtained
        // if self.has_tag() && !ciphertext.is_empty() {
        //     panic!("could not write to AES-GCM decrypter, exceeding specified lenght");
        // }

        // Generate encryption nonce
        let nonce = self.generate_nonce(self.seq);

        #[cfg(feature = "crypto-openssl")]
        {
            // Split payload and tag
            let (payload, tag) = ciphertext.split_at(ciphertext.len() - TAG_LEN);

            // Decrypt the chunk, and unpad decrypted payload
            let mut plaintext = symm::decrypt_aead(
                symm::Cipher::aes_128_gcm(),
                self.key
                    .as_ref()
                    .expect("failed to decrypt ECE chunk, missing crypto key"),
                Some(&nonce),
                &[],
                payload,
                tag,
            )
            .expect("failed to decrypt ECE chunk");
            unpad(&mut plaintext, self.is_last());

            // Update transformed length
            self.cur += plaintext.len();

            (ciphertext.len(), Some(plaintext))
        }

        #[cfg(feature = "crypto-ring")]
        {
            // Clone ciphertext so we can modify in-place
            let mut ciphertext = ciphertext.to_vec();

            // Prepare opening key
            let nonce = aead::Nonce::try_assume_unique_for_key(&nonce)
                .expect("failed to decrypt ECE chunk, invalid nonce");
            let aad = aead::Aad::empty();
            let key = self
                .key
                .as_ref()
                .expect("failed to decrypt ECE chunk, missing crypto key");
            let unbound_key = aead::UnboundKey::new(&aead::AES_128_GCM, key).unwrap();
            let key = aead::LessSafeKey::new(unbound_key);

            // Decrypt the chunk, and unpad decrypted payload
            let mut plaintext = key
                .open_in_place(nonce, aad, &mut ciphertext)
                .expect("failed to decrypt ECE chunk")
                .to_vec();
            unpad(&mut plaintext, self.is_last());

            // Update transformed length
            self.cur += plaintext.len();

            (ciphertext.len(), Some(plaintext))
        }
    }

    /// Create the ECE crypto header.
    ///
    /// This header includes the salt and record size as configured in this crypter instance.
    /// The header bytes are returned.
    ///
    /// # Panics
    ///
    /// Panics if the salt is not set.
    #[inline(always)]
    fn create_header(&self) -> Vec<u8> {
        // Allocate the header
        let mut header = Vec::with_capacity(HEADER_LEN as usize);

        // Add the salt
        let salt = self
            .salt
            .as_ref()
            .expect("failed to create ECE header, no crypto salt specified");
        assert_eq!(salt.len(), SALT_LEN);
        header.extend_from_slice(salt);

        // Add the record size
        let mut rs = [0u8; 4];
        BigEndian::write_u32(&mut rs, self.rs);
        header.extend_from_slice(&rs);

        // Add length of unused key ID length
        header.push(0);

        header
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
    #[inline(always)]
    fn parse_header(&mut self, header: &[u8]) {
        // Assert the header size
        assert_eq!(
            header.len() as u32,
            HEADER_LEN,
            "failed to decrypt, ECE header is not 21 bytes long",
        );

        // Parse the salt, record size and length
        let (salt, header) = header.split_at(SALT_LEN);
        let (rs, header) = header.split_at(RS_LEN);
        self.salt = Some(salt.to_vec());
        self.rs = BigEndian::read_u32(rs);

        // Extracted in Send v3 code, but doesn't seem to be used
        let (key_id_data, header) = header.split_at(1);
        let key_id_len = key_id_data[0] as usize;
        let _length = key_id_len + KEY_LEN + 5;

        // Derive the key and nonce based on extracted salt
        self.derive_key_and_nonce();

        // Assert all header bytes have been consumed
        // If this fails, update `len_encrypted` as well
        assert!(
            header.is_empty(),
            "failed to decrypt, not all ECE header bytes are used",
        );
    }

    /// Derive the crypto key and base nonce.
    ///
    /// These are derived based on `self.salt` and `self.ikm`, and must be configured.
    ///
    /// # Panics
    ///
    /// panics if either `self.salt` or `self.ikm` is not configured.
    #[inline(always)]
    fn derive_key_and_nonce(&mut self) {
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
    }

    /// Generate crypto nonce for sequence with index `seq`.
    ///
    /// Each payload chunk uses a different nonce.
    /// This method generates the nonce to use.
    #[inline(always)]
    fn generate_nonce(&self, seq: u32) -> Vec<u8> {
        // Get the base nonce which we need to modify
        let mut nonce = self
            .nonce
            .clone()
            .expect("failed to generate nonce, no base nonce available");

        // TODO: slice `nonce` only once, use that for mutating

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
    ///
    /// TODO: better docs
    #[inline(always)]
    fn has_header(&self) -> bool {
        match self.mode {
            CryptMode::Encrypt => self.cur > 0,
            CryptMode::Decrypt => self.salt.is_some(),
        }
    }

    /// Check if working with the last crypto chunk.
    ///
    /// This checks whether all data for the last chunk, determined by the plaintext length in
    /// bytes, has entered this crypto pipe.
    #[inline(always)]
    fn is_last(&self) -> bool {
        self.is_last_with(0)
    }

    /// Check if working with the last crypto chunk including given `extra` bytes.
    ///
    /// This checks whether all data for the last chunk including `extra`, determined by the
    /// plaintext length in bytes, has entered this crypto pipe.
    #[inline(always)]
    fn is_last_with(&self, extra: usize) -> bool {
        self.cur_in + extra >= self.len_in()
    }

    /// Increase the chunk sequence number.
    ///
    /// Called automatically by the `pipe_encrypt` and `pipe_decrypt` methods when a chunk is read.
    /// This should never be invoked manually.
    ///
    /// # Panics
    ///
    /// Panics if the sequence number exceeds the maximum.
    #[inline(always)]
    fn increase_seq(&mut self) {
        self.seq = self
            .seq
            .checked_add(1)
            .expect("failed to crypt ECE payload, record sequence number exceeds limit");
    }
}

impl Pipe for EceCrypt {
    type Reader = EceReader;
    type Writer = EceWriter;

    fn pipe(&mut self, input: &[u8]) -> (usize, Option<Vec<u8>>) {
        // Increase input byte counter
        self.cur_in += input.len();

        // Use mode specific pipe function
        match self.mode {
            CryptMode::Encrypt => self.pipe_encrypt(input.to_vec()),
            CryptMode::Decrypt => self.pipe_decrypt(input),
        }
    }
}

impl Crypt for EceCrypt {}

impl PipeLen for EceCrypt {
    fn len_in(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => self.len,
            CryptMode::Decrypt => len_encrypted(self.len, self.rs as usize),
        }
    }

    fn len_out(&self) -> usize {
        match self.mode {
            CryptMode::Encrypt => len_encrypted(self.len, self.rs as usize),
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

            // Break if:
            // - no new data was read
            // - buffer doesn't have enough data to crypt, while there's data left to read
            if read == 0 || (read != capacity && !self.crypt.is_last_with(read)) {
                return Ok(total);
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

impl Write for EceWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        // Get the chunk size to use
        let chunk_size = self.crypt.chunk_size() as usize;

        // Attempt to fill input buffer if has capacity upto the chunk size
        let capacity = chunk_size - self.buf.len();
        let read = min(capacity, buf.len());
        if capacity > 0 {
            self.buf.extend_from_slice(&buf[..read]);
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
        if self.crypt.is_last_with(self.buf.len()) {
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

impl ReadLen for EceReader {}

impl PipeLen for EceWriter {
    fn len_in(&self) -> usize {
        self.crypt.len_in()
    }

    fn len_out(&self) -> usize {
        self.crypt.len_out()
    }
}

impl WriteLen for EceWriter {}

unsafe impl Send for EceReader {}
unsafe impl Send for EceWriter {}

/// Pad a plaintext chunk for ECE encryption.
///
/// Padding is a required step for ECE encryption.
/// This modifies the block in-place.
///
/// The padding length in number of bytes must be passed to `pad_len`.
/// If this is the last chunk that will be encrypted, `last` must be `true`.
///
/// This internally suffixes a padding delimiter to the block, and the padding bytes itself.
fn pad(block: &mut Vec<u8>, rs: usize, last: bool) {
    // Assert the data fits the records
    assert!(
        block.len() + TAG_LEN < rs,
        "failed to pad ECE ciphertext, data too large for record size"
    );

    // Pad chunks with 1 delimiter and zeros, pad last chunk with single 2 delimiter
    if !last {
        let mut pad = vec![0u8; rs - block.len() - TAG_LEN];
        pad[0] = 1;
        block.extend(pad);
    } else {
        block.push(2);
    }
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

/// Generate a random salt for encryption.
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_LEN];
    rand_bytes(&mut salt).expect("failed to generate encryption salt");
    salt
}

/// Calcualte length of ECE encrypted data.
///
/// This function calculates the length in bytes of the ECE ciphertext.
/// The record size and length in bytes of the plaintext must be given as `rs` and `len`.
pub fn len_encrypted(len: usize, rs: usize) -> usize {
    let chunk_meta = TAG_LEN + 1;
    let chunk_data = rs - chunk_meta;
    let header = HEADER_LEN as usize;
    let chunks = (len as f64 / chunk_data as f64).ceil() as usize;

    header + len + chunk_meta * chunks
}
