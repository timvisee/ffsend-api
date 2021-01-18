use std::fs::File;
use std::io::{self, Error as IoError, Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use reqwest::{blocking::Response, header::AUTHORIZATION};
use thiserror::Error;

use super::metadata::{Error as MetadataError, Metadata as MetadataAction, MetadataResponse};
use crate::api::request::{ensure_success, ResponseError};
use crate::api::url::UrlBuilder;
use crate::api::Version;
use crate::client::Client;
use crate::crypto::key_set::KeySet;
use crate::crypto::sig::signature_encoded;
use crate::file::remote_file::RemoteFile;
#[cfg(feature = "send3")]
use crate::pipe::crypto::EceCrypt;
#[cfg(feature = "send2")]
use crate::pipe::crypto::GcmCrypt;
use crate::pipe::{
    prelude::*,
    progress::{ProgressPipe, ProgressReporter},
};

/// A file download action to a Send server.
///
/// This action is compatible with both Firefox Send v2 and v3, but the server API version to use
/// must be explicitly given due to a version specific download method.
pub struct Download<'a> {
    /// The server API version to use when downloading the file.
    version: Version,

    /// The remote file to download.
    file: &'a RemoteFile,

    /// The target file or directory, to download the file to.
    target: PathBuf,

    /// An optional password to decrypt a protected file.
    password: Option<String>,

    /// Check whether the file exists (recommended).
    check_exists: bool,

    /// The metadata response to work with,
    /// which will skip the internal metadata request.
    metadata_response: Option<MetadataResponse>,
}

impl<'a> Download<'a> {
    /// Construct a new download action for the given remote file.
    /// It is recommended to check whether the file exists,
    /// unless that is already done.
    pub fn new(
        version: Version,
        file: &'a RemoteFile,
        target: PathBuf,
        password: Option<String>,
        check_exists: bool,
        metadata_response: Option<MetadataResponse>,
    ) -> Self {
        Self {
            version,
            file,
            target,
            password,
            check_exists,
            metadata_response,
        }
    }

    /// Invoke the download action.
    pub fn invoke(
        mut self,
        client: &Client,
        reporter: Option<Arc<Mutex<dyn ProgressReporter>>>,
    ) -> Result<(), Error> {
        // Create a key set for the file
        let mut key = KeySet::from(self.file, self.password.as_ref());

        // Get the metadata, or fetch the file metadata,
        // then update the input vector in the key set
        let metadata: MetadataResponse = if self.metadata_response.is_some() {
            self.metadata_response.take().unwrap()
        } else {
            MetadataAction::new(self.file, self.password.clone(), self.check_exists)
                .invoke(&client)?
        };

        // Set the input vector if known, depending on the API version
        if let Some(nonce) = metadata.metadata().iv() {
            key.set_nonce(nonce);
        }

        // Decide what actual file target to use
        let path = self.decide_path(metadata.metadata().name());
        let path_str = path.to_str().unwrap_or("?").to_owned();

        // Open the file we will write to
        // TODO: this should become a temporary file first
        // TODO: use the uploaded file name as default
        let out = File::create(path)
            .map_err(|err| Error::File(path_str.clone(), FileError::Create(err)))?;

        // Create the file reader for downloading
        let (reader, len) = self.create_file_reader(&key, &metadata, &client)?;

        // Create the file writer
        let writer = self
            .create_writer(out, len, &key, reporter.clone())
            .map_err(|err| Error::File(path_str.clone(), err))?;

        // Download the file
        self.download(reader, writer, len, reporter)?;

        // TODO: return the file path
        // TODO: return the new remote state (does it still exist remote)

        Ok(())
    }

    /// Decide what path we will download the file to.
    ///
    /// A target file or directory, and a file name hint must be given.
    /// The name hint can be derived from the retrieved metadata on this file.
    ///
    /// The name hint is used as file name, if a directory was given.
    fn decide_path(&self, name_hint: &str) -> PathBuf {
        // Return the target if it is an existing file
        if self.target.is_file() {
            return self.target.clone();
        }

        // Append the name hint if this is a directory
        if self.target.is_dir() {
            return self.target.join(name_hint);
        }

        // Return if the parent is an existing directory
        if self.target.parent().map(|p| p.is_dir()).unwrap_or(false) {
            return self.target.clone();
        }

        // TODO: are these todos below already implemented in CLI client?
        // TODO: canonicalize the path when possible
        // TODO: allow using `file.toml` as target without directory indication
        // TODO: return a nice error here as the path may be invalid
        // TODO: maybe prompt the user to create the directory
        panic!("Invalid (non-existing) output path given, not yet supported");
    }

    /// Make a download request, and create a reader that downloads the
    /// encrypted file.
    ///
    /// The response representing the file reader is returned along with the
    /// length of the reader content.
    fn create_file_reader(
        &self,
        key: &KeySet,
        metadata: &MetadataResponse,
        client: &Client,
    ) -> Result<(Response, u64), DownloadError> {
        // Compute the cryptographic signature
        let sig = signature_encoded(key.auth_key().unwrap(), metadata.nonce())
            .map_err(|_| DownloadError::ComputeSignature)?;

        // Build and send the download request
        let response = client
            .get(UrlBuilder::api_download(self.file))
            .header(AUTHORIZATION.as_str(), format!("send-v1 {}", sig))
            .send()
            .map_err(|_| DownloadError::Request)?;

        // Ensure the response is successful
        ensure_success(&response).map_err(DownloadError::Response)?;

        // Get the content length
        // TODO: make sure there is enough disk space
        let len = metadata.size();

        Ok((response, len))
    }

    /// Create a file writer.
    ///
    /// This writer will will decrypt the input on the fly, and writes the
    /// decrypted data to the given file.
    fn create_writer(
        &self,
        file: File,
        len: u64,
        key: &KeySet,
        reporter: Option<Arc<Mutex<dyn ProgressReporter>>>,
    ) -> Result<impl Write, FileError> {
        // Build the decrypting file writer for the selected server API version
        let writer: Box<dyn Write> = match self.version {
            #[cfg(feature = "send2")]
            Version::V2 => {
                let decrypt = GcmCrypt::decrypt(len as usize, key.file_key().unwrap(), key.nonce());
                let writer = decrypt.writer(Box::new(file));
                Box::new(writer)
            }
            #[cfg(feature = "send3")]
            Version::V3 => {
                let ikm = key.secret().to_vec();
                let decrypt = EceCrypt::decrypt(len as usize, ikm);
                let writer = decrypt.writer(Box::new(file));
                Box::new(writer)
            }
        };

        // Build the progress pipe file writer
        let progress = ProgressPipe::zero(len as u64, reporter);
        let writer = progress.writer(writer);

        Ok(writer)
    }

    /// Download the file from the reader, and write it to the writer.
    /// The length of the file must also be given.
    /// The status will be reported to the given progress reporter.
    fn download<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        len: u64,
        reporter: Option<Arc<Mutex<dyn ProgressReporter>>>,
    ) -> Result<(), DownloadError>
    where
        R: Read,
        W: Write,
    {
        // Start the writer
        if let Some(reporter) = reporter.as_ref() {
            reporter
                .lock()
                .map_err(|_| DownloadError::Progress)?
                .start(len);
        }

        // Write to the output file
        io::copy(&mut reader, &mut writer).map_err(|_| DownloadError::Download)?;

        // Finish
        if let Some(reporter) = reporter.as_ref() {
            reporter
                .lock()
                .map_err(|_| DownloadError::Progress)?
                .finish();
        }

        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum Error {
    /// An error occurred while fetching the metadata of the file.
    /// This step is required in order to succsessfully decrypt the
    /// file that will be downloaded.
    #[error("failed to fetch file metadata")]
    Meta(#[from] MetadataError),

    /// The given Send file has expired, or did never exist in the first place.
    /// Therefore the file could not be downloaded.
    #[error("the file has expired or did never exist")]
    Expired,

    /// A password is required, but was not given.
    #[error("missing password, password required")]
    PasswordRequired,

    /// An error occurred while downloading the file.
    #[error("failed to download the file")]
    Download(#[from] DownloadError),

    /// An error occurred while decrypting the downloaded file.
    #[error("failed to decrypt the downloaded file")]
    Decrypt,

    /// An error occurred while opening or writing to the target file.
    // TODO: show what file this is about
    #[error("couldn't use the target file at '{}'", _0)]
    File(String, #[source] FileError),
}

#[derive(Error, Debug)]
pub enum DownloadError {
    /// An error occurred while computing the cryptographic signature used for
    /// downloading the file.
    #[error("failed to compute cryptographic signature")]
    ComputeSignature,

    /// Sending the request to download the file failed.
    #[error("failed to request file download")]
    Request,

    /// The server responded with an error while requesting the file download.
    #[error("bad response from server while requesting download")]
    Response(#[from] ResponseError),

    /// Failed to start or update the downloading progress, because of this the
    /// download can't continue.
    #[error("failed to update download progress")]
    Progress,

    /// The actual download and decryption process the server.
    /// This covers reading the file from the server, decrypting the file,
    /// and writing it to the file system.
    #[error("failed to download the file")]
    Download,
    // /// Verifying the downloaded file failed.
    // #[error("file verification failed")]
    // Verify,
}

#[derive(Error, Debug)]
pub enum FileError {
    /// An error occurred while creating or opening the file to write to.
    #[error("failed to create or replace the file")]
    Create(#[from] IoError),

    /// Failed to create an encrypted writer for the file, which is used to
    /// decrypt the downloaded file.
    #[error("failed to create file decryptor")]
    EncryptedWriter,
}
