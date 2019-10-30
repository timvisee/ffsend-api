extern crate mime;

use std::fs::File;
use std::io::{self, Error as IoError, Read};
#[cfg(feature = "send3")]
use std::mem;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[cfg(feature = "send2")]
use self::mime::APPLICATION_OCTET_STREAM;
use chrono::{DateTime, Duration, Utc};
use mime_guess::{self, Mime};
use openssl::symm::encrypt_aead;
#[cfg(feature = "send2")]
use reqwest::header::AUTHORIZATION;
#[cfg(feature = "send2")]
use reqwest::multipart::{Form, Part};
use reqwest::Error as ReqwestError;
#[cfg(feature = "send2")]
use reqwest::Request;
#[cfg(feature = "send3")]
use serde_json;
use url::{ParseError as UrlParseError, Url};
#[cfg(feature = "send3")]
use websocket::{result::WebSocketError, OwnedMessage};

#[cfg(feature = "send2")]
use super::params::Params;
use super::params::{Error as ParamsError, ParamsData};
use super::password::{Error as PasswordError, Password};
#[cfg(feature = "send2")]
use crate::api::nonce::header_nonce;
#[cfg(feature = "send2")]
use crate::api::request::ensure_success;
use crate::api::request::ResponseError;
use crate::api::Version;
use crate::client::Client;
use crate::crypto::b64;
use crate::crypto::key_set::KeySet;
#[cfg(feature = "send3")]
use crate::file::info::FileInfo;
use crate::file::metadata::Metadata;
use crate::file::remote_file::RemoteFile;
#[cfg(feature = "send3")]
use crate::io::ChunkRead;
#[cfg(feature = "send2")]
use crate::pipe::crypto::GcmCrypt;
#[cfg(feature = "send3")]
use crate::pipe::crypto::{ece, EceCrypt};
use crate::pipe::{
    prelude::*,
    progress::{ProgressPipe, ProgressReporter},
};

/// A file upload action to a Send server.
///
/// The server API version to use must be given.
pub struct Upload {
    /// The server API version to use.
    version: Version,

    /// The Send host to upload the file to.
    host: Url,

    /// The file to upload.
    path: PathBuf,

    /// The name of the file being uploaded.
    /// This has no relation to the file path, and will become the name of the
    /// shared file if set.
    name: Option<String>,

    /// An optional password to protect the file with.
    password: Option<String>,

    /// Optional file parameters to set.
    params: Option<ParamsData>,
}

impl Upload {
    /// Construct a new upload action.
    pub fn new(
        version: Version,
        host: Url,
        path: PathBuf,
        name: Option<String>,
        password: Option<String>,
        params: Option<ParamsData>,
    ) -> Self {
        Self {
            version,
            host,
            path,
            name,
            password,
            params,
        }
    }

    /// Invoke the upload action.
    pub fn invoke(
        self,
        client: &Client,
        reporter: Option<&Arc<Mutex<dyn ProgressReporter>>>,
    ) -> Result<RemoteFile, Error> {
        // Create file data, generate a key
        let file = FileData::from(&self.path)?;
        let key = KeySet::generate(true);

        // Create the file reader
        let reader = self.create_reader(&key, reporter.cloned())?;
        let reader_len = reader.len_in() as u64;

        // Start the reporter
        if let Some(reporter) = reporter {
            reporter
                .lock()
                .map_err(|_| UploadError::Progress)?
                .start(reader_len);
        }

        // Execute the request
        let (result, nonce) = match self.version {
            #[cfg(feature = "send2")]
            Version::V2 => self.upload_send2(client, &key, &file, reader)?,
            #[cfg(feature = "send3")]
            Version::V3 => self.upload_send3(client, &key, &file, reader)?,
        };

        // Mark the reporter as finished
        if let Some(reporter) = reporter {
            reporter.lock().map_err(|_| UploadError::Progress)?.finish();
        }

        // Change the password if set
        if let Some(password) = self.password {
            Password::new(&result, &password, nonce.clone()).invoke(client)?;
        }

        // Change parameters if any non-default, are already set with upload for Send v3
        #[cfg(feature = "send2")]
        {
            #[allow(unreachable_patterns)]
            match self.version {
                Version::V2 => {
                    if let Some(mut params) = self.params {
                        params.normalize(self.version);
                        if !params.is_empty() {
                            Params::new(&result, params, nonce.clone()).invoke(client)?;
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(result)
    }

    /// Create a blob of encrypted metadata, used in Firefox Send v2.
    #[cfg(feature = "send2")]
    fn create_metadata(&self, key: &KeySet, file: &FileData) -> Result<Vec<u8>, MetaError> {
        // Determine what filename to use
        let name = self.name.clone().unwrap_or_else(|| file.name().to_owned());

        // Construct the metadata
        let metadata = Metadata::from_send2(key.iv(), name, &file.mime())
            .to_json()
            .into_bytes();

        // Encrypt the metadata
        let mut metadata_tag = vec![0u8; 16];
        let mut metadata = match encrypt_aead(
            KeySet::cipher(),
            key.meta_key().unwrap(),
            Some(&[0u8; 12]),
            &[],
            &metadata,
            &mut metadata_tag,
        ) {
            Ok(metadata) => metadata,
            Err(_) => return Err(MetaError::Encrypt),
        };

        // Append the encryption tag
        metadata.append(&mut metadata_tag);

        Ok(metadata)
    }

    /// Create file info to send to the server, used for Firefox Send v3.
    #[cfg(feature = "send3")]
    fn create_file_info(&self, key: &KeySet, file: &FileData) -> Result<String, MetaError> {
        // Determine what filename to use, build the metadata
        let name = self.name.clone().unwrap_or_else(|| file.name().to_owned());

        // Construct the metadata
        let mime = format!("{}", file.mime());
        let metadata = Metadata::from_send3(name, mime, file.size())
            .to_json()
            .into_bytes();

        // Encrypt the metadata
        let mut metadata_tag = vec![0u8; 16];
        let mut metadata = match encrypt_aead(
            KeySet::cipher(),
            key.meta_key().unwrap(),
            Some(&[0u8; 12]),
            &[],
            &metadata,
            &mut metadata_tag,
        ) {
            Ok(metadata) => metadata,
            Err(_) => return Err(MetaError::Encrypt),
        };

        // Append the encryption tag
        metadata.append(&mut metadata_tag);

        // Get the expiry time and donwload limit
        let expiry = self.params.as_ref().and_then(|p| p.expiry_time);
        let downloads = self.params.as_ref().and_then(|p| p.download_limit);

        // Build file info for this metadata and return it as JSON
        Ok(FileInfo::from(expiry, downloads, b64::encode(&metadata), key).to_json())
    }

    /// Create a reader that reads the file as encrypted stream.
    fn create_reader(
        &self,
        key: &KeySet,
        reporter: Option<Arc<Mutex<dyn ProgressReporter>>>,
    ) -> Result<Reader, Error> {
        // Open the file
        let file = match File::open(self.path.as_path()) {
            Ok(file) => file,
            Err(err) => return Err(FileError::Open(err).into()),
        };

        // Get the file length
        let len = file
            .metadata()
            .expect("failed to fetch file metadata")
            .len();

        // Build the progress pipe file reader
        let progress = ProgressPipe::zero(len, reporter);
        let reader = progress.reader(Box::new(file));

        // Build the encrypting file reader
        match self.version {
            #[cfg(feature = "send2")]
            Version::V2 => {
                let encrypt = GcmCrypt::encrypt(len as usize, key.file_key().unwrap(), key.iv());
                let reader = encrypt.reader(Box::new(reader));
                Ok(Reader::new(Box::new(reader)))
            }
            #[cfg(feature = "send3")]
            Version::V3 => {
                let ikm = key.secret().to_vec();
                let encrypt = EceCrypt::encrypt(len as usize, ikm, None);
                let reader = encrypt.reader(Box::new(reader));
                Ok(Reader::new(Box::new(reader)))
            }
        }
    }

    /// Upload the file to the server, used in Firefox Send v2.
    #[cfg(feature = "send2")]
    fn upload_send2(
        &self,
        client: &Client,
        key: &KeySet,
        file: &FileData,
        reader: Reader,
    ) -> Result<(RemoteFile, Option<Vec<u8>>), Error> {
        // Create metadata
        let metadata = self.create_metadata(&key, file)?;

        // Create the request to send
        let req = self.create_request_send2(client, &key, &metadata, reader)?;

        // Execute the request
        self.execute_request_send2(req, client, &key)
            .map_err(|e| e.into())
    }

    /// Build the request that will be send to the server, used in Firefox Send v2.
    #[cfg(feature = "send2")]
    fn create_request_send2(
        &self,
        client: &Client,
        key: &KeySet,
        metadata: &[u8],
        reader: Reader,
    ) -> Result<Request, UploadError> {
        // Get the reader output length
        let len = reader.len_out() as u64;

        // Configure a form to send
        let part = Part::reader_with_length(reader, len)
            .mime_str(APPLICATION_OCTET_STREAM.as_ref())
            .expect("failed to set request mime");
        let form = Form::new().part("data", part);

        // Define the URL to call
        let url = self.host.join("api/upload")?;

        // Build the request
        client
            .post(url.as_str())
            .header(
                AUTHORIZATION.as_str(),
                format!("send-v1 {}", key.auth_key_encoded().unwrap()),
            )
            .header("X-File-Metadata", b64::encode(&metadata))
            .multipart(form)
            .build()
            .map_err(|_| UploadError::Request)
    }

    /// Execute the given request, and create a file object that represents the
    /// uploaded file, used in Firefox Send v2.
    #[cfg(feature = "send2")]
    fn execute_request_send2(
        &self,
        req: Request,
        client: &Client,
        key: &KeySet,
    ) -> Result<(RemoteFile, Option<Vec<u8>>), UploadError> {
        // Execute the request
        let mut response = match client.execute(req) {
            Ok(response) => response,
            // TODO: attach the error context
            Err(_) => return Err(UploadError::Request),
        };

        // Ensure the response is successful
        ensure_success(&response).map_err(UploadError::Response)?;

        // Try to get the nonce, don't error on failure
        let nonce = header_nonce(&response).ok();

        // Decode the response
        let response: UploadResponse = match response.json() {
            Ok(response) => response,
            Err(err) => return Err(UploadError::Decode(err)),
        };

        // Transform the responce into a file object
        Ok((response.into_file(self.host.clone(), &key, None)?, nonce))
    }

    /// Upload the file to the server, used in Firefox Send v3.
    #[cfg(feature = "send3")]
    fn upload_send3(
        &self,
        client: &Client,
        key: &KeySet,
        file_data: &FileData,
        mut reader: Reader,
    ) -> Result<(RemoteFile, Option<Vec<u8>>), Error> {
        // Build the uploading websocket URL
        let ws_url = self
            .host
            .join("api/ws")
            .map_err(|e| Error::Upload(e.into()))?;

        // Build the websocket client used for uploading
        let mut client = client
            .websocket(ws_url.as_str())
            .map_err(|_| Error::Upload(UploadError::Request))?;

        // Create file info to sent when uploading
        let file_info = self
            .create_file_info(&key, file_data)
            .map_err(|e| -> Error { e.into() })?;
        let ws_metadata = OwnedMessage::Text(file_info);
        client
            .send_message(&ws_metadata)
            .map_err(|e| Error::Upload(e.into()))?;

        // Read the upload initialization response from the server
        let result = client
            .recv_message()
            .map_err(|_| Error::Upload(UploadError::InvalidResponse))?;
        let upload_response: UploadResponse = match result {
            OwnedMessage::Text(ref data) => serde_json::from_str(data)
                .map_err(|_| Error::Upload(UploadError::InvalidResponse))?,
            _ => return Err(UploadError::InvalidResponse.into()),
        };

        // Read the header part, and send it
        let mut header = vec![0u8; ece::HEADER_LEN as usize];
        reader
            .read_exact(&mut header)
            .expect("failed to read header from reader");
        client
            .send_message(&OwnedMessage::Binary(header))
            .map_err(|e| Error::Upload(e.into()))?;

        // Send the whole encrypted file in chunks as binary websocket messages
        let result =
            reader
                .chunks(ece::RS as usize)
                .fold(None, |result: Option<UploadError>, chunk| {
                    // Skip if an error occurred
                    if result.is_some() {
                        return result;
                    }

                    // Send the message, capture errors
                    let message = OwnedMessage::Binary(chunk.expect("invalid chunk"));
                    client.send_message(&message).err().map(|e| e.into())
                });
        if let Some(err) = result {
            return Err(err.into());
        }

        // Send the file footer
        client
            .send_message(&OwnedMessage::Binary(vec![0]))
            .map_err(|e| Error::Upload(e.into()))?;

        // Make sure we receive a success message from the server
        let status = match client
            .recv_message()
            .map_err(|_| Error::Upload(UploadError::InvalidResponse))?
        {
            OwnedMessage::Text(status) => Some(status),
            _ => None,
        };
        let ok = status
            .and_then(|s| serde_json::from_str::<UploadStatusResponse>(&s).ok())
            .map(|s| s.is_ok())
            .unwrap_or(false);
        if !ok {
            return Err(UploadError::Response(ResponseError::Undefined).into());
        }

        // Done uploading, explicitly close upload client
        let _ = client.shutdown();
        mem::drop(client);

        // Construct the remote file from the data we've obtained
        let remote_file = upload_response.into_file(
            self.host.clone(),
            &key,
            self.params.as_ref().and_then(|p| {
                p.expiry_time
                    .map(|s| Utc::now() + Duration::seconds(s as i64))
            }),
        )?;

        Ok((remote_file, None))
    }
}

/// The response from the server after a file has been uploaded.
/// This response contains the file ID and owner key, to manage the file.
///
/// It also contains the download URL, although an additional secret is
/// required.
///
/// The download URL can be generated using `download_url()` which will
/// include the required secret in the URL.
#[derive(Debug, Deserialize)]
struct UploadResponse {
    /// The file ID.
    id: String,

    /// The URL the file is reachable at.
    /// This includes the file ID, but does not include the secret.
    url: String,

    /// The owner key, used to do further file modifications.
    ///
    /// Called `owner` in Firefox Send v2, and `ownerToken` in Firefox Send v3.
    #[serde(alias = "ownerToken", alias = "owner")]
    owner_token: String,
}

impl UploadResponse {
    /// Convert this response into a file object.
    ///
    /// The `host` and `key` must be given.
    pub fn into_file(
        self,
        host: Url,
        key: &KeySet,
        expiry_time: Option<DateTime<Utc>>,
    ) -> Result<RemoteFile, UploadError> {
        Ok(RemoteFile::new(
            self.id,
            Some(Utc::now()),
            expiry_time,
            host,
            Url::parse(&self.url)?,
            key.secret().to_vec(),
            Some(self.owner_token),
        ))
    }
}

/// The status response from the server over the websocket during or after uploading.
/// This defines whether uploading was successful.
#[derive(Debug, Deserialize)]
#[cfg(feature = "send3")]
struct UploadStatusResponse {
    /// True if ok, false if not.
    ok: bool,
}

#[cfg(feature = "send3")]
impl UploadStatusResponse {
    /// Check if OK.
    pub fn is_ok(&self) -> bool {
        self.ok
    }
}

/// A struct that holds various file properties, such as it's name and it's
/// mime type.
struct FileData<'a> {
    /// The file name.
    name: &'a str,

    /// The file mime type.
    mime: Mime,

    /// The file size.
    #[allow(unused)]
    size: u64,
}

impl<'a> FileData<'a> {
    /// Create a file data object, from the file at the given path.
    pub fn from(path: &'a PathBuf) -> Result<Self, FileError> {
        // Make sure the given path is a file
        if !path.is_file() {
            return Err(FileError::NotAFile);
        }

        // Get the file name
        let name = match path.file_name() {
            Some(name) => name.to_str().unwrap_or("file"),
            None => "file",
        };

        // Get the file size
        let size = path.metadata()?.len();

        Ok(Self {
            name,
            mime: mime_guess::from_path(path).first_or_octet_stream(),
            size,
        })
    }

    /// Get the file name.
    pub fn name(&self) -> &str {
        self.name
    }

    /// Get the file mime type.
    pub fn mime(&self) -> &Mime {
        &self.mime
    }

    /// Get the file size in bytes.
    #[cfg(feature = "send3")]
    pub fn size(&self) -> u64 {
        self.size
    }
}

/// A wrapped reader to make it easier to pass around.
struct Reader {
    // TODO: use better type
    inner: Box<dyn ReadLen>,
}

impl Reader {
    /// Construct a new wrapped reader.
    pub fn new(inner: Box<dyn ReadLen>) -> Self {
        Self { inner }
    }
}

impl Read for Reader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl PipeLen for Reader {
    fn len_in(&self) -> usize {
        self.inner.len_in()
    }

    fn len_out(&self) -> usize {
        self.inner.len_out()
    }
}

#[derive(Fail, Debug)]
pub enum Error {
    /// An error occurred while preparing a file for uploading.
    #[fail(display = "failed to prepare uploading the file")]
    Prepare(#[cause] PrepareError),

    /// An error occurred while opening, reading or using the file that
    /// the should be uploaded.
    // TODO: maybe append the file path here for further information
    #[fail(display = "")]
    File(#[cause] FileError),

    /// An error occurred while uploading the file.
    #[fail(display = "failed to upload the file")]
    Upload(#[cause] UploadError),

    /// An error occurred while chaining file parameters.
    #[fail(display = "failed to change file parameters")]
    Params(#[cause] ParamsError),

    /// An error occurred while setting the password.
    #[fail(display = "failed to set the password")]
    Password(#[cause] PasswordError),
}

impl From<MetaError> for Error {
    fn from(err: MetaError) -> Error {
        Error::Prepare(PrepareError::Meta(err))
    }
}

impl From<FileError> for Error {
    fn from(err: FileError) -> Error {
        Error::File(err)
    }
}

impl From<ReaderError> for Error {
    fn from(err: ReaderError) -> Error {
        Error::Prepare(PrepareError::Reader(err))
    }
}

impl From<UploadError> for Error {
    fn from(err: UploadError) -> Error {
        Error::Upload(err)
    }
}

impl From<ParamsError> for Error {
    fn from(err: ParamsError) -> Error {
        Error::Params(err)
    }
}

impl From<PasswordError> for Error {
    fn from(err: PasswordError) -> Error {
        Error::Password(err)
    }
}

#[derive(Fail, Debug)]
pub enum PrepareError {
    /// Failed to prepare the file metadata for uploading.
    #[fail(display = "failed to prepare file metadata")]
    Meta(#[cause] MetaError),

    /// Failed to create an encrypted file reader, that encrypts
    /// the file on the fly when it is read.
    #[fail(display = "failed to access the file to upload")]
    Reader(#[cause] ReaderError),

    /// Failed to create a client for uploading a file.
    #[fail(display = "failed to create uploader client")]
    Client,
}

#[derive(Fail, Debug)]
pub enum MetaError {
    /// An error occurred while encrypting the file metadata.
    #[fail(display = "failed to encrypt file metadata")]
    Encrypt,
}

#[derive(Fail, Debug)]
pub enum ReaderError {
    /// An error occurred while creating the file encryptor.
    #[fail(display = "failed to create file encryptor")]
    Encrypt,

    /// Failed to create the progress reader, attached to the file reader,
    /// to measure the uploading progress.
    #[fail(display = "failed to create progress reader")]
    Progress,
}

#[derive(Fail, Debug)]
pub enum FileError {
    /// The given path, is not not a file or doesn't exist.
    #[fail(display = "the given path is not an existing file")]
    NotAFile,

    /// Failed to open the file that must be uploaded for reading.
    #[fail(display = "failed to open the file to upload")]
    Open(#[cause] IoError),
}

impl From<IoError> for FileError {
    fn from(err: IoError) -> FileError {
        FileError::Open(err)
    }
}

#[derive(Fail, Debug)]
pub enum UploadError {
    /// Failed to start or update the uploading progress, because of this the
    /// upload can't continue.
    #[fail(display = "failed to update upload progress")]
    Progress,

    /// Sending the request to upload the file failed.
    #[fail(display = "failed to request file upload")]
    Request,

    /// An error occurred while streaming the encrypted file (including file info, header and
    /// footer) for uploading over a websocket.
    #[fail(display = "failed to stream file for upload over websocket")]
    #[cfg(feature = "send3")]
    UploadStream(#[cause] WebSocketError),

    /// The server responded with data that was not understood, or did not respond at all while a
    /// response was espected.
    #[fail(display = "got invalid response from server")]
    InvalidResponse,

    /// The server responded with an error for uploading.
    #[fail(display = "bad response from server for uploading")]
    Response(#[cause] ResponseError),

    /// Failed to decode the upload response from the server.
    /// Maybe the server responded with data from a newer API version.
    #[fail(display = "failed to decode upload response")]
    Decode(#[cause] ReqwestError),

    /// Failed to parse the retrieved URL from the upload response.
    #[fail(display = "failed to parse received URL")]
    ParseUrl(#[cause] UrlParseError),
}

#[cfg(feature = "send3")]
impl From<WebSocketError> for UploadError {
    fn from(err: WebSocketError) -> UploadError {
        UploadError::UploadStream(err)
    }
}

impl From<ResponseError> for UploadError {
    fn from(err: ResponseError) -> UploadError {
        UploadError::Response(err)
    }
}

impl From<UrlParseError> for UploadError {
    fn from(err: UrlParseError) -> UploadError {
        UploadError::ParseUrl(err)
    }
}
