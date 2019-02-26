extern crate mime;

use std::fs::File;
use std::io::{self, BufReader, Error as IoError, Read};
use std::mem;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use self::mime::APPLICATION_OCTET_STREAM;
use mime_guess::{guess_mime_type, Mime};
use openssl::symm::encrypt_aead;
use reqwest::header::AUTHORIZATION;
use reqwest::multipart::{Form, Part};
use reqwest::{Client, Error as ReqwestError, Request};
use serde_json;
use url::{ParseError as UrlParseError, Url};

use super::params::{Error as ParamsError, Params, ParamsData};
use super::password::{Error as PasswordError, Password};
use crate::api::nonce::header_nonce;
use crate::api::request::{ensure_success, ResponseError};
use crate::crypto::b64;
use crate::crypto::key_set::KeySet;
use crate::file::{
    info::FileInfo,
    metadata::Metadata,
};
use crate::file::remote_file::RemoteFile;
use crate::io::{Chunks, ChunkRead};
use crate::pipe::{
    crypto::{EceCrypt, GcmCrypt},
    progress::{ProgressPipe, ProgressReporter},
    prelude::*,
};

/// A file upload action to a Send server.
pub struct Upload {
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
        host: Url,
        path: PathBuf,
        name: Option<String>,
        password: Option<String>,
        params: Option<ParamsData>,
    ) -> Self {
        Self {
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
        reporter: Option<&Arc<Mutex<ProgressReporter>>>,
    ) -> Result<RemoteFile, Error> {
        // Create file data, generate a key
        let file = FileData::from(&self.path)?;
        let key = KeySet::generate(true);

        // Create metadata and a file reader
        let metadata = self.create_metadata(&key, &file)?;
        let mut reader = self.create_reader(&key, reporter.cloned())?;
        let reader_len = reader.len_in() as u64;

        // // create the request to send
        // let req = self.create_request(client, &key, &metadata, reader);

        // Start the reporter
        if let Some(reporter) = reporter {
            reporter
                .lock()
                .map_err(|_| UploadError::Progress)?
                .start(reader_len);
        }



        use websocket::{ClientBuilder, Message, OwnedMessage};

        // TODO: define endpoint in constant
        let ws_url = self.host.join("api/ws").expect("invalid host");

        let mut ws_client = ClientBuilder::new(ws_url.as_str())
            .expect("failed to set up websocket builder")
            .add_protocol("rust-websocket")
            // What is this for?
            .connect_insecure()
            .expect("failed to build websocket client");

        let file_info = self.create_file_info(&key, &file).expect("failed to create file info for upload");
        let ws_metadata = OwnedMessage::Text(file_info);
        ws_client.send_message(&ws_metadata).expect("failed to send metadata message");

        eprintln!("### receiving result");
        // TODO: handle error results
        let result = ws_client.recv_message().expect("failed to read result");
        let upload_response: UploadResponse = match result {
            OwnedMessage::Text(ref data) => serde_json::from_str(data)
                .expect("failed to deserialize upload request response"),
            _ => panic!("failed to request file upload"),
        };
        eprintln!("GOT FROM SERVER: {:?}", &upload_response);

        eprintln!("### starting upload");

        // Read the header chunk and send it
        // TODO: use size from constant
        let mut header = vec![0u8; 21];
        reader.read_exact(&mut header).expect("failed to read header from reader");
        ws_client.send_message(
            &OwnedMessage::Binary(header),
        ).expect("failed to send header chunk");

        // TODO: do not use hard coded value
        reader.chunks(64 * 1024).enumerate().for_each(|(i, chunk)| {
            let chunk = chunk.expect("invalid chunk");

            eprintln!("Sending chunk #{} of {} bytes", i, chunk.len());

            ws_client.send_message(
                &OwnedMessage::Binary(chunk),
            ).expect("failed to send chunk");

            // TODO: check if we received an error message
        });

        // Send the file footer
        ws_client.send_message(
            &OwnedMessage::Binary(vec![0]),
        ).expect("failed to send chunk");

        eprintln!("### done uploading");

        // Assert OK! {"ok":true}
        let result = ws_client.recv_message().expect("failed to get resonse");
        eprintln!("RESULT: {:?}", result);

        // Done uploading, close upload client
        ws_client.shutdown().expect("failed to close websocket");
        mem::drop(ws_client);

        let remote_file = upload_response.into_file(self.host.clone(), &key)
            .expect("failed to build remote file");
        return Ok(remote_file);



        // // Execute the request
        // let (result, nonce) = self.execute_request(req, client, &key)?;

        // // Mark the reporter as finished
        // if let Some(reporter) = reporter {
        //     reporter.lock().map_err(|_| UploadError::Progress)?.finish();
        // }

        // // Change the password if set
        // if let Some(password) = self.password {
        //     Password::new(&result, &password, nonce.clone()).invoke(client)?;
        // }

        // // Change parameters if set
        // if let Some(params) = self.params {
        //     Params::new(&result, params, nonce.clone()).invoke(client)?;
        // }

        // Ok(result)
    }

    /// Create a blob of encrypted metadata.
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
    #[cfg(feature = "send2")]
    fn create_file_info(&self, key: &KeySet, file: &FileData) -> Result<String, MetaError> {
        // Determine what filename to use, build the metadata
        let name = self.name.clone().unwrap_or_else(|| file.name().to_owned());
        //let metadata = Metadata::from_send2(name, file.mime(), file.size());



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



        // TODO: use proper expire and download count configuration here
        let info = FileInfo::from(None, Some(1), b64::encode(&metadata), key);

        Ok(info.to_json())
    }

    /// Create a reader that reads the file as encrypted stream.
    fn create_reader(
        &self,
        key: &KeySet,
        reporter: Option<Arc<Mutex<ProgressReporter>>>,
    ) -> Result<impl Read + PipeLen, Error> {
        // Open the file
        let file = match File::open(self.path.as_path()) {
            Ok(file) => file,
            Err(err) => return Err(FileError::Open(err).into()),
        };

        // TODO: remove old code
        // // Create an encrypted reader
        // let reader = match EncryptedFileReader::new(
        //     file,
        //     KeySet::cipher(),
        //     key.file_key().unwrap(),
        //     key.iv(),
        // ) {
        //     Ok(reader) => reader,
        //     Err(_) => return Err(ReaderError::Encrypt.into()),
        // };

        // // Wrap into the encrypted reader
        // let mut reader = ProgressReader::new(reader).map_err(|_| ReaderError::Progress)?;

        // Get the file length
        let len = file.metadata().expect("failed to fetch file metadata").len();

        // Build the progress pipe file reader
        let progress = ProgressPipe::zero(len, reporter);
        let reader = progress.reader(Box::new(file));

        let ikm = key.secret().to_vec();

        // Build the encrypting file reader
        // let encrypt = GcmCrypt::encrypt(len as usize, key.file_key().unwrap(), key.iv());
        let encrypt = EceCrypt::encrypt(len as usize, ikm, None);
        let reader = encrypt.reader(Box::new(reader));

        Ok(reader)
    }

    /// Build the request that will be send to the server.
    fn create_request<R>(
        &self,
        client: &Client,
        key: &KeySet,
        metadata: &[u8],
        reader: R,
    ) -> Request
        where R: Read + PipeLen + Send + 'static,
    {
        // Get the reader output length
        let len = reader.len_out() as u64;

        // Configure a form to send
        let part = Part::reader_with_length(reader, len)
            .mime_str(APPLICATION_OCTET_STREAM.as_ref())
            .expect("failed to set request mime");
        let form = Form::new().part("data", part);

        // Define the URL to call
        // TODO: define endpoint in constant
        // TODO: create an error for this unwrap
        let url = self.host.join("api/upload").expect("invalid host");

        // Build the request
        // TODO: create an error for this unwrap
        client
            .post(url.as_str())
            .header(
                AUTHORIZATION.as_str(),
                format!("send-v1 {}", key.auth_key_encoded().unwrap()),
            )
            .header("X-File-Metadata", b64::encode(&metadata))
            .multipart(form)
            .build()
            .expect("failed to build an API request")
    }

    /// Execute the given request, and create a file object that represents the
    /// uploaded file.
    fn execute_request(
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
        Ok((response.into_file(self.host.clone(), &key)?, nonce))
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
    pub fn into_file(self, host: Url, key: &KeySet) -> Result<RemoteFile, UploadError> {
        Ok(RemoteFile::new_now(
            self.id,
            host,
            Url::parse(&self.url)?,
            key.secret().to_vec(),
            Some(self.owner_token),
        ))
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
        // TODO: do not unwrap here, handle error
        let size = path.metadata().expect("failed to determine file length").len();

        Ok(Self {
            name,
            mime: guess_mime_type(path),
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
    pub fn size(&self) -> u64 {
        self.size
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

#[derive(Fail, Debug)]
pub enum UploadError {
    /// Failed to start or update the uploading progress, because of this the
    /// upload can't continue.
    #[fail(display = "failed to update upload progress")]
    Progress,

    /// Sending the request to upload the file failed.
    #[fail(display = "failed to request file upload")]
    Request,

    /// The server responded with an error while uploading.
    #[fail(display = "bad response from server while uploading")]
    Response(#[cause] ResponseError),

    /// Failed to decode the upload response from the server.
    /// Maybe the server responded with data from a newer API version.
    #[fail(display = "failed to decode upload response")]
    Decode(#[cause] ReqwestError),

    /// Failed to parse the retrieved URL from the upload response.
    #[fail(display = "failed to parse received URL")]
    ParseUrl(#[cause] UrlParseError),
}

impl From<UrlParseError> for UploadError {
    fn from(err: UrlParseError) -> UploadError {
        UploadError::ParseUrl(err)
    }
}
