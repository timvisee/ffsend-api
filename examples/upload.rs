use std::path::PathBuf;

use ffsend_api::{
    action::upload::Error, action::upload::Upload, api::Version, client::ClientConfigBuilder,
    file::remote_file::RemoteFile,
};
use url::Url;

fn main() {
    // Upload the given file, get and report it's share URL
    let url = upload_file(PathBuf::from("./README.md"))
        .expect("failed to upload file")
        .download_url(true);
    println!("Share URL: {}", url);
}

/// Upload the file at the given path. Returns uploaded file on success.
fn upload_file(path: PathBuf) -> Result<RemoteFile, Error> {
    // Build the client for uploading
    let client_config = ClientConfigBuilder::default().build().unwrap();
    let client = client_config.client(true);

    // Build upload action, and invoke to upload
    let upload = Upload::new(
        Version::V3,
        Url::parse("https://send.firefox.com/").unwrap(),
        path,
        None,
        None,
        None,
    );
    Upload::invoke(upload, &client, None)
}
