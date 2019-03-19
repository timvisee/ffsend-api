use std::time::Duration;

use reqwest::{self, IntoUrl};

/// A networking client for ffsend actions.
pub struct Client {
    /// The client configuration to use for built reqwest clients.
    config: ClientConfig,

    /// The inner reqwest client.
    reqwest: reqwest::Client,
}

impl Client {
    /// Construct the ffsend client with the given `config`.
    ///
    /// If this client is used for transfering files, `transfer` should be true.
    // TODO: properly handle errors, do not unwrap
    pub fn new(config: ClientConfig, transfer: bool) -> Self {
        // Set up the reqwest client
        let mut builder = reqwest::ClientBuilder::new();
        match config.timeout {
            Some(timeout) if !transfer => builder = builder.timeout(timeout),
            _ => {},
        }
        match config.transfer_timeout {
            Some(timeout) if transfer => builder = builder.timeout(timeout),
            _ => {},
        }
        let reqwest = builder.build()
            .expect("failed to build reqwest client");

        // Build the client
        Self {
            config,
            reqwest,
        }
    }

    /// Create a HTTP GET request through this client, returning a `RequestBuilder`.
    pub fn get<U: IntoUrl>(&self, url: U) -> reqwest::RequestBuilder {
        self.configure(self.reqwest.get(url))
    }

    /// Create a HTTP GET request through this client, returning a `RequestBuilder`.
    pub fn post<U: IntoUrl>(&self, url: U) -> reqwest::RequestBuilder {
        self.configure(self.reqwest.post(url))
    }

    /// Configure the given reqwest client to match the configuration.
    fn configure(&self, mut client: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        // Configure basic HTTP authentication
        if let Some((user, password)) = &self.config.basic_auth {
            client = client.basic_auth(user, password.to_owned());
        }

        client
    }
}

/// Configurable properties for networking client used for ffsend actions.
#[derive(Clone, Debug, Builder)]
pub struct ClientConfig {
    /// Connection timeout for control requests.
    timeout: Option<Duration>,

    /// Connection timeout specific to file transfers.
    transfer_timeout: Option<Duration>,

    /// Basic HTTP authentication credentials.
    ///
    /// Consists of a username, and an optional password.
    basic_auth: Option<(String, Option<String>)>,

    // TODO: proxy settings
}

impl ClientConfig {
    /// Construct a ffsend client based on this configuration.
    ///
    /// If this client is used for transfering files, `transfer` should be true.
    pub fn client(self, transfer: bool) -> Client {
        Client::new(self, transfer)
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            timeout: None,
            transfer_timeout: None,
            basic_auth: None,
        }
    }
}
