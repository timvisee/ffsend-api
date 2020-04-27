#[macro_use]
extern crate arrayref;
extern crate byteorder;
extern crate bytes;
#[macro_use]
extern crate derive_builder;
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate mime_guess;
// TODO: enable this attribute for selective compilation
// #[cfg(feature = "crypto-openssl")]
extern crate openssl;
pub extern crate reqwest;
#[cfg(feature = "crypto-ring")]
extern crate ring;
extern crate serde;
#[macro_use]
extern crate serde_derive;
extern crate serde_json;
extern crate time;
pub extern crate url;
extern crate version_compare;
#[cfg(feature = "send3")]
extern crate websocket;

pub mod action;
pub mod api;
pub mod client;
pub mod config;
pub mod crypto;
mod ext;
pub mod file;
#[cfg(feature = "send3")]
mod io;
pub mod pipe;

pub use failure::Error;
