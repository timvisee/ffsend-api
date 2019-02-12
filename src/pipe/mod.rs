//! Provides IO stream pipe functionality.
//!
//! This module provides piping functionality for IO streams implementing `Read` or `Write`.
//! A pipe can be used to wrap an existing reader or writer, monitoring or transforming data read
//! from or written to it.
//!
//! You may use a pipe for archiving (zipping) or to encrypt/decrypt bytes flowing through the
//! pipe reader or writer.

pub mod crypto;
pub mod progress;
mod traits;

// Re-export modules
pub use progress::{ProgressPipe, ProgressReader, ProgressWriter, ProgressReporter};
pub use traits::{Pipe, PipeRead, PipeWrite, PipeLen};

/// Prelude for common pipe traits.
pub mod prelude {
    pub use super::{
        crypto::prelude::*,
        Pipe,
        PipeRead,
        PipeWrite,
        PipeLen,
    };
}

/// The default size of byte buffers.
const DEFAULT_BUF_SIZE: usize = 8 * 1024;
