pub mod crypto;
mod pipe;

// Re-export modules
pub use pipe::{Pipe, PipeRead, PipeWrite, PipeLen};

// Re-export common traits for prelude
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
