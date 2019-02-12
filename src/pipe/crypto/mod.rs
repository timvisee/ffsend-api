mod crypt;
mod ece;
mod gcm;

// Re-export modules
pub use crypt::{Crypt, CryptMode};
pub use self::ece::{EceCrypt, EceReader, EceWriter};
pub use gcm::{GcmCrypt, GcmReader, GcmWriter};

// Re-export common traits for prelude
pub mod prelude {
    pub use super::Crypt;
}
