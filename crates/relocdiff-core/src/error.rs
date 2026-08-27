use thiserror::Error;

/// Errors returned by PE parsing and binary analysis.
#[derive(Debug, Error)]
pub enum Error {
    /// The input does not contain a valid supported PE image.
    #[error("invalid PE image: {0}")]
    InvalidPe(String),
    /// The image uses an unsupported architecture or PE mode.
    #[error("unsupported image: {0}")]
    Unsupported(String),
    /// The requested address is outside executable code.
    #[error("{0:#x} is outside executable sections")]
    OutsideCode(u64),
    /// The requested address is not part of a recovered function.
    #[error("{0:#x} is not part of a recoverable function")]
    NoFunction(u64),
    /// The function contains bytes that cannot be decoded safely.
    #[error("decode error at {0:#x}")]
    Decode(u64),
    /// The input is not a valid relocdiff analysis index.
    #[error("invalid analysis index: {0}")]
    InvalidIndex(String),
}

/// A result returned by this crate.
pub type Result<T> = std::result::Result<T, Error>;
