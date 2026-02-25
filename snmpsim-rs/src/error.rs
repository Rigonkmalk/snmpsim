//! Error types for snmpsim-rs
//!
//! Mirrors the Python snmpsim.error module.

use std::io;

/// Top-level error type for all snmpsim errors.
#[derive(Debug, thiserror::Error)]
pub enum SnmpsimError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Parse error: {0}")]
    Parse(String),

    #[error("SNMP error: {0}")]
    Snmp(String),

    /// Raised when no data is available for a given OID (replaces NoDataNotification).
    #[error("No data available")]
    NoData,

    /// Raised when more data follows (replaces MoreDataNotification).
    #[error("More data: {message}")]
    MoreData { message: String },

    #[error("Index error: {0}")]
    Index(String),

    #[error("Variation module error: {0}")]
    Variation(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("BER encoding/decoding error: {0}")]
    Ber(String),
}

pub type Result<T> = std::result::Result<T, SnmpsimError>;
