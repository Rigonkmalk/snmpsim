//! Grammar parsers for simulation data file formats.
//!
//! Each grammar module can parse a specific file format and produce
//! (oid_string, tag_string, value_string) triples.

pub mod snmprec;
pub mod walk;
pub mod dump;

use crate::error::Result;

/// Trait for parsing a single line of a simulation data file.
pub trait Grammar: Send + Sync {
    /// Parse one data record line into (oid, tag, value) strings.
    fn parse(&self, line: &[u8]) -> Result<(String, String, String)>;

    /// Build a binary record from (oid, tag, value) strings.
    fn build(&self, oid: &str, tag: &str, val: &str) -> Result<Vec<u8>>;
}
