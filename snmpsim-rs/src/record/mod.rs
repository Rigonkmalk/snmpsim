//! Record types for simulation data files.
//!
//! Each record type understands how to parse a file line into a typed
//! (Oid, SnmpValue) pair, and how to format back.

pub mod snmprec;
pub mod walk;
pub mod dump;

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::error::Result;
use crate::grammar::Grammar;
use crate::oid::Oid;
use crate::snmp_value::SnmpValue;

/// The context in which a record is being evaluated.
#[derive(Debug, Clone, Default)]
pub struct EvalContext {
    /// True if this is a GET-NEXT operation.
    pub next_flag: bool,
    /// True if this is a SET operation.
    pub set_flag: bool,
    /// True if the OID was an exact match in the index.
    pub exact_match: bool,
    /// True if the matched record serves a subtree.
    pub subtree_flag: bool,
    /// The original OID from the request.
    pub orig_oid: Option<Oid>,
    /// The path to the data file being accessed.
    pub data_file: String,
    /// Only parse the OID, skip value evaluation.
    pub oid_only: bool,
}

/// Trait for simulation data record types (.snmprec, .dump, .walk, etc.).
pub trait Record: Send + Sync {
    /// Return a reference to this record type's grammar.
    fn grammar(&self) -> &dyn Grammar;

    /// Return the file extension for this record type (without leading dot).
    fn extension(&self) -> &str;

    /// Parse an OID string into a typed Oid.
    fn evaluate_oid(&self, oid_str: &str) -> Result<Oid>;

    /// Parse a (tag, value) string pair into a typed SnmpValue.
    fn evaluate_value(&self, oid: &Oid, tag: &str, value: &str, ctx: &EvalContext) -> Result<SnmpValue>;

    /// Parse a full data file line into (Oid, SnmpValue).
    fn evaluate(&self, line: &[u8], ctx: &EvalContext) -> Result<(Oid, Option<SnmpValue>)>;

    /// Format an OID for output.
    fn format_oid(&self, oid: &Oid) -> String;

    /// Format a value for output.
    fn format_value(&self, oid: &Oid, value: &SnmpValue) -> (String, String, String);

    /// Build a record line from (oid, value).
    fn format(&self, oid: &Oid, value: &SnmpValue) -> Result<Vec<u8>> {
        let (fmt_oid, tag, val) = self.format_value(oid, value);
        self.grammar().build(&fmt_oid, &tag, &val)
    }

    /// Open a data file for reading. Default: plain binary open.
    fn open(&self, path: &Path) -> Result<Box<dyn Read>> {
        let f = File::open(path)?;
        Ok(Box::new(BufReader::new(f)))
    }
}
