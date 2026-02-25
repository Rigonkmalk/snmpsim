//! Grammar for .dump file format (legacy SNMP dump format).
//!
//! Format similar to snmprec but with different type tags.

use crate::error::{Result, SnmpsimError};
use crate::grammar::Grammar;

/// Grammar for .dump format files.
pub struct DumpGrammar;

impl DumpGrammar {
    pub fn new() -> Self {
        DumpGrammar
    }
}

impl Default for DumpGrammar {
    fn default() -> Self {
        DumpGrammar::new()
    }
}

impl Grammar for DumpGrammar {
    /// Parse a .dump line into (oid, tag, value).
    /// Format is identical to snmprec: OID|tag|value
    fn parse(&self, line: &[u8]) -> Result<(String, String, String)> {
        let line_str = std::str::from_utf8(line)
            .map_err(|e| SnmpsimError::Parse(format!("Non-UTF8 line: {}", e)))?
            .trim();

        let parts: Vec<&str> = line_str.splitn(3, '|').collect();
        if parts.len() != 3 {
            return Err(SnmpsimError::Parse(format!(
                "Broken .dump record: {:?}",
                line_str
            )));
        }

        let oid = parts[0].trim().to_string();
        let tag = parts[1].trim().to_string();
        let value = parts[2].to_string();

        if oid.is_empty() || tag.is_empty() {
            return Err(SnmpsimError::Parse(format!(
                "Empty OID or tag in .dump record: {:?}",
                line_str
            )));
        }

        Ok((oid, tag, value))
    }

    fn build(&self, oid: &str, tag: &str, val: &str) -> Result<Vec<u8>> {
        if oid.is_empty() || tag.is_empty() {
            return Err(SnmpsimError::Parse(format!(
                "Empty OID/tag: <{}/{}>",
                oid, tag
            )));
        }
        let line = format!("{}|{}|{}\n", oid, tag, val);
        Ok(line.into_bytes())
    }
}
