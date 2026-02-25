//! Grammar for the .snmprec file format.
//!
//! Format: OID|tag|value
//! - OID: dotted decimal string, e.g. "1.3.6.1.2.1.1.1.0"
//! - tag: numeric string corresponding to SNMP type, optionally followed by
//!        'x' (hex-encoded) or 'e' (Python-escaped), and optionally followed
//!        by ':module_name' for variation module references.
//! - value: string representation of the value

use crate::error::{Result, SnmpsimError};
use crate::grammar::Grammar;

/// Grammar for .snmprec format files.
pub struct SnmprecGrammar;

impl SnmprecGrammar {
    pub fn new() -> Self {
        SnmprecGrammar
    }

    /// Unpack the encoding suffix from a tag string.
    /// Returns `(base_tag, encoding)` where encoding is `Some('x')`, `Some('e')` or `None`.
    pub fn unpack_tag(tag: &str) -> (&str, Option<char>) {
        if tag.ends_with('x') {
            (&tag[..tag.len() - 1], Some('x'))
        } else if tag.ends_with('e') {
            (&tag[..tag.len() - 1], Some('e'))
        } else {
            (tag, None)
        }
    }

    /// Split a tag into (type_tag, module_name) for variation module support.
    /// For "4:redis" returns ("4", Some("redis")).
    /// For "4x:delay" returns ("4x", Some("delay")).
    pub fn split_module(tag: &str) -> (&str, Option<&str>) {
        if let Some(colon_pos) = tag.find(':') {
            (&tag[..colon_pos], Some(&tag[colon_pos + 1..]))
        } else {
            (tag, None)
        }
    }

    /// Evaluate a Python-style escaped string (like ast.literal_eval).
    pub fn evaluate_escaped(s: &str) -> Result<Vec<u8>> {
        let mut out: Vec<u8> = Vec::new();
        let mut chars = s.chars().peekable();

        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c as u8);
                continue;
            }
            match chars.next() {
                None => {
                    return Err(SnmpsimError::Parse(
                        "Trailing backslash in escaped string".into(),
                    ))
                }
                Some('\\') => out.push(b'\\'),
                Some('\'') => out.push(b'\''),
                Some('"') => out.push(b'"'),
                Some('a') => out.push(0x07),
                Some('b') => out.push(0x08),
                Some('f') => out.push(0x0C),
                Some('n') => out.push(0x0A),
                Some('r') => out.push(0x0D),
                Some('t') => out.push(0x09),
                Some('v') => out.push(0x0B),
                Some('x') => {
                    let h1 = chars
                        .next()
                        .ok_or_else(|| SnmpsimError::Parse("Truncated \\x escape".into()))?;
                    let h2 = chars
                        .next()
                        .ok_or_else(|| SnmpsimError::Parse("Truncated \\x escape".into()))?;
                    let hex = format!("{}{}", h1, h2);
                    let byte = u8::from_str_radix(&hex, 16)
                        .map_err(|e| SnmpsimError::Parse(format!("Invalid \\x escape: {}", e)))?;
                    out.push(byte);
                }
                Some(other) => {
                    return Err(SnmpsimError::Parse(format!(
                        "Unknown escape character: {}",
                        other
                    )));
                }
            }
        }
        Ok(out)
    }
}

impl Default for SnmprecGrammar {
    fn default() -> Self {
        SnmprecGrammar::new()
    }
}

impl Grammar for SnmprecGrammar {
    /// Parse a .snmprec line into (oid, tag, value) strings.
    fn parse(&self, line: &[u8]) -> Result<(String, String, String)> {
        let line_str = std::str::from_utf8(line)
            .map_err(|e| SnmpsimError::Parse(format!("Non-UTF8 line: {}", e)))?
            .trim();

        let parts: Vec<&str> = line_str.splitn(3, '|').collect();
        if parts.len() != 3 {
            return Err(SnmpsimError::Parse(format!(
                "Broken .snmprec record: expected OID|tag|value, got {:?}",
                line_str
            )));
        }

        let oid = parts[0].trim().to_string();
        let tag = parts[1].trim().to_string();
        let value = parts[2].to_string();

        if oid.is_empty() || tag.is_empty() {
            return Err(SnmpsimError::Parse(format!(
                "Empty OID or tag in record: {:?}",
                line_str
            )));
        }

        Ok((oid, tag, value))
    }

    /// Build a .snmprec record line from (oid, tag, value).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_basic() {
        let g = SnmprecGrammar::new();
        let (oid, tag, val) = g.parse(b"1.3.6.1.2.1.1.1.0|4|Linux 4.15").unwrap();
        assert_eq!(oid, "1.3.6.1.2.1.1.1.0");
        assert_eq!(tag, "4");
        assert_eq!(val, "Linux 4.15");
    }

    #[test]
    fn test_parse_timeticks() {
        let g = SnmprecGrammar::new();
        let (oid, tag, val) = g
            .parse(b"1.3.6.1.2.1.1.3.0|67:numeric|rate=100,initial=123999999")
            .unwrap();
        assert_eq!(oid, "1.3.6.1.2.1.1.3.0");
        assert_eq!(tag, "67:numeric");
        assert_eq!(val, "rate=100,initial=123999999");
    }

    #[test]
    fn test_parse_hex_tag() {
        let g = SnmprecGrammar::new();
        let (_, tag, _) = g.parse(b"1.3.6.1.2.1.2.2.1.6.1|4x|001122334455").unwrap();
        assert_eq!(tag, "4x");
    }

    #[test]
    fn test_unpack_tag() {
        assert_eq!(SnmprecGrammar::unpack_tag("4x"), ("4", Some('x')));
        assert_eq!(SnmprecGrammar::unpack_tag("4e"), ("4", Some('e')));
        assert_eq!(SnmprecGrammar::unpack_tag("2"), ("2", None));
    }

    #[test]
    fn test_split_module() {
        assert_eq!(
            SnmprecGrammar::split_module("4:delay"),
            ("4", Some("delay"))
        );
        assert_eq!(
            SnmprecGrammar::split_module("4x:redis"),
            ("4x", Some("redis"))
        );
        assert_eq!(SnmprecGrammar::split_module("66"), ("66", None));
    }

    #[test]
    fn test_evaluate_escaped() {
        let bytes = SnmprecGrammar::evaluate_escaped("hello\\nworld").unwrap();
        assert_eq!(bytes, b"hello\nworld");
    }

    #[test]
    fn test_build() {
        let g = SnmprecGrammar::new();
        let line = g.build("1.3.6.1", "4", "test").unwrap();
        assert_eq!(line, b"1.3.6.1|4|test\n");
    }
}
