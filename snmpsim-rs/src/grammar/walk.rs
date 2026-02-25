//! Grammar for snmpwalk output format.
//!
//! Parses lines like:
//!   .1.3.6.1.2.1.1.1.0 = STRING: "Linux netdev02"
//!   .1.3.6.1.2.1.1.3.0 = Timeticks: (12345) 0:02:03.45

use crate::error::{Result, SnmpsimError};
use crate::grammar::Grammar;

/// Maps snmpwalk type labels to .snmprec numeric tags.
/// Keys are uppercase for case-insensitive matching.
fn walk_tag_to_snmprec(tag: &str) -> Option<&'static str> {
    match tag.to_uppercase().as_str() {
        "INTEGER:" => Some("2"),
        "STRING:" => Some("4"),
        "BITS:" => Some("4"),
        "HEX-STRING:" => Some("4x"),
        "GAUGE32:" => Some("66"),
        "COUNTER32:" => Some("65"),
        "COUNTER64:" => Some("70"),
        "IPADDRESS:" => Some("64"),
        "TIMETICKS:" => Some("67"),
        "OPAQUE:" => Some("68"),
        "OID:" => Some("6"),
        "NETWORK ADDRESS:" => Some("64"),
        "UNSIGNED32:" => Some("66"),
        "NULL:" => Some("5"),
        _ => None,
    }
}

/// Grammar for snmpwalk output format files (.snmpwalk, .walk).
pub struct WalkGrammar;

impl WalkGrammar {
    pub fn new() -> Self {
        WalkGrammar
    }

    /// Filter integer values: strip unit suffixes and enumeration labels.
    fn filter_integer(value: &str) -> String {
        // Try direct parse
        if value.parse::<i64>().is_ok() {
            return value.to_string();
        }
        // Enumeration: "ethernetCsmacd(6)" → "6"
        if let Some(m) = extract_parenthesized_integer(value) {
            return m.to_string();
        }
        // Unit suffix: "60 seconds" → "60"
        if let Some(pos) = value.find(' ') {
            let prefix = &value[..pos];
            if prefix.parse::<i64>().is_ok() {
                return prefix.to_string();
            }
        }
        value.to_string()
    }

    /// Filter string values: strip surrounding quotes, handle MAC address notation.
    fn filter_string(value: &str) -> String {
        if value.is_empty() {
            return String::new();
        }
        if value.starts_with('"') && value.ends_with('"') && value.len() >= 2 {
            return value[1..value.len() - 1].to_string();
        }
        // MAC address style: "60:9c:9f:ec:a3:38" → hex bytes
        if is_colon_hex(value) {
            return value
                .split(':')
                .filter_map(|s| u8::from_str_radix(s, 16).ok())
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .join("");
        }
        value.to_string()
    }

    /// Filter Gauge32 values.
    fn filter_gauge(value: &str) -> String {
        Self::filter_integer(value)
    }

    /// Filter HEX-STRING values: strip trailing "[...]" annotation.
    fn filter_hex_string(value: &str) -> String {
        // "00 C0 FF 43 CE 45   [...C.E]" → "00C0FF43CE45"
        let cleaned = if let Some(bracket_pos) = value.find('[') {
            value[..bracket_pos].trim()
        } else {
            value.trim()
        };
        cleaned
            .split_whitespace()
            .collect::<Vec<_>>()
            .join("")
    }

    /// Filter BITS values: extract hex bytes.
    fn filter_bits(value: &str) -> String {
        // "5B 00 00 00   clear(1)" → "5B000000"
        let cleaned = value
            .split_whitespace()
            .take_while(|s| s.len() == 2 && s.chars().all(|c| c.is_ascii_hexdigit()))
            .collect::<Vec<_>>()
            .join("");
        cleaned
    }

    /// Filter OPAQUE values.
    fn filter_opaque(value: &str) -> String {
        if value.to_uppercase().starts_with("FLOAT:") {
            // Keep as-is; value is a float
            value.to_string()
        } else {
            // Hex bytes separated by spaces
            value
                .split_whitespace()
                .collect::<Vec<_>>()
                .join("")
        }
    }

    /// Filter Network Address: "ac:1e:01:1e" → "172.30.1.30"
    fn filter_net_address(value: &str) -> String {
        value
            .split(':')
            .filter_map(|s| u8::from_str_radix(s, 16).ok())
            .map(|b| b.to_string())
            .collect::<Vec<_>>()
            .join(".")
    }

    /// Filter TimeTicks: "(12345) 0:02:03.45" → "12345"
    fn filter_timeticks(value: &str) -> String {
        if let Some(m) = extract_parenthesized_integer(value) {
            return m.to_string();
        }
        value.to_string()
    }
}

fn extract_parenthesized_integer(s: &str) -> Option<i64> {
    let open = s.find('(')?;
    let close = s[open..].find(')')?;
    let inner = &s[open + 1..open + close];
    inner.trim().parse::<i64>().ok()
}

fn is_colon_hex(s: &str) -> bool {
    let parts: Vec<&str> = s.split(':').collect();
    parts.len() >= 2 && parts.iter().all(|p| p.len() <= 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

impl Default for WalkGrammar {
    fn default() -> Self {
        WalkGrammar::new()
    }
}

impl Grammar for WalkGrammar {
    /// Parse a snmpwalk line into (oid, tag, value) strings.
    ///
    /// Returns tag as the numeric .snmprec tag string.
    fn parse(&self, line: &[u8]) -> Result<(String, String, String)> {
        // Drop any non-ASCII high bytes (as Python does with ascii/ignore)
        let line_str: String = line
            .iter()
            .filter(|&&b| b < 0x80)
            .map(|&b| b as char)
            .collect();
        let line_str = line_str.trim();

        if line_str.is_empty() || line_str.starts_with('#') {
            return Err(SnmpsimError::Parse("Empty or comment line".into()));
        }

        // Split at first " = "
        let (oid_part, value_part) = match line_str.split_once(" = ") {
            Some(pair) => pair,
            None => {
                return Err(SnmpsimError::Parse(format!(
                    "Broken walk record (no ' = '): {:?}",
                    line_str
                )))
            }
        };

        // Strip leading dot from OID
        let oid = oid_part.trim().trim_start_matches('.');

        // Handle special value prefixes
        let value_part = if value_part.starts_with("Wrong Type (should be") {
            // "Wrong Type (should be XXX): actual_value"
            &value_part[value_part.find(": ").map(|p| p + 2).unwrap_or(0)..]
        } else {
            value_part
        };

        let value_part = if value_part.starts_with("No more variables left in this MIB View") {
            "STRING: "
        } else {
            value_part
        };

        // Parse "TYPE: value" or special cases
        let (walk_tag, raw_value) = if value_part == "\"\"" || value_part == "STRING:" {
            ("STRING:", "")
        } else if value_part == "NULL" {
            ("NULL:", "")
        } else if let Some(m) = parse_walk_tag(value_part) {
            m
        } else {
            // Fallback: treat as timeticks
            ("TIMETICKS:", value_part)
        };

        let upper_tag = walk_tag.to_uppercase();
        let upper_tag = upper_tag.as_str();

        // Apply value filters based on type
        let filtered_value = match upper_tag {
            "INTEGER:" => WalkGrammar::filter_integer(raw_value.trim()),
            "STRING:" => WalkGrammar::filter_string(raw_value.trim()),
            "HEX-STRING:" => WalkGrammar::filter_hex_string(raw_value.trim()),
            "BITS:" => WalkGrammar::filter_bits(raw_value.trim()),
            "GAUGE32:" => WalkGrammar::filter_gauge(raw_value.trim()),
            "OPAQUE:" => WalkGrammar::filter_opaque(raw_value.trim()),
            "TIMETICKS:" => WalkGrammar::filter_timeticks(raw_value.trim()),
            "NETWORK ADDRESS:" => WalkGrammar::filter_net_address(raw_value.trim()),
            _ => raw_value.trim().to_string(),
        };

        // Map to snmprec tag; handle "NETWORK ADDRESS:" → IpAddress
        let snmprec_tag = if upper_tag == "NETWORK ADDRESS:" {
            "64"
        } else {
            walk_tag_to_snmprec(walk_tag).unwrap_or("4")
        };

        Ok((oid.to_string(), snmprec_tag.to_string(), filtered_value))
    }

    fn build(&self, _oid: &str, _tag: &str, _val: &str) -> Result<Vec<u8>> {
        // Walk format doesn't support building - use snmprec format instead
        Err(SnmpsimError::Parse(
            "WalkGrammar does not support build; convert to snmprec first".into(),
        ))
    }
}

/// Try to parse "TYPE: value" from a walk value string.
/// Returns `(tag, value)` or `None` if it doesn't match.
fn parse_walk_tag(s: &str) -> Option<(&str, &str)> {
    // Match word characters possibly with hyphens, followed by optional space, colon
    // e.g. "INTEGER:", "HEX-STRING:", "Network Address:"
    let s = s.trim_start();

    // Find the colon
    let colon_pos = s.find(':')?;
    let tag_part = &s[..colon_pos + 1];

    // Check tag consists of word chars and hyphens/spaces
    if tag_part.chars().all(|c| c.is_alphanumeric() || c == '-' || c == ' ' || c == ':') {
        let value_part = s[colon_pos + 1..].trim_start_matches(' ');
        Some((tag_part, value_part))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_string() {
        let g = WalkGrammar::new();
        let (oid, tag, val) = g
            .parse(b".1.3.6.1.2.1.1.1.0 = STRING: \"Linux netdev02\"")
            .unwrap();
        assert_eq!(oid, "1.3.6.1.2.1.1.1.0");
        assert_eq!(tag, "4");
        assert_eq!(val, "Linux netdev02");
    }

    #[test]
    fn test_parse_integer() {
        let g = WalkGrammar::new();
        let (_, tag, val) = g
            .parse(b".1.3.6.1.2.1.2.2.1.3.1 = INTEGER: ethernetCsmacd(6)")
            .unwrap();
        assert_eq!(tag, "2");
        assert_eq!(val, "6");
    }

    #[test]
    fn test_parse_timeticks() {
        let g = WalkGrammar::new();
        let (_, tag, val) = g
            .parse(b".1.3.6.1.2.1.1.3.0 = Timeticks: (12345) 0:02:03.45")
            .unwrap();
        assert_eq!(tag, "67");
        assert_eq!(val, "12345");
    }

    #[test]
    fn test_parse_null() {
        let g = WalkGrammar::new();
        let (_, tag, val) = g.parse(b".1.3.6.1.2.1.1.1.0 = NULL").unwrap();
        assert_eq!(tag, "5");
        assert_eq!(val, "");
    }
}
