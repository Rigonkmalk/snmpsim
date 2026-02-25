//! Record implementation for .snmprec format files.

use std::collections::HashMap;
use std::io::Read;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use crate::error::{Result, SnmpsimError};
use crate::grammar::snmprec::SnmprecGrammar;
use crate::grammar::Grammar;
use crate::oid::Oid;
use crate::record::{EvalContext, Record};
use crate::snmp_value::{tags, SnmpValue};
use crate::variation::{VariationContext, VariationModuleRegistry};

/// Record handler for .snmprec files.
pub struct SnmprecRecord {
    grammar: SnmprecGrammar,
    registry: Arc<VariationModuleRegistry>,
}

impl SnmprecRecord {
    pub fn new() -> Self {
        SnmprecRecord {
            grammar: SnmprecGrammar::new(),
            registry: Arc::new(VariationModuleRegistry::with_builtins()),
        }
    }

    /// Parse a snmprec value string into a typed SnmpValue, handling
    /// encoding suffixes ('x' for hex, 'e' for escaped).
    fn parse_value(base_tag: &str, encoding: Option<char>, value_str: &str) -> Result<SnmpValue> {
        match base_tag {
            tags::INTEGER => {
                let v: i64 = value_str
                    .trim()
                    .parse()
                    .map_err(|e| SnmpsimError::Parse(format!("Invalid INTEGER {:?}: {}", value_str, e)))?;
                Ok(SnmpValue::Integer(v))
            }

            tags::OCTET_STRING => {
                let bytes = match encoding {
                    Some('x') => {
                        hex::decode(value_str.trim())
                            .map_err(|e| SnmpsimError::Parse(format!("Hex decode error: {}", e)))?
                    }
                    Some('e') => SnmprecGrammar::evaluate_escaped(value_str)?,
                    _ => value_str.as_bytes().to_vec(),
                };
                Ok(SnmpValue::OctetString(bytes))
            }

            tags::NULL => Ok(SnmpValue::Null),

            tags::OID => {
                let oid = Oid::from_str(value_str.trim())?;
                Ok(SnmpValue::ObjectIdentifier(oid))
            }

            tags::IP_ADDRESS => {
                let bytes = match encoding {
                    Some('x') => {
                        hex::decode(value_str.trim())
                            .map_err(|e| SnmpsimError::Parse(format!("Hex decode error: {}", e)))?
                    }
                    _ => {
                        // Dotted decimal: "192.168.1.1"
                        let parts: Result<Vec<u8>> = value_str
                            .trim()
                            .split('.')
                            .map(|s| {
                                s.parse::<u8>().map_err(|e| {
                                    SnmpsimError::Parse(format!("Invalid IP octet {:?}: {}", s, e))
                                })
                            })
                            .collect();
                        parts?
                    }
                };
                if bytes.len() != 4 {
                    return Err(SnmpsimError::Parse(format!(
                        "IpAddress must be 4 bytes, got {}",
                        bytes.len()
                    )));
                }
                Ok(SnmpValue::IpAddress(Ipv4Addr::new(
                    bytes[0], bytes[1], bytes[2], bytes[3],
                )))
            }

            tags::COUNTER32 => {
                let v: u32 = value_str
                    .trim()
                    .parse()
                    .map_err(|e| SnmpsimError::Parse(format!("Invalid Counter32 {:?}: {}", value_str, e)))?;
                Ok(SnmpValue::Counter32(v))
            }

            tags::GAUGE32 => {
                let v: u32 = value_str
                    .trim()
                    .parse()
                    .map_err(|e| SnmpsimError::Parse(format!("Invalid Gauge32 {:?}: {}", value_str, e)))?;
                Ok(SnmpValue::Gauge32(v))
            }

            tags::TIME_TICKS => {
                let v: u32 = value_str
                    .trim()
                    .parse()
                    .map_err(|e| SnmpsimError::Parse(format!("Invalid TimeTicks {:?}: {}", value_str, e)))?;
                Ok(SnmpValue::TimeTicks(v))
            }

            tags::OPAQUE => {
                let bytes = match encoding {
                    Some('x') => hex::decode(value_str.trim())
                        .map_err(|e| SnmpsimError::Parse(format!("Hex decode error: {}", e)))?,
                    _ => value_str.as_bytes().to_vec(),
                };
                Ok(SnmpValue::Opaque(bytes))
            }

            tags::COUNTER64 => {
                let v: u64 = value_str
                    .trim()
                    .parse()
                    .map_err(|e| SnmpsimError::Parse(format!("Invalid Counter64 {:?}: {}", value_str, e)))?;
                Ok(SnmpValue::Counter64(v))
            }

            tags::NO_SUCH_OBJECT => Ok(SnmpValue::NoSuchObject),
            tags::NO_SUCH_INSTANCE => Ok(SnmpValue::NoSuchInstance),
            tags::END_OF_MIB_VIEW => Ok(SnmpValue::EndOfMibView),

            other => Err(SnmpsimError::Parse(format!("Unknown snmprec tag: {:?}", other))),
        }
    }

    /// Format a value as a hex string for display in .snmprec files.
    fn hexify_value(value: &SnmpValue) -> Option<String> {
        match value {
            SnmpValue::OctetString(bytes) => {
                // Hexify if value contains non-printable ASCII characters
                if bytes.iter().any(|&b| !(b.is_ascii_alphanumeric() || b.is_ascii_punctuation() || b == b' ')) {
                    Some(hex::encode(bytes))
                } else {
                    None
                }
            }
            SnmpValue::IpAddress(ip) => Some(hex::encode(ip.octets())),
            SnmpValue::Opaque(bytes) => Some(hex::encode(bytes)),
            _ => None,
        }
    }
}

impl Default for SnmprecRecord {
    fn default() -> Self {
        SnmprecRecord::new()
    }
}

impl Record for SnmprecRecord {
    fn grammar(&self) -> &dyn Grammar {
        &self.grammar
    }

    fn extension(&self) -> &str {
        "snmprec"
    }

    fn evaluate_oid(&self, oid_str: &str) -> Result<Oid> {
        Oid::from_str(oid_str)
    }

    fn evaluate_value(&self, oid: &Oid, tag: &str, value_str: &str, ctx: &EvalContext) -> Result<SnmpValue> {
        // Subtree records have a leading ':' with no numeric type prefix
        if tag.starts_with(':') {
            return Ok(SnmpValue::Null);
        }

        // Split off module name (e.g. "4:delay" → type_tag="4", module="delay")
        let (type_tag, module_name) = SnmprecGrammar::split_module(tag);

        // Split off encoding suffix (e.g. "4x" → base="4", enc=Some('x'))
        let (base_tag, encoding) = SnmprecGrammar::unpack_tag(type_tag);

        // Route through variation module when one is specified
        if let Some(name) = module_name {
            if let Some(module) = self.registry.get(name) {
                let mut vctx = VariationContext {
                    oid: oid.clone(),
                    tag: base_tag.to_string(),
                    value: value_str.to_string(),
                    next_flag: ctx.next_flag,
                    set_flag: ctx.set_flag,
                    exact_match: ctx.exact_match,
                    data_file: ctx.data_file.clone(),
                    options: String::new(),
                    record_context: HashMap::new(),
                    agent_context: HashMap::new(),
                };
                let result = module.variate(&mut vctx)?;
                return Ok(result.value);
            } else {
                return Err(SnmpsimError::Config(format!(
                    "Unknown variation module: {:?}", name
                )));
            }
        }

        let value = Self::parse_value(base_tag, encoding, value_str)?;

        // If this is a GET (not NEXT) and not an exact match, return noSuchInstance
        if !ctx.next_flag && !ctx.exact_match && !ctx.set_flag && ctx.orig_oid.is_some() {
            return Ok(SnmpValue::NoSuchInstance);
        }

        Ok(value)
    }

    fn evaluate(&self, line: &[u8], ctx: &EvalContext) -> Result<(Oid, Option<SnmpValue>)> {
        let (oid_str, tag, value_str) = self.grammar.parse(line)?;
        let oid = self.evaluate_oid(&oid_str)?;

        if ctx.oid_only {
            return Ok((oid, None));
        }

        let value = self.evaluate_value(&oid, &tag, &value_str, ctx)?;
        Ok((oid, Some(value)))
    }

    fn format_oid(&self, oid: &Oid) -> String {
        oid.to_string()
    }

    fn format_value(&self, oid: &Oid, value: &SnmpValue) -> (String, String, String) {
        let oid_str = self.format_oid(oid);
        let base_tag = value.snmprec_tag().to_string();

        if let Some(hex) = Self::hexify_value(value) {
            let tag_with_suffix = format!("{}x", base_tag);
            (oid_str, tag_with_suffix, hex)
        } else {
            let val_str = match value {
                SnmpValue::Integer(v) => v.to_string(),
                SnmpValue::OctetString(bytes) => {
                    // Check if printable
                    if bytes.iter().all(|&b| b.is_ascii_graphic() || b == b' ') {
                        String::from_utf8_lossy(bytes).into_owned()
                    } else {
                        hex::encode(bytes)
                    }
                }
                SnmpValue::Null => String::new(),
                SnmpValue::ObjectIdentifier(o) => o.to_string(),
                SnmpValue::IpAddress(ip) => ip.to_string(),
                SnmpValue::Counter32(v) => v.to_string(),
                SnmpValue::Gauge32(v) => v.to_string(),
                SnmpValue::TimeTicks(v) => v.to_string(),
                SnmpValue::Opaque(bytes) => hex::encode(bytes),
                SnmpValue::Counter64(v) => v.to_string(),
                SnmpValue::NoSuchObject | SnmpValue::NoSuchInstance | SnmpValue::EndOfMibView => {
                    String::new()
                }
            };
            (oid_str, base_tag, val_str)
        }
    }
}

/// Record handler for .snmprec.bz2 compressed files.
pub struct CompressedSnmprecRecord {
    inner: SnmprecRecord,
}

impl CompressedSnmprecRecord {
    pub fn new() -> Self {
        CompressedSnmprecRecord {
            inner: SnmprecRecord::new(),
        }
    }
}

impl Default for CompressedSnmprecRecord {
    fn default() -> Self {
        CompressedSnmprecRecord::new()
    }
}

impl Record for CompressedSnmprecRecord {
    fn grammar(&self) -> &dyn Grammar {
        self.inner.grammar()
    }

    fn extension(&self) -> &str {
        "snmprec.bz2"
    }

    fn evaluate_oid(&self, oid_str: &str) -> Result<Oid> {
        self.inner.evaluate_oid(oid_str)
    }

    fn evaluate_value(&self, oid: &Oid, tag: &str, value_str: &str, ctx: &EvalContext) -> Result<SnmpValue> {
        self.inner.evaluate_value(oid, tag, value_str, ctx)
    }

    fn evaluate(&self, line: &[u8], ctx: &EvalContext) -> Result<(Oid, Option<SnmpValue>)> {
        self.inner.evaluate(line, ctx)
    }

    fn format_oid(&self, oid: &Oid) -> String {
        self.inner.format_oid(oid)
    }

    fn format_value(&self, oid: &Oid, value: &SnmpValue) -> (String, String, String) {
        self.inner.format_value(oid, value)
    }

    fn open(&self, path: &Path) -> Result<Box<dyn Read>> {
        use bzip2::read::BzDecoder;
        let f = std::fs::File::open(path)?;
        Ok(Box::new(BzDecoder::new(f)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evaluate_integer() {
        let r = SnmprecRecord::new();
        let ctx = EvalContext {
            exact_match: true,
            ..Default::default()
        };
        let (oid, val) = r.evaluate(b"1.3.6.1.2.1.1.1.0|2|12345", &ctx).unwrap();
        assert_eq!(oid.to_string(), "1.3.6.1.2.1.1.1.0");
        assert_eq!(val, Some(SnmpValue::Integer(12345)));
    }

    #[test]
    fn test_evaluate_hex_octet_string() {
        let r = SnmprecRecord::new();
        let ctx = EvalContext {
            exact_match: true,
            ..Default::default()
        };
        let (_, val) = r.evaluate(b"1.3.6.1|4x|deadbeef", &ctx).unwrap();
        assert_eq!(val, Some(SnmpValue::OctetString(vec![0xde, 0xad, 0xbe, 0xef])));
    }

    #[test]
    fn test_evaluate_ipaddress() {
        let r = SnmprecRecord::new();
        let ctx = EvalContext {
            exact_match: true,
            ..Default::default()
        };
        let (_, val) = r.evaluate(b"1.3.6.1|64|192.168.1.1", &ctx).unwrap();
        assert_eq!(
            val,
            Some(SnmpValue::IpAddress("192.168.1.1".parse().unwrap()))
        );
    }
}
