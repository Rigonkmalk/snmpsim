//! SNMP value types and tag constants
//!
//! Mirrors the pyasn1/pysnmp type system used in the Python snmpsim.

use std::fmt;
use std::net::Ipv4Addr;

use crate::oid::Oid;

/// All SNMP value types that can appear in simulation data files.
#[derive(Debug, Clone, PartialEq)]
pub enum SnmpValue {
    Integer(i64),
    OctetString(Vec<u8>),
    Null,
    ObjectIdentifier(Oid),
    IpAddress(Ipv4Addr),
    Counter32(u32),
    Gauge32(u32),
    TimeTicks(u32),
    Opaque(Vec<u8>),
    Counter64(u64),
    /// noSuchObject exception value (v2c)
    NoSuchObject,
    /// noSuchInstance exception value (v2c)
    NoSuchInstance,
    /// endOfMibView exception value (v2c)
    EndOfMibView,
}

impl SnmpValue {
    /// Return the numeric tag string used in .snmprec files.
    pub fn snmprec_tag(&self) -> &'static str {
        match self {
            SnmpValue::Integer(_) => tags::INTEGER,
            SnmpValue::OctetString(_) => tags::OCTET_STRING,
            SnmpValue::Null => tags::NULL,
            SnmpValue::ObjectIdentifier(_) => tags::OID,
            SnmpValue::IpAddress(_) => tags::IP_ADDRESS,
            SnmpValue::Counter32(_) => tags::COUNTER32,
            SnmpValue::Gauge32(_) => tags::GAUGE32,
            SnmpValue::TimeTicks(_) => tags::TIME_TICKS,
            SnmpValue::Opaque(_) => tags::OPAQUE,
            SnmpValue::Counter64(_) => tags::COUNTER64,
            SnmpValue::NoSuchObject => tags::NO_SUCH_OBJECT,
            SnmpValue::NoSuchInstance => tags::NO_SUCH_INSTANCE,
            SnmpValue::EndOfMibView => tags::END_OF_MIB_VIEW,
        }
    }

    /// Return the BER tag byte for this value type.
    pub fn ber_tag(&self) -> u8 {
        match self {
            SnmpValue::Integer(_) => ber_tags::INTEGER,
            SnmpValue::OctetString(_) => ber_tags::OCTET_STRING,
            SnmpValue::Null => ber_tags::NULL,
            SnmpValue::ObjectIdentifier(_) => ber_tags::OID,
            SnmpValue::IpAddress(_) => ber_tags::IP_ADDRESS,
            SnmpValue::Counter32(_) => ber_tags::COUNTER32,
            SnmpValue::Gauge32(_) => ber_tags::GAUGE32,
            SnmpValue::TimeTicks(_) => ber_tags::TIME_TICKS,
            SnmpValue::Opaque(_) => ber_tags::OPAQUE,
            SnmpValue::Counter64(_) => ber_tags::COUNTER64,
            SnmpValue::NoSuchObject => ber_tags::NO_SUCH_OBJECT,
            SnmpValue::NoSuchInstance => ber_tags::NO_SUCH_INSTANCE,
            SnmpValue::EndOfMibView => ber_tags::END_OF_MIB_VIEW,
        }
    }
}

impl fmt::Display for SnmpValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnmpValue::Integer(v) => write!(f, "{}", v),
            SnmpValue::OctetString(v) => {
                let s = String::from_utf8_lossy(v);
                write!(f, "{}", s)
            }
            SnmpValue::Null => write!(f, "NULL"),
            SnmpValue::ObjectIdentifier(oid) => write!(f, "{}", oid),
            SnmpValue::IpAddress(ip) => write!(f, "{}", ip),
            SnmpValue::Counter32(v) => write!(f, "{}", v),
            SnmpValue::Gauge32(v) => write!(f, "{}", v),
            SnmpValue::TimeTicks(v) => write!(f, "{}", v),
            SnmpValue::Opaque(v) => {
                write!(f, "0x")?;
                for b in v {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            SnmpValue::Counter64(v) => write!(f, "{}", v),
            SnmpValue::NoSuchObject => write!(f, "noSuchObject"),
            SnmpValue::NoSuchInstance => write!(f, "noSuchInstance"),
            SnmpValue::EndOfMibView => write!(f, "endOfMibView"),
        }
    }
}

/// Numeric tag strings used in .snmprec files.
/// These correspond to the sum of pyasn1 tag components (class + format + tagId).
pub mod tags {
    /// Universal INTEGER (tag 2)
    pub const INTEGER: &str = "2";
    /// Universal OCTET STRING (tag 4)
    pub const OCTET_STRING: &str = "4";
    /// Universal NULL (tag 5)
    pub const NULL: &str = "5";
    /// Universal OBJECT IDENTIFIER (tag 6)
    pub const OID: &str = "6";
    /// Application IpAddress (class=64, tag=0 → 64)
    pub const IP_ADDRESS: &str = "64";
    /// Application Counter32 (class=64, tag=1 → 65)
    pub const COUNTER32: &str = "65";
    /// Application Gauge32/Unsigned32 (class=64, tag=2 → 66)
    pub const GAUGE32: &str = "66";
    /// Application TimeTicks (class=64, tag=3 → 67)
    pub const TIME_TICKS: &str = "67";
    /// Application Opaque (class=64, tag=4 → 68)
    pub const OPAQUE: &str = "68";
    /// Application Counter64 (class=64, tag=6 → 70)
    pub const COUNTER64: &str = "70";
    /// Context noSuchObject (class=128, tag=0 → 128)
    pub const NO_SUCH_OBJECT: &str = "128";
    /// Context noSuchInstance (class=128, tag=1 → 129)
    pub const NO_SUCH_INSTANCE: &str = "129";
    /// Context endOfMibView (class=128, tag=2 → 130)
    pub const END_OF_MIB_VIEW: &str = "130";
}

/// BER tag bytes for SNMP wire encoding.
pub mod ber_tags {
    /// Universal INTEGER
    pub const INTEGER: u8 = 0x02;
    /// Universal OCTET STRING
    pub const OCTET_STRING: u8 = 0x04;
    /// Universal NULL
    pub const NULL: u8 = 0x05;
    /// Universal OBJECT IDENTIFIER
    pub const OID: u8 = 0x06;
    /// Universal SEQUENCE (constructed)
    pub const SEQUENCE: u8 = 0x30;

    // Application types
    pub const IP_ADDRESS: u8 = 0x40;
    pub const COUNTER32: u8 = 0x41;
    pub const GAUGE32: u8 = 0x42;
    pub const TIME_TICKS: u8 = 0x43;
    pub const OPAQUE: u8 = 0x44;
    pub const COUNTER64: u8 = 0x46;

    // Context-specific exception types (v2c)
    pub const NO_SUCH_OBJECT: u8 = 0x80;
    pub const NO_SUCH_INSTANCE: u8 = 0x81;
    pub const END_OF_MIB_VIEW: u8 = 0x82;

    // PDU types (context-specific, constructed)
    pub const GET_REQUEST: u8 = 0xA0;
    pub const GET_NEXT_REQUEST: u8 = 0xA1;
    pub const GET_RESPONSE: u8 = 0xA2;
    pub const SET_REQUEST: u8 = 0xA3;
    pub const GET_BULK_REQUEST: u8 = 0xA5;
    pub const INFORM_REQUEST: u8 = 0xA6;
    pub const SNMPV2_TRAP: u8 = 0xA7;
    pub const REPORT: u8 = 0xA8;
}
