//! BER (Basic Encoding Rules) codec for SNMP messages.
//!
//! Implements encoding and decoding of SNMP v1/v2c/v3 messages using
//! the BER subset required by the SNMP protocol.

use std::net::Ipv4Addr;

use crate::error::{Result, SnmpsimError};
use crate::oid::Oid;
use crate::snmp_value::{ber_tags, SnmpValue};

// ─── SNMP message structures ──────────────────────────────────────────────────

/// Decoded SNMP message (v1 or v2c).
#[derive(Debug, Clone)]
pub struct SnmpMessage {
    pub version: i64,
    pub community: Vec<u8>,
    pub pdu: Pdu,
}

/// SNMP PDU variants.
#[derive(Debug, Clone)]
pub enum Pdu {
    GetRequest(VarBindPdu),
    GetNextRequest(VarBindPdu),
    GetResponse(VarBindPdu),
    SetRequest(VarBindPdu),
    GetBulkRequest(GetBulkPdu),
    /// Unrecognised PDU type - tag stored for error reporting.
    Unknown(u8),
}

/// Common structure for GET/GETNEXT/SET/RESPONSE PDUs.
#[derive(Debug, Clone)]
pub struct VarBindPdu {
    pub request_id: i64,
    pub error_status: i64,
    pub error_index: i64,
    pub var_binds: Vec<VarBind>,
}

/// GETBULK PDU.
#[derive(Debug, Clone)]
pub struct GetBulkPdu {
    pub request_id: i64,
    pub non_repeaters: i64,
    pub max_repetitions: i64,
    pub var_binds: Vec<VarBind>,
}

/// A single OID + value pair.
#[derive(Debug, Clone)]
pub struct VarBind {
    pub oid: Oid,
    pub value: SnmpValue,
}

// ─── SNMP error status codes ──────────────────────────────────────────────────

pub mod error_status {
    pub const NO_ERROR: i64 = 0;
    pub const TOO_BIG: i64 = 1;
    pub const NO_SUCH_NAME: i64 = 2;
    pub const BAD_VALUE: i64 = 3;
    pub const READ_ONLY: i64 = 4;
    pub const GEN_ERR: i64 = 5;
    pub const NO_ACCESS: i64 = 6;
    pub const WRONG_TYPE: i64 = 7;
    pub const WRONG_LENGTH: i64 = 8;
    pub const WRONG_ENCODING: i64 = 9;
    pub const WRONG_VALUE: i64 = 10;
    pub const NO_CREATION: i64 = 11;
    pub const INCONSISTENT_VALUE: i64 = 12;
    pub const RESOURCE_UNAVAILABLE: i64 = 13;
    pub const COMMIT_FAILED: i64 = 14;
    pub const UNDO_FAILED: i64 = 15;
    pub const AUTHORIZATION_ERROR: i64 = 16;
    pub const NOT_WRITABLE: i64 = 17;
    pub const INCONSISTENT_NAME: i64 = 18;
}

// ─── BER length encoding/decoding ────────────────────────────────────────────

fn encode_length(len: usize) -> Vec<u8> {
    if len < 128 {
        vec![len as u8]
    } else if len < 256 {
        vec![0x81, len as u8]
    } else if len < 65536 {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    } else {
        vec![
            0x83,
            ((len >> 16) & 0xFF) as u8,
            ((len >> 8) & 0xFF) as u8,
            (len & 0xFF) as u8,
        ]
    }
}

/// Returns `(length, remaining_bytes)`.
fn decode_length(data: &[u8]) -> Result<(usize, &[u8])> {
    if data.is_empty() {
        return Err(SnmpsimError::Ber("Unexpected EOF reading length".into()));
    }
    if data[0] & 0x80 == 0 {
        Ok((data[0] as usize, &data[1..]))
    } else {
        let n = (data[0] & 0x7F) as usize;
        if n == 0 {
            return Err(SnmpsimError::Ber("Indefinite-length BER not supported".into()));
        }
        if data.len() < n + 1 {
            return Err(SnmpsimError::Ber("Truncated length field".into()));
        }
        let mut len: usize = 0;
        for &b in &data[1..=n] {
            len = (len << 8) | b as usize;
        }
        Ok((len, &data[n + 1..]))
    }
}

/// Returns `(tag, value_bytes, remaining_bytes)`.
fn decode_tlv(data: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    if data.is_empty() {
        return Err(SnmpsimError::Ber("Empty BER data".into()));
    }
    let tag = data[0];
    let (len, rest) = decode_length(&data[1..])?;
    if rest.len() < len {
        return Err(SnmpsimError::Ber(format!(
            "Truncated value: need {} bytes, have {}",
            len,
            rest.len()
        )));
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

// ─── BER integer encoding/decoding ───────────────────────────────────────────

/// Encode a signed integer as a minimal BER integer value.
fn encode_integer_bytes(val: i64) -> Vec<u8> {
    if val == 0 {
        return vec![0x00];
    }
    let bytes = val.to_be_bytes();
    let mut start = 0;
    // Skip leading redundant bytes
    while start < 7 {
        let b0 = bytes[start];
        let b1 = bytes[start + 1];
        if (b0 == 0x00 && b1 & 0x80 == 0) || (b0 == 0xFF && b1 & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    bytes[start..].to_vec()
}

fn decode_integer(data: &[u8]) -> i64 {
    if data.is_empty() {
        return 0;
    }
    // Sign-extend from the MSB
    let mut val: i64 = if data[0] & 0x80 != 0 { -1i64 } else { 0i64 };
    for &b in data {
        val = (val << 8) | b as i64;
    }
    val
}

fn decode_unsigned(data: &[u8]) -> u64 {
    let mut val: u64 = 0;
    for &b in data {
        val = (val << 8) | b as u64;
    }
    val
}

// ─── OID encoding/decoding ───────────────────────────────────────────────────

fn encode_oid_component(mut val: u32, out: &mut Vec<u8>) {
    if val == 0 {
        out.push(0);
        return;
    }
    let mut bytes: Vec<u8> = Vec::new();
    while val > 0 {
        bytes.push((val & 0x7F) as u8);
        val >>= 7;
    }
    bytes.reverse();
    let last = bytes.len() - 1;
    for (i, &b) in bytes.iter().enumerate() {
        if i < last {
            out.push(b | 0x80);
        } else {
            out.push(b);
        }
    }
}

fn encode_oid_bytes(oid: &Oid) -> Vec<u8> {
    let c = oid.components();
    let mut out = Vec::new();
    if c.len() < 2 {
        out.push(0);
    } else {
        out.push((c[0] * 40 + c[1]) as u8);
        for &comp in &c[2..] {
            encode_oid_component(comp, &mut out);
        }
    }
    out
}

fn decode_oid_bytes(data: &[u8]) -> Result<Oid> {
    if data.is_empty() {
        return Ok(Oid::new(vec![]));
    }
    let first = data[0] as u32;
    let mut components = vec![first / 40, first % 40];

    let mut i = 1;
    while i < data.len() {
        let mut val: u32 = 0;
        loop {
            if i >= data.len() {
                return Err(SnmpsimError::Ber("Truncated OID encoding".into()));
            }
            let b = data[i];
            i += 1;
            val = (val << 7) | (b & 0x7F) as u32;
            if b & 0x80 == 0 {
                break;
            }
        }
        components.push(val);
    }
    Ok(Oid::new(components))
}

// ─── SnmpValue BER encoding ──────────────────────────────────────────────────

/// Encode a single SNMP value including its BER tag and length.
pub fn encode_value(val: &SnmpValue) -> Vec<u8> {
    let tag = val.ber_tag();
    match val {
        SnmpValue::Integer(v) => {
            let content = encode_integer_bytes(*v);
            let mut out = vec![tag];
            out.extend_from_slice(&encode_length(content.len()));
            out.extend_from_slice(&content);
            out
        }
        SnmpValue::OctetString(v) | SnmpValue::Opaque(v) => {
            let mut out = vec![tag];
            out.extend_from_slice(&encode_length(v.len()));
            out.extend_from_slice(v);
            out
        }
        SnmpValue::Null
        | SnmpValue::NoSuchObject
        | SnmpValue::NoSuchInstance
        | SnmpValue::EndOfMibView => {
            vec![tag, 0x00]
        }
        SnmpValue::ObjectIdentifier(oid) => {
            let content = encode_oid_bytes(oid);
            let mut out = vec![tag];
            out.extend_from_slice(&encode_length(content.len()));
            out.extend_from_slice(&content);
            out
        }
        SnmpValue::IpAddress(ip) => {
            let octets = ip.octets();
            vec![tag, 0x04, octets[0], octets[1], octets[2], octets[3]]
        }
        SnmpValue::Counter32(v) | SnmpValue::Gauge32(v) | SnmpValue::TimeTicks(v) => {
            let bytes = v.to_be_bytes();
            // Minimal unsigned encoding (no sign bit)
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(3);
            let content = &bytes[start..];
            let mut out = vec![tag];
            out.extend_from_slice(&encode_length(content.len()));
            out.extend_from_slice(content);
            out
        }
        SnmpValue::Counter64(v) => {
            let bytes = v.to_be_bytes();
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
            let content = &bytes[start..];
            let mut out = vec![tag];
            out.extend_from_slice(&encode_length(content.len()));
            out.extend_from_slice(content);
            out
        }
    }
}

/// Decode a single SNMP value from BER bytes (tag must be at bytes[0]).
pub fn decode_value(data: &[u8]) -> Result<(SnmpValue, &[u8])> {
    let (tag, value_bytes, rest) = decode_tlv(data)?;
    let val = match tag {
        ber_tags::INTEGER => SnmpValue::Integer(decode_integer(value_bytes)),
        ber_tags::OCTET_STRING => SnmpValue::OctetString(value_bytes.to_vec()),
        ber_tags::NULL => SnmpValue::Null,
        ber_tags::OID => SnmpValue::ObjectIdentifier(decode_oid_bytes(value_bytes)?),
        ber_tags::IP_ADDRESS => {
            if value_bytes.len() != 4 {
                return Err(SnmpsimError::Ber("IpAddress must be 4 bytes".into()));
            }
            SnmpValue::IpAddress(Ipv4Addr::new(
                value_bytes[0],
                value_bytes[1],
                value_bytes[2],
                value_bytes[3],
            ))
        }
        ber_tags::COUNTER32 => SnmpValue::Counter32(decode_unsigned(value_bytes) as u32),
        ber_tags::GAUGE32 => SnmpValue::Gauge32(decode_unsigned(value_bytes) as u32),
        ber_tags::TIME_TICKS => SnmpValue::TimeTicks(decode_unsigned(value_bytes) as u32),
        ber_tags::OPAQUE => SnmpValue::Opaque(value_bytes.to_vec()),
        ber_tags::COUNTER64 => SnmpValue::Counter64(decode_unsigned(value_bytes)),
        ber_tags::NO_SUCH_OBJECT => SnmpValue::NoSuchObject,
        ber_tags::NO_SUCH_INSTANCE => SnmpValue::NoSuchInstance,
        ber_tags::END_OF_MIB_VIEW => SnmpValue::EndOfMibView,
        _ => {
            // Unknown application/context type - treat as opaque
            SnmpValue::Opaque(value_bytes.to_vec())
        }
    };
    Ok((val, rest))
}

// ─── VarBind encoding/decoding ───────────────────────────────────────────────

fn encode_var_bind(vb: &VarBind) -> Vec<u8> {
    let oid_bytes = encode_oid_bytes(&vb.oid);
    let mut oid_tlv = vec![ber_tags::OID];
    oid_tlv.extend_from_slice(&encode_length(oid_bytes.len()));
    oid_tlv.extend_from_slice(&oid_bytes);

    let value_bytes = encode_value(&vb.value);

    let mut content = oid_tlv;
    content.extend_from_slice(&value_bytes);

    let mut out = vec![ber_tags::SEQUENCE];
    out.extend_from_slice(&encode_length(content.len()));
    out.extend_from_slice(&content);
    out
}

fn decode_var_bind(data: &[u8]) -> Result<(VarBind, &[u8])> {
    let (tag, seq_bytes, rest) = decode_tlv(data)?;
    if tag != ber_tags::SEQUENCE {
        return Err(SnmpsimError::Ber(format!(
            "Expected SEQUENCE (0x30), got 0x{:02x}",
            tag
        )));
    }

    let (oid_tag, oid_bytes, remaining) = decode_tlv(seq_bytes)?;
    if oid_tag != ber_tags::OID {
        return Err(SnmpsimError::Ber(format!(
            "Expected OID (0x06), got 0x{:02x}",
            oid_tag
        )));
    }
    let oid = decode_oid_bytes(oid_bytes)?;

    let (value, _) = decode_value(remaining)?;

    Ok((VarBind { oid, value }, rest))
}

// ─── PDU encoding/decoding ───────────────────────────────────────────────────

fn decode_var_bind_list(data: &[u8]) -> Result<Vec<VarBind>> {
    let (tag, list_bytes, _) = decode_tlv(data)?;
    if tag != ber_tags::SEQUENCE {
        return Err(SnmpsimError::Ber(format!(
            "Expected VarBindList SEQUENCE (0x30), got 0x{:02x}",
            tag
        )));
    }

    let mut var_binds = Vec::new();
    let mut remaining = list_bytes;
    while !remaining.is_empty() {
        let (vb, rest) = decode_var_bind(remaining)?;
        var_binds.push(vb);
        remaining = rest;
    }
    Ok(var_binds)
}

fn decode_pdu_body(data: &[u8]) -> Result<(i64, i64, i64, Vec<VarBind>)> {
    let (_, req_id_bytes, after_req) = decode_tlv(data)?;
    let request_id = decode_integer(req_id_bytes);

    let (_, err_status_bytes, after_err) = decode_tlv(after_req)?;
    let error_status = decode_integer(err_status_bytes);

    let (_, err_index_bytes, after_index) = decode_tlv(after_err)?;
    let error_index = decode_integer(err_index_bytes);

    let var_binds = decode_var_bind_list(after_index)?;

    Ok((request_id, error_status, error_index, var_binds))
}

fn encode_pdu_body(pdu_tag: u8, request_id: i64, error_status: i64, error_index: i64, var_binds: &[VarBind]) -> Vec<u8> {
    // Encode request-id
    let req_bytes = encode_integer_bytes(request_id);
    let mut content = vec![ber_tags::INTEGER];
    content.extend_from_slice(&encode_length(req_bytes.len()));
    content.extend_from_slice(&req_bytes);

    // error-status
    let es_bytes = encode_integer_bytes(error_status);
    content.push(ber_tags::INTEGER);
    content.extend_from_slice(&encode_length(es_bytes.len()));
    content.extend_from_slice(&es_bytes);

    // error-index
    let ei_bytes = encode_integer_bytes(error_index);
    content.push(ber_tags::INTEGER);
    content.extend_from_slice(&encode_length(ei_bytes.len()));
    content.extend_from_slice(&ei_bytes);

    // VarBindList
    let mut vbl = Vec::new();
    for vb in var_binds {
        vbl.extend_from_slice(&encode_var_bind(vb));
    }
    content.push(ber_tags::SEQUENCE);
    content.extend_from_slice(&encode_length(vbl.len()));
    content.extend_from_slice(&vbl);

    // Wrap in PDU type
    let mut out = vec![pdu_tag];
    out.extend_from_slice(&encode_length(content.len()));
    out.extend_from_slice(&content);
    out
}

// ─── Top-level SNMP message decode ───────────────────────────────────────────

/// Decode an SNMP v1/v2c message from raw UDP bytes.
pub fn decode_message(data: &[u8]) -> Result<SnmpMessage> {
    let (tag, msg_bytes, _) = decode_tlv(data)?;
    if tag != ber_tags::SEQUENCE {
        return Err(SnmpsimError::Ber(format!(
            "Expected SNMP message SEQUENCE (0x30), got 0x{:02x}",
            tag
        )));
    }

    let (_, version_bytes, after_version) = decode_tlv(msg_bytes)?;
    let version = decode_integer(version_bytes);

    let (_, community_bytes, after_community) = decode_tlv(after_version)?;
    let community = community_bytes.to_vec();

    // PDU
    if after_community.is_empty() {
        return Err(SnmpsimError::Ber("Missing PDU in SNMP message".into()));
    }
    let pdu_tag = after_community[0];
    let (_, pdu_bytes, _) = decode_tlv(after_community)?;

    let pdu = match pdu_tag {
        ber_tags::GET_REQUEST => {
            let (request_id, error_status, error_index, var_binds) =
                decode_pdu_body(pdu_bytes)?;
            Pdu::GetRequest(VarBindPdu {
                request_id,
                error_status,
                error_index,
                var_binds,
            })
        }
        ber_tags::GET_NEXT_REQUEST => {
            let (request_id, error_status, error_index, var_binds) =
                decode_pdu_body(pdu_bytes)?;
            Pdu::GetNextRequest(VarBindPdu {
                request_id,
                error_status,
                error_index,
                var_binds,
            })
        }
        ber_tags::GET_RESPONSE => {
            let (request_id, error_status, error_index, var_binds) =
                decode_pdu_body(pdu_bytes)?;
            Pdu::GetResponse(VarBindPdu {
                request_id,
                error_status,
                error_index,
                var_binds,
            })
        }
        ber_tags::SET_REQUEST => {
            let (request_id, error_status, error_index, var_binds) =
                decode_pdu_body(pdu_bytes)?;
            Pdu::SetRequest(VarBindPdu {
                request_id,
                error_status,
                error_index,
                var_binds,
            })
        }
        ber_tags::GET_BULK_REQUEST => {
            // GETBULK reuses error-status as non-repeaters, error-index as max-repetitions
            let (request_id, non_repeaters, max_repetitions, var_binds) =
                decode_pdu_body(pdu_bytes)?;
            Pdu::GetBulkRequest(GetBulkPdu {
                request_id,
                non_repeaters,
                max_repetitions,
                var_binds,
            })
        }
        other => Pdu::Unknown(other),
    };

    Ok(SnmpMessage {
        version,
        community,
        pdu,
    })
}

// ─── Top-level SNMP message encode ───────────────────────────────────────────

/// Encode an SNMP v1/v2c GetResponse message into raw UDP bytes.
pub fn encode_response(
    version: i64,
    community: &[u8],
    request_id: i64,
    error_status: i64,
    error_index: i64,
    var_binds: &[VarBind],
) -> Vec<u8> {
    let pdu = encode_pdu_body(
        ber_tags::GET_RESPONSE,
        request_id,
        error_status,
        error_index,
        var_binds,
    );

    // version INTEGER
    let ver_bytes = encode_integer_bytes(version);
    let mut msg_content = vec![ber_tags::INTEGER];
    msg_content.extend_from_slice(&encode_length(ver_bytes.len()));
    msg_content.extend_from_slice(&ver_bytes);

    // community OCTET STRING
    msg_content.push(ber_tags::OCTET_STRING);
    msg_content.extend_from_slice(&encode_length(community.len()));
    msg_content.extend_from_slice(community);

    // PDU
    msg_content.extend_from_slice(&pdu);

    // Outer SEQUENCE
    let mut out = vec![ber_tags::SEQUENCE];
    out.extend_from_slice(&encode_length(msg_content.len()));
    out.extend_from_slice(&msg_content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_integer() {
        let v = SnmpValue::Integer(12345);
        let encoded = encode_value(&v);
        let (decoded, _) = decode_value(&encoded).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn test_encode_decode_oid() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        let v = SnmpValue::ObjectIdentifier(oid.clone());
        let encoded = encode_value(&v);
        let (decoded, _) = decode_value(&encoded).unwrap();
        if let SnmpValue::ObjectIdentifier(decoded_oid) = decoded {
            assert_eq!(oid, decoded_oid);
        } else {
            panic!("Expected OID");
        }
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let v = SnmpValue::OctetString(b"hello world".to_vec());
        let encoded = encode_value(&v);
        let (decoded, _) = decode_value(&encoded).unwrap();
        assert_eq!(v, decoded);
    }
}
