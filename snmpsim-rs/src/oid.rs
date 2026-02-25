//! SNMP Object Identifier (OID) type
//!
//! Provides a strongly-typed OID with numeric comparison, prefix matching,
//! and standard string formatting.

use std::cmp::Ordering;
use std::fmt;
use std::str::FromStr;

use crate::error::{Result, SnmpsimError};

/// An SNMP Object Identifier represented as a sequence of unsigned 32-bit integers.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Oid(Vec<u32>);

impl Oid {
    /// Create a new OID from a vector of components.
    pub fn new(components: Vec<u32>) -> Self {
        Oid(components)
    }

    /// Return a reference to the OID components.
    pub fn components(&self) -> &[u32] {
        &self.0
    }

    /// Return the number of components in this OID.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Return true if this OID has no components.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Return true if this OID is a prefix of `other`.
    ///
    /// For example, `1.3.6.1` is a prefix of `1.3.6.1.2.1.1.1.0`.
    pub fn is_prefix_of(&self, other: &Oid) -> bool {
        if self.0.len() > other.0.len() {
            return false;
        }
        self.0 == other.0[..self.0.len()]
    }

    /// Concatenate another OID to this one, returning a new OID.
    pub fn append(&self, other: &Oid) -> Oid {
        let mut components = self.0.clone();
        components.extend_from_slice(&other.0);
        Oid(components)
    }

    /// Return the OID as a dotted string (without leading dot).
    pub fn to_dotted_string(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s: Vec<String> = self.0.iter().map(|x| x.to_string()).collect();
        write!(f, "{}", s.join("."))
    }
}

impl FromStr for Oid {
    type Err = SnmpsimError;

    fn from_str(s: &str) -> Result<Self> {
        // Strip optional leading dot
        let s = s.trim_start_matches('.');

        if s.is_empty() {
            return Ok(Oid(vec![]));
        }

        let components: std::result::Result<Vec<u32>, _> =
            s.split('.').map(|x| x.parse::<u32>()).collect();

        components
            .map(Oid)
            .map_err(|e| SnmpsimError::Parse(format!("Invalid OID '{}': {}", s, e)))
    }
}

impl PartialOrd for Oid {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Oid {
    /// Lexicographic comparison of OID components (numeric, not string).
    fn cmp(&self, other: &Self) -> Ordering {
        let len = self.0.len().min(other.0.len());
        for i in 0..len {
            match self.0[i].cmp(&other.0[i]) {
                Ordering::Equal => continue,
                ord => return ord,
            }
        }
        self.0.len().cmp(&other.0.len())
    }
}

impl From<Vec<u32>> for Oid {
    fn from(v: Vec<u32>) -> Self {
        Oid(v)
    }
}

impl From<&[u32]> for Oid {
    fn from(s: &[u32]) -> Self {
        Oid(s.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse() {
        let oid: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        assert_eq!(oid.components(), &[1, 3, 6, 1, 2, 1, 1, 1, 0]);
    }

    #[test]
    fn test_parse_with_leading_dot() {
        let oid: Oid = ".1.3.6.1".parse().unwrap();
        assert_eq!(oid.components(), &[1, 3, 6, 1]);
    }

    #[test]
    fn test_display() {
        let oid = Oid::new(vec![1, 3, 6, 1, 2, 1]);
        assert_eq!(oid.to_string(), "1.3.6.1.2.1");
    }

    #[test]
    fn test_ordering() {
        let a: Oid = "1.3.6.1.2".parse().unwrap();
        let b: Oid = "1.3.6.1.10".parse().unwrap();
        assert!(a < b);
    }

    #[test]
    fn test_prefix() {
        let prefix: Oid = "1.3.6.1".parse().unwrap();
        let child: Oid = "1.3.6.1.2.1.1.1.0".parse().unwrap();
        assert!(prefix.is_prefix_of(&child));
        assert!(!child.is_prefix_of(&prefix));
    }
}
