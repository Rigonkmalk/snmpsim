//! SNMP Agent Simulator library
//!
//! Rust port of the Python snmpsim package.
//! Provides SNMP v1/v2c/v3 simulation from .snmprec data files.

pub mod error;
pub mod oid;
pub mod snmp_value;
pub mod ber;
pub mod grammar;
pub mod record;
pub mod datafile;
pub mod confdir;
pub mod daemon;
pub mod variation;
pub mod reporting;
pub mod server;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
