//! Variation module support.
//!
//! Variation modules allow dynamic SNMP responses. This module provides
//! the trait definition and built-in implementations (delay, error, numeric).
//!
//! The Python version dynamically loads .py files with exec(); the Rust version
//! uses statically-linked built-in modules with a registration mechanism.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::Result;
use crate::oid::Oid;
use crate::snmp_value::SnmpValue;

pub mod builtin;

/// Context passed to a variation module when variating a value.
#[derive(Debug, Clone)]
pub struct VariationContext {
    pub oid: Oid,
    pub tag: String,
    pub value: String,
    pub next_flag: bool,
    pub set_flag: bool,
    pub exact_match: bool,
    pub data_file: String,
    /// Module options string (from --variation-module-options).
    pub options: String,
    /// Per-record state (persists for an OID across calls).
    pub record_context: HashMap<String, String>,
    /// Per-agent state (persists for a data file across calls).
    pub agent_context: HashMap<String, String>,
}

/// Result returned by a variation module.
pub struct VariationResult {
    pub oid: Oid,
    pub tag: String,
    pub value: SnmpValue,
}

/// Trait that all variation modules must implement.
pub trait VariationModule: Send + Sync {
    /// Called once when the module is loaded.
    fn init(&mut self, options: &str, mode: &str) -> Result<()>;

    /// Called for each record that references this module.
    fn variate(&self, ctx: &mut VariationContext) -> Result<VariationResult>;

    /// Called when the module is unloaded.
    fn shutdown(&mut self, options: &str, mode: &str) -> Result<()>;

    /// Module name.
    fn name(&self) -> &str;
}

/// Registry of loaded variation modules.
pub struct VariationModuleRegistry {
    modules: HashMap<String, Arc<dyn VariationModule>>,
}

impl VariationModuleRegistry {
    pub fn new() -> Self {
        VariationModuleRegistry {
            modules: HashMap::new(),
        }
    }

    /// Register a built-in variation module.
    pub fn register(&mut self, module: Arc<dyn VariationModule>) {
        self.modules.insert(module.name().to_string(), module);
    }

    /// Look up a module by name.
    pub fn get(&self, name: &str) -> Option<&Arc<dyn VariationModule>> {
        self.modules.get(name)
    }

    /// Return all registered module names.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.modules.keys().map(|s| s.as_str())
    }

    /// Create a registry with all built-in modules pre-registered.
    pub fn with_builtins() -> Self {
        let mut registry = Self::new();
        registry.register(Arc::new(builtin::DelayModule::new()));
        registry.register(Arc::new(builtin::ErrorModule::new()));
        registry.register(Arc::new(builtin::NumericModule::new()));
        registry.register(Arc::new(builtin::WriteCacheModule::new()));
        registry
    }
}

impl Default for VariationModuleRegistry {
    fn default() -> Self {
        Self::with_builtins()
    }
}
