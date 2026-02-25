//! Record implementation for .snmpwalk format files.

use std::str::FromStr;

use crate::error::Result;
use crate::grammar::walk::WalkGrammar;
use crate::grammar::Grammar;
use crate::oid::Oid;
use crate::record::snmprec::SnmprecRecord;
use crate::record::{EvalContext, Record};
use crate::snmp_value::SnmpValue;

/// Record handler for .snmpwalk files.
/// Parsing uses WalkGrammar, but value evaluation re-uses SnmprecRecord logic.
pub struct WalkRecord {
    grammar: WalkGrammar,
    snmprec: SnmprecRecord,
}

impl WalkRecord {
    pub fn new() -> Self {
        WalkRecord {
            grammar: WalkGrammar::new(),
            snmprec: SnmprecRecord::new(),
        }
    }
}

impl Default for WalkRecord {
    fn default() -> Self {
        WalkRecord::new()
    }
}

impl Record for WalkRecord {
    fn grammar(&self) -> &dyn Grammar {
        &self.grammar
    }

    fn extension(&self) -> &str {
        "snmpwalk"
    }

    fn evaluate_oid(&self, oid_str: &str) -> Result<Oid> {
        Oid::from_str(oid_str)
    }

    fn evaluate_value(&self, oid: &Oid, tag: &str, value_str: &str, ctx: &EvalContext) -> Result<SnmpValue> {
        // Walk grammar already converts tags to snmprec numeric tags
        self.snmprec.evaluate_value(oid, tag, value_str, ctx)
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
        self.snmprec.format_value(oid, value)
    }
}
