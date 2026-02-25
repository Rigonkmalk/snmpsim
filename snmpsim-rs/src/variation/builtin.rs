//! Built-in variation modules.
//!
//! These replace the Python variation modules (delay.py, error.py, etc.).

use std::collections::HashMap;
use std::time::Duration;

use crate::error::Result;
use crate::snmp_value::SnmpValue;
use crate::variation::{VariationContext, VariationModule, VariationResult};

// ─── Delay module ────────────────────────────────────────────────────────────

/// Adds a configurable delay before returning a value.
///
/// Options: `value=<SnmpValue>&delay=<milliseconds>`
pub struct DelayModule;

impl DelayModule {
    pub fn new() -> Self {
        DelayModule
    }
}

impl VariationModule for DelayModule {
    fn name(&self) -> &str {
        "delay"
    }

    fn init(&mut self, _options: &str, _mode: &str) -> Result<()> {
        Ok(())
    }

    fn variate(&self, ctx: &mut VariationContext) -> Result<VariationResult> {
        let params = parse_kv(&ctx.value);

        let delay_ms: u64 = params
            .get("delay")
            .and_then(|v| v.parse().ok())
            .unwrap_or(500);

        // In async context we'd use tokio::time::sleep; here we block briefly.
        // In production, this would be integrated with the async server.
        std::thread::sleep(Duration::from_millis(delay_ms));

        let value_str = params.get("value").map(|s| s.as_str()).unwrap_or("");
        let value = parse_value_from_tag(&ctx.tag, value_str)?;

        Ok(VariationResult {
            oid: ctx.oid.clone(),
            tag: ctx.tag.clone(),
            value,
        })
    }

    fn shutdown(&mut self, _options: &str, _mode: &str) -> Result<()> {
        Ok(())
    }
}

// ─── Error module ────────────────────────────────────────────────────────────

/// Returns SNMP error statuses instead of values.
///
/// Options: `error=<status_code>&value=<SnmpValue>`
pub struct ErrorModule;

impl ErrorModule {
    pub fn new() -> Self {
        ErrorModule
    }
}

impl VariationModule for ErrorModule {
    fn name(&self) -> &str {
        "error"
    }

    fn init(&mut self, _options: &str, _mode: &str) -> Result<()> {
        Ok(())
    }

    fn variate(&self, ctx: &mut VariationContext) -> Result<VariationResult> {
        let params = parse_kv(&ctx.value);

        // error status to embed in value
        let error = params
            .get("error")
            .map(|s| s.as_str())
            .unwrap_or("noSuchInstance");

        let value = match error {
            "noSuchObject" => SnmpValue::NoSuchObject,
            "noSuchInstance" => SnmpValue::NoSuchInstance,
            "endOfMibView" => SnmpValue::EndOfMibView,
            _ => SnmpValue::NoSuchInstance,
        };

        Ok(VariationResult {
            oid: ctx.oid.clone(),
            tag: ctx.tag.clone(),
            value,
        })
    }

    fn shutdown(&mut self, _options: &str, _mode: &str) -> Result<()> {
        Ok(())
    }
}

// ─── Numeric module ───────────────────────────────────────────────────────────

/// Generates incrementing/oscillating numeric values.
///
/// Options: `min=<n>&max=<n>&start=<n>&step=<n>&function=<inc|osc>`
pub struct NumericModule;

impl NumericModule {
    pub fn new() -> Self {
        NumericModule
    }
}

impl VariationModule for NumericModule {
    fn name(&self) -> &str {
        "numeric"
    }

    fn init(&mut self, _options: &str, _mode: &str) -> Result<()> {
        Ok(())
    }

    fn variate(&self, ctx: &mut VariationContext) -> Result<VariationResult> {
        let params = parse_kv(&ctx.value);

        let min: i64 = params.get("min").and_then(|v| v.parse().ok()).unwrap_or(0);
        // Default max to i64::MAX so an unspecified max never causes wrapping
        let max: i64 = params.get("max").and_then(|v| v.parse().ok()).unwrap_or(i64::MAX);
        // `initial` is a Python-snmpsim alias for the starting value
        let initial: i64 = params.get("initial").and_then(|v| v.parse().ok()).unwrap_or(min);
        let start: i64 = params.get("start").and_then(|v| v.parse().ok()).unwrap_or(initial);
        // `rate` is a Python-snmpsim alias for the per-poll step size
        let rate: i64 = params.get("rate").and_then(|v| v.parse().ok()).unwrap_or(1);
        let step: i64 = params.get("step").and_then(|v| v.parse().ok()).unwrap_or(rate);
        let function = params.get("function").map(|s| s.as_str()).unwrap_or("inc");

        // Get current value from record context
        let current: i64 = ctx
            .record_context
            .get("current")
            .and_then(|v| v.parse().ok())
            .unwrap_or(start);

        let next = match function {
            "inc" => {
                let v = current + step;
                if v > max {
                    min
                } else {
                    v
                }
            }
            "osc" => {
                let direction: i64 = ctx
                    .record_context
                    .get("direction")
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(1);
                let v = current + step * direction;
                if v >= max {
                    ctx.record_context.insert("direction".into(), "-1".into());
                    max
                } else if v <= min {
                    ctx.record_context.insert("direction".into(), "1".into());
                    min
                } else {
                    v
                }
            }
            _ => current + step,
        };

        ctx.record_context
            .insert("current".into(), next.to_string());

        // Determine value type from tag
        let value = match ctx.tag.as_str() {
            "2" => SnmpValue::Integer(next),
            "65" => SnmpValue::Counter32(next as u32),
            "66" => SnmpValue::Gauge32(next as u32),
            "67" => SnmpValue::TimeTicks(next as u32),
            "70" => SnmpValue::Counter64(next as u64),
            _ => SnmpValue::Integer(next),
        };

        Ok(VariationResult {
            oid: ctx.oid.clone(),
            tag: ctx.tag.clone(),
            value,
        })
    }

    fn shutdown(&mut self, _options: &str, _mode: &str) -> Result<()> {
        Ok(())
    }
}

// ─── WriteCache module ────────────────────────────────────────────────────────

/// Caches SET values and returns them on subsequent GETs.
pub struct WriteCacheModule {
    cache: std::sync::Mutex<HashMap<String, SnmpValue>>,
}

impl WriteCacheModule {
    pub fn new() -> Self {
        WriteCacheModule {
            cache: std::sync::Mutex::new(HashMap::new()),
        }
    }
}

impl VariationModule for WriteCacheModule {
    fn name(&self) -> &str {
        "writecache"
    }

    fn init(&mut self, _options: &str, _mode: &str) -> Result<()> {
        Ok(())
    }

    fn variate(&self, ctx: &mut VariationContext) -> Result<VariationResult> {
        let key = ctx.oid.to_string();

        if ctx.set_flag {
            // Cache the incoming value (from origValue in Python)
            // For now, just acknowledge the SET
            let value = parse_value_from_tag(&ctx.tag, &ctx.value)?;
            if let Ok(mut cache) = self.cache.lock() {
                cache.insert(key.clone(), value.clone());
                return Ok(VariationResult {
                    oid: ctx.oid.clone(),
                    tag: ctx.tag.clone(),
                    value,
                });
            }
        }

        // GET: return cached value or parse default
        if let Ok(cache) = self.cache.lock() {
            if let Some(cached) = cache.get(&key) {
                return Ok(VariationResult {
                    oid: ctx.oid.clone(),
                    tag: ctx.tag.clone(),
                    value: cached.clone(),
                });
            }
        }

        // Return the default value from the record
        let value = parse_value_from_tag(&ctx.tag, &ctx.value)?;
        Ok(VariationResult {
            oid: ctx.oid.clone(),
            tag: ctx.tag.clone(),
            value,
        })
    }

    fn shutdown(&mut self, _options: &str, _mode: &str) -> Result<()> {
        Ok(())
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Parse a `key=value,key2=value2` style options string.
/// Both `,` and `&` are accepted as pair separators.
fn parse_kv(s: &str) -> HashMap<String, String> {
    s.split(|c| c == ',' || c == '&')
        .filter_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next()?.trim().to_string();
            let val = parts.next().unwrap_or("").trim().to_string();
            if key.is_empty() {
                None
            } else {
                Some((key, val))
            }
        })
        .collect()
}

/// Parse a value string given a snmprec numeric tag.
fn parse_value_from_tag(tag: &str, value_str: &str) -> Result<SnmpValue> {
    // Re-use snmprec record logic
    use crate::record::snmprec::SnmprecRecord;
    use crate::record::{EvalContext, Record};
    let record = SnmprecRecord::new();
    let ctx = EvalContext {
        exact_match: true,
        ..Default::default()
    };
    let dummy_oid = crate::oid::Oid::new(vec![1]);
    record.evaluate_value(&dummy_oid, tag, value_str, &ctx)
}
