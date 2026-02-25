//! Activity metrics reporting.
//!
//! Mirrors the Python snmpsim.reporting module.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// A counter set for a single data file or variation module.
#[derive(Debug, Default)]
pub struct Metrics {
    pub transport_calls: AtomicU64,
    pub datafile_calls: AtomicU64,
    pub datafile_failures: AtomicU64,
    pub varbind_count: AtomicU64,
    pub variation_calls: AtomicU64,
    pub variation_failures: AtomicU64,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    pub fn transport_calls(&self) -> u64 {
        self.transport_calls.load(Ordering::Relaxed)
    }

    pub fn datafile_calls(&self) -> u64 {
        self.datafile_calls.load(Ordering::Relaxed)
    }

    pub fn varbind_count(&self) -> u64 {
        self.varbind_count.load(Ordering::Relaxed)
    }
}

/// Central reporting manager.
///
/// Accumulates metrics per data file and optionally flushes them
/// to a configured reporter (null, JSON file, etc.).
pub struct ReportingManager {
    metrics: Mutex<HashMap<String, Arc<Metrics>>>,
    reporter: Box<dyn Reporter>,
}

impl ReportingManager {
    pub fn new(reporter: Box<dyn Reporter>) -> Self {
        ReportingManager {
            metrics: Mutex::new(HashMap::new()),
            reporter,
        }
    }

    /// Create a manager that silently discards all metrics.
    pub fn null() -> Self {
        Self::new(Box::new(NullReporter))
    }

    /// Create a manager that writes JSON metrics to a file.
    pub fn json(path: &str) -> Self {
        Self::new(Box::new(JsonReporter {
            path: path.to_string(),
        }))
    }

    /// Update metrics for a data file.
    pub fn update(
        &self,
        data_file: &str,
        transport_call: bool,
        datafile_call: bool,
        datafile_failure: bool,
        varbind_count: u64,
    ) {
        let metrics = {
            let mut map = self.metrics.lock().unwrap();
            Arc::clone(
                map.entry(data_file.to_string())
                    .or_insert_with(Metrics::new),
            )
        };

        if transport_call {
            metrics.transport_calls.fetch_add(1, Ordering::Relaxed);
        }
        if datafile_call {
            metrics.datafile_calls.fetch_add(1, Ordering::Relaxed);
        }
        if datafile_failure {
            metrics.datafile_failures.fetch_add(1, Ordering::Relaxed);
        }
        metrics.varbind_count.fetch_add(varbind_count, Ordering::Relaxed);
    }

    /// Flush accumulated metrics to the configured reporter.
    pub fn flush(&self) {
        let map = self.metrics.lock().unwrap();
        self.reporter.report(&map);
    }
}

// ─── Reporter trait ───────────────────────────────────────────────────────────

pub trait Reporter: Send + Sync {
    fn report(&self, metrics: &HashMap<String, Arc<Metrics>>);
}

/// Discards all metrics.
pub struct NullReporter;

impl Reporter for NullReporter {
    fn report(&self, _metrics: &HashMap<String, Arc<Metrics>>) {}
}

/// Writes metrics as JSON to a file.
pub struct JsonReporter {
    path: String,
}

impl Reporter for JsonReporter {
    fn report(&self, metrics: &HashMap<String, Arc<Metrics>>) {
        use std::io::Write;
        let mut entries = Vec::new();
        for (file, m) in metrics {
            entries.push(serde_json::json!({
                "dataFile": file,
                "transportCalls": m.transport_calls(),
                "datafileCalls": m.datafile_calls(),
                "varbindCount": m.varbind_count(),
            }));
        }
        let json = serde_json::to_string_pretty(&entries).unwrap_or_default();
        if let Ok(mut f) = std::fs::File::create(&self.path) {
            let _ = f.write_all(json.as_bytes());
        }
    }
}
