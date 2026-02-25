//! Simulation data file management.
//!
//! Replaces the Python datafile.py + record/search modules.
//! Uses an in-memory BTreeMap index instead of the dbm on-disk index,
//! enabling fast OID lookups without filesystem-dependent dbm libraries.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tracing::{error, info, warn};

use crate::error::{Result, SnmpsimError};
use crate::oid::Oid;
use crate::record::{EvalContext, Record};
use crate::snmp_value::SnmpValue;

/// Label used when context engine ID matches "self".
pub const SELF_LABEL: &str = "self";

// ─── Index entry ──────────────────────────────────────────────────────────────

/// Entry in the OID index for a data file.
#[derive(Debug, Clone)]
pub struct IndexEntry {
    /// Byte offset of the record line in the data file.
    pub offset: u64,
    /// True if this OID record serves a subtree (tag starts with ':').
    pub subtree_flag: bool,
    /// Byte offset of the previous subtree record, if any.
    pub prev_offset: Option<u64>,
}

// ─── DataFile ─────────────────────────────────────────────────────────────────

/// A loaded simulation data file with an in-memory OID index.
pub struct DataFile {
    /// Path to the data file on disk.
    pub path: PathBuf,
    /// Record parser for this file type.
    record: Arc<dyn Record>,
    /// In-memory sorted OID index: OID → IndexEntry.
    index: BTreeMap<Oid, IndexEntry>,
    /// Last-entry sentinel used for GETNEXT past end-of-file.
    last_offset: u64,
}

impl DataFile {
    /// Load a data file and build its in-memory OID index.
    pub fn load(path: &Path, record: Arc<dyn Record>) -> Result<Self> {
        info!("Indexing data file {:?}", path);
        let index = build_index(path, record.as_ref())?;
        let last_offset = index
            .values()
            .map(|e| e.offset)
            .max()
            .map(|o| o + 1)
            .unwrap_or(0);
        info!("Indexed {} OID entries in {:?}", index.len(), path);
        Ok(DataFile {
            path: path.to_path_buf(),
            record,
            index,
            last_offset,
        })
    }

    /// Return the record parser.
    pub fn record(&self) -> &dyn Record {
        self.record.as_ref()
    }

    /// Return the number of OIDs in the index.
    pub fn len(&self) -> usize {
        self.index.len()
    }

    pub fn is_empty(&self) -> bool {
        self.index.is_empty()
    }

    /// Process a list of var-bind requests and return the response var-binds.
    pub fn process_var_binds(
        &self,
        requests: &[(Oid, SnmpValue)],
        next_flag: bool,
        set_flag: bool,
    ) -> Vec<(Oid, SnmpValue)> {
        let error_value = if next_flag {
            SnmpValue::EndOfMibView
        } else {
            SnmpValue::NoSuchInstance
        };

        let mut responses = Vec::with_capacity(requests.len());

        for (req_oid, _req_val) in requests {
            let result = if next_flag {
                self.get_next(req_oid)
            } else {
                self.get_exact(req_oid, set_flag)
            };

            match result {
                Ok(Some((oid, val))) => responses.push((oid, val)),
                Ok(None) => responses.push((req_oid.clone(), error_value.clone())),
                Err(e) => {
                    error!("Error processing OID {}: {}", req_oid, e);
                    responses.push((req_oid.clone(), error_value.clone()));
                }
            }
        }

        responses
    }

    /// GET: look up an exact OID match.
    fn get_exact(&self, oid: &Oid, set_flag: bool) -> Result<Option<(Oid, SnmpValue)>> {
        // Check for exact match
        if let Some(entry) = self.index.get(oid) {
            let line = self.read_line_at(entry.offset)?;
            let ctx = EvalContext {
                exact_match: true,
                subtree_flag: entry.subtree_flag,
                orig_oid: Some(oid.clone()),
                set_flag,
                ..Default::default()
            };
            let (result_oid, val) = self.record.evaluate(&line, &ctx)?;
            return Ok(val.map(|v| (result_oid, v)));
        }

        // Check for subtree match: find the nearest OID before `oid` that is a subtree
        if let Some((_subtree_oid, entry)) = self.find_subtree_for(oid) {
            if entry.subtree_flag {
                let line = self.read_line_at(entry.offset)?;
                let ctx = EvalContext {
                    exact_match: true,
                    subtree_flag: true,
                    orig_oid: Some(oid.clone()),
                    set_flag,
                    ..Default::default()
                };
                let (_, val) = self.record.evaluate(&line, &ctx)?;
                return Ok(val.map(|v| (oid.clone(), v)));
            }
        }

        Ok(None)
    }

    /// GETNEXT: find the OID that lexicographically follows `oid`.
    fn get_next(&self, oid: &Oid) -> Result<Option<(Oid, SnmpValue)>> {
        // Check if oid is in index and is a subtree - if so, return it
        if let Some(entry) = self.index.get(oid) {
            if entry.subtree_flag {
                // Subtree record - return it for the requested OID
                let line = self.read_line_at(entry.offset)?;
                let ctx = EvalContext {
                    next_flag: true,
                    exact_match: true,
                    subtree_flag: true,
                    orig_oid: Some(oid.clone()),
                    ..Default::default()
                };
                let (_, val) = self.record.evaluate(&line, &ctx)?;
                return Ok(val.map(|v| (oid.clone(), v)));
            }
        }

        // Find the next OID in the index after `oid`
        use std::ops::Bound;
        let next = self
            .index
            .range((Bound::Excluded(oid), Bound::Unbounded))
            .next();

        match next {
            Some((next_oid, entry)) => {
                let line = self.read_line_at(entry.offset)?;
                let ctx = EvalContext {
                    next_flag: true,
                    exact_match: true,
                    subtree_flag: entry.subtree_flag,
                    orig_oid: Some(oid.clone()),
                    ..Default::default()
                };
                let (result_oid, val) = self.record.evaluate(&line, &ctx)?;
                Ok(val.map(|v| (result_oid, v)))
            }
            None => {
                // Check for subtree covering this oid
                if let Some((_subtree_oid, entry)) = self.find_subtree_for(oid) {
                    if entry.subtree_flag {
                        let line = self.read_line_at(entry.offset)?;
                        let ctx = EvalContext {
                            next_flag: true,
                            exact_match: true,
                            subtree_flag: true,
                            orig_oid: Some(oid.clone()),
                            ..Default::default()
                        };
                        let (_, val) = self.record.evaluate(&line, &ctx)?;
                        return Ok(val.map(|v| (oid.clone(), v)));
                    }
                }
                Ok(None) // endOfMibView
            }
        }
    }

    /// Find the closest subtree OID that is a prefix of `oid`.
    fn find_subtree_for(&self, oid: &Oid) -> Option<(&Oid, &IndexEntry)> {
        use std::ops::Bound;
        // Look backwards from oid
        self.index
            .range((Bound::Unbounded, Bound::Excluded(oid)))
            .rev()
            .find(|(candidate, entry)| entry.subtree_flag && candidate.is_prefix_of(oid))
    }

    /// Read the raw line bytes at a given file offset.
    fn read_line_at(&self, offset: u64) -> Result<Vec<u8>> {
        let mut file = fs::File::open(&self.path)?;
        file.seek(SeekFrom::Start(offset))?;
        let mut reader = BufReader::new(file);
        let mut line = Vec::new();
        reader.read_until(b'\n', &mut line)?;
        Ok(line)
    }
}

impl std::fmt::Display for DataFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "DataFile({:?})", self.path)
    }
}

// ─── Index building ───────────────────────────────────────────────────────────

/// Read the next non-comment, non-blank line from a reader, tracking offset.
pub fn read_record<R: BufRead>(
    reader: &mut R,
    offset: &mut u64,
) -> Result<Option<Vec<u8>>> {
    loop {
        let mut line = Vec::new();
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            return Ok(None); // EOF
        }
        let trimmed = line.trim_ascii();
        if !trimmed.is_empty() && !trimmed.starts_with(b"#") {
            *offset += bytes_read as u64;
            return Ok(Some(line));
        }
        *offset += bytes_read as u64;
    }
}

/// Build the in-memory OID index from a data file.
fn build_index(path: &Path, record: &dyn Record) -> Result<BTreeMap<Oid, IndexEntry>> {
    let mut index = BTreeMap::new();

    let reader_box = record.open(path)?;
    let mut reader = BufReader::new(reader_box);

    let mut current_offset: u64 = 0;
    let mut prev_subtree_offset: Option<u64> = None;

    loop {
        let line_start = current_offset;
        let mut line = Vec::new();
        let bytes_read = reader.read_until(b'\n', &mut line)?;
        if bytes_read == 0 {
            break;
        }
        current_offset += bytes_read as u64;

        let trimmed = line.trim_ascii();
        if trimmed.is_empty() || trimmed.starts_with(b"#") {
            continue;
        }

        match record.grammar().parse(&line) {
            Ok((oid_str, tag, _value)) => {
                match record.evaluate_oid(&oid_str) {
                    Ok(oid) => {
                        let subtree_flag = tag.starts_with(':');
                        index.insert(
                            oid,
                            IndexEntry {
                                offset: line_start,
                                subtree_flag,
                                prev_offset: prev_subtree_offset,
                            },
                        );
                        if subtree_flag {
                            prev_subtree_offset = Some(line_start);
                        } else {
                            prev_subtree_offset = None;
                        }
                    }
                    Err(e) => {
                        warn!("Skipping invalid OID at offset {}: {}", line_start, e);
                    }
                }
            }
            Err(e) => {
                warn!("Skipping unparseable line at offset {}: {}", line_start, e);
            }
        }
    }

    Ok(index)
}

// ─── Data file discovery ──────────────────────────────────────────────────────

/// Describes the file extensions we recognise as simulation data.
pub const KNOWN_EXTENSIONS: &[&str] = &["snmprec", "snmprec.bz2", "dump", "snmpwalk", "walk", "mvc", "sap"];

/// Scan a directory tree and return all simulation data files with their
/// community/context name (derived from relative path).
pub fn get_data_files(
    dir: &Path,
) -> Result<Vec<(PathBuf, String, String)>> {
    let mut results = Vec::new();
    collect_data_files(dir, dir, &mut results)?;
    Ok(results)
}

fn collect_data_files(
    base: &Path,
    dir: &Path,
    results: &mut Vec<(PathBuf, String, String)>,
) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::metadata(&path)?;

        if metadata.is_dir() {
            collect_data_files(base, &path, results)?;
            continue;
        }

        if !metadata.is_file() {
            continue;
        }

        let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Find matching extension
        let ext = KNOWN_EXTENSIONS
            .iter()
            .find(|&&ext| filename.ends_with(&format!(".{}", ext)));

        let ext = match ext {
            Some(e) => e,
            None => continue,
        };

        // Derive community/context name from relative path
        let rel = path
            .strip_prefix(base)
            .map_err(|e| SnmpsimError::Config(e.to_string()))?;

        let community = derive_community_name(rel, ext);

        results.push((path.clone(), ext.to_string(), community));
    }
    Ok(())
}

/// Derive the SNMP community/context name from a relative file path.
///
/// For example:
/// - `public.snmprec`          → `"public"`
/// - `self/public.snmprec`     → `"public"`
/// - `1.3.6.1.6.1.1.0/127.0.0.1.snmprec` → `"1.3.6.1.6.1.1.0/127.0.0.1"`
fn derive_community_name(rel: &Path, ext: &str) -> String {
    // Remove extension
    let stem = rel.to_string_lossy();
    let dot_ext = format!(".{}", ext);
    let name = if stem.ends_with(&dot_ext) {
        stem[..stem.len() - dot_ext.len()].to_string()
    } else {
        stem.to_string()
    };

    // Strip "self/" prefix
    let name = if name.starts_with("self/") || name.starts_with("self\\") {
        name[5..].to_string()
    } else {
        name
    };

    // Normalise path separators
    name.replace('\\', "/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_community_name() {
        let p = Path::new("public.snmprec");
        assert_eq!(derive_community_name(p, "snmprec"), "public");

        let p = Path::new("self/public.snmprec");
        assert_eq!(derive_community_name(p, "snmprec"), "public");
    }
}
