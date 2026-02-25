//! Default configuration directories.
//!
//! Mirrors the Python snmpsim.confdir module.

use std::env;
use std::path::PathBuf;

/// Return the default data directories to search for simulation files.
pub fn data_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(home) = env::var("HOME") {
        dirs.push(PathBuf::from(&home).join(".snmpsim").join("data"));
    }

    #[cfg(target_os = "macos")]
    dirs.push(PathBuf::from("/usr/local/share/snmpsim/data"));

    dirs.push(PathBuf::from("/usr/share/snmpsim/data"));
    dirs.push(PathBuf::from("/usr/local/share/snmpsim/data"));

    dirs
}

/// Return the default variation modules directories.
pub fn variation_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Ok(home) = env::var("HOME") {
        dirs.push(PathBuf::from(&home).join(".snmpsim").join("variation"));
    }

    #[cfg(target_os = "macos")]
    dirs.push(PathBuf::from("/usr/local/share/snmpsim/variation"));

    dirs.push(PathBuf::from("/usr/share/snmpsim/variation"));
    dirs.push(PathBuf::from("/usr/local/share/snmpsim/variation"));

    dirs
}

/// Return the default cache directory (for index files).
pub fn cache_dir() -> PathBuf {
    env::temp_dir().join("snmpsim")
}
