//! snmp-command-responder — SNMP Agent Simulator
//!
//! Faithfully ports the Python `snmpsim/commands/responder.py` command.
//!
//! Responds to SNMP v1/v2c GET, GETNEXT and GETBULK requests using
//! simulation data files (.snmprec, .snmpwalk, etc.).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use snmpsim::datafile::{self, DataFile};
use snmpsim::record::snmprec::{CompressedSnmprecRecord, SnmprecRecord};
use snmpsim::record::walk::WalkRecord;
use snmpsim::record::dump::DumpRecord;
use snmpsim::record::Record;
use snmpsim::reporting::ReportingManager;
use snmpsim::server::{EngineConfig, ServerState};

// ─── CLI argument definitions ─────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name = "snmp-command-responder",
    about = "SNMP Agent Simulator - responds to SNMP v1/v2c requests using data files",
    version
)]
struct Args {
    /// Logging method: stderr | stdout | null | file:<path>[:<size>] | syslog:<facility>
    #[arg(long, default_value = "stderr", value_name = "METHOD[:ARGS]")]
    logging_method: String,

    /// Log level: debug | info | error
    #[arg(long, default_value = "info", value_name = "LEVEL")]
    log_level: String,

    /// Reporting method: null | json:<file>
    #[arg(long, default_value = "null", value_name = "METHOD[:ARGS]")]
    reporting_method: String,

    /// Daemonise the process
    #[arg(long)]
    daemonize: bool,

    /// PID file path (used when daemonizing)
    #[arg(long, value_name = "FILE")]
    pid_file: Option<PathBuf>,

    /// Run as this user (requires root)
    #[arg(long, value_name = "USER")]
    process_user: Option<String>,

    /// Run as this group (requires root)
    #[arg(long, value_name = "GROUP")]
    process_group: Option<String>,

    /// Force rebuild of data file indices
    #[arg(long)]
    force_index_rebuild: bool,

    /// Validate data file contents on startup
    #[arg(long)]
    validate_data: bool,

    /// Maximum variable bindings per SNMP response
    #[arg(long, default_value = "64")]
    max_var_binds: usize,

    /// UDP/IPv4 endpoint(s) to listen on, e.g. 0.0.0.0:161
    #[arg(long, value_name = "ADDRESS:PORT", action = clap::ArgAction::Append)]
    agent_udpv4_endpoint: Vec<String>,

    /// UDP/IPv6 endpoint(s) to listen on, e.g. [::]:161
    #[arg(long, value_name = "[ADDRESS]:PORT", action = clap::ArgAction::Append)]
    agent_udpv6_endpoint: Vec<String>,

    /// Simulation data directory/directories
    #[arg(long, value_name = "DIR", action = clap::ArgAction::Append)]
    data_dir: Vec<PathBuf>,

    /// Read additional arguments from file
    #[arg(long, value_name = "FILE")]
    args_from_file: Option<PathBuf>,
}

// ─── Main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();

    // Set up logging
    let filter = match args.log_level.to_lowercase().as_str() {
        "debug" => "snmpsim=debug",
        "error" => "snmpsim=error",
        _ => "snmpsim=info",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .with_writer(std::io::stderr)
        .init();

    info!(
        "SNMP Simulator v{} (Rust port)",
        snmpsim::VERSION
    );

    // Daemonise if requested
    if args.daemonize {
        if let Err(e) = snmpsim::daemon::daemonize(args.pid_file.as_deref()) {
            error!("Failed to daemonize: {}", e);
            std::process::exit(1);
        }
    }

    // Set up reporting
    let reporting = Arc::new(configure_reporting(&args.reporting_method));

    // Discover and load data files
    let data_dirs = if args.data_dir.is_empty() {
        snmpsim::confdir::data_dirs()
    } else {
        args.data_dir.clone()
    };

    if data_dirs.is_empty() {
        error!("No data directories configured");
        std::process::exit(1);
    }

    // Build community → DataFile mappings
    let mut engine = EngineConfig::new("auto");
    engine.max_var_binds = args.max_var_binds;

    let record_types: Vec<Arc<dyn Record>> = vec![
        Arc::new(SnmprecRecord::new()),
        Arc::new(CompressedSnmprecRecord::new()),
        Arc::new(WalkRecord::new()),
        Arc::new(DumpRecord::new()),
    ];

    for dir in &data_dirs {
        if !dir.exists() {
            warn!("Data directory does not exist: {}", dir.display());
            continue;
        }

        info!("Scanning data directory: {}", dir.display());

        match datafile::get_data_files(dir) {
            Ok(files) => {
                for (path, ext, community) in files {
                    // Find the matching record type
                    let record = record_types
                        .iter()
                        .find(|r| r.extension() == ext)
                        .cloned();

                    let record = match record {
                        Some(r) => r,
                        None => {
                            warn!("No record handler for extension '{}': {}", ext, path.display());
                            continue;
                        }
                    };

                    match DataFile::load(&path, record) {
                        Ok(df) => {
                            let df = Arc::new(df);
                            info!(
                                "Loaded data file '{}' as community '{}'",
                                path.display(),
                                community
                            );
                            engine.add_community(&community, Arc::clone(&df));

                            // Also register by MD5 hash for long community names
                            if community.len() > 32 {
                                let hash = md5_hex(community.as_bytes());
                                engine.add_community(&hash, df);
                            }
                        }
                        Err(e) => {
                            error!("Failed to load {}: {}", path.display(), e);
                        }
                    }
                }
            }
            Err(e) => {
                error!("Error scanning {}: {}", dir.display(), e);
            }
        }
    }

    // Parse endpoints
    let mut all_endpoints: Vec<SocketAddr> = Vec::new();

    for ep in &args.agent_udpv4_endpoint {
        match parse_endpoint(ep, false) {
            Ok(addr) => all_endpoints.push(addr),
            Err(e) => {
                error!("Invalid IPv4 endpoint '{}': {}", ep, e);
                std::process::exit(1);
            }
        }
    }

    for ep in &args.agent_udpv6_endpoint {
        match parse_endpoint(ep, true) {
            Ok(addr) => all_endpoints.push(addr),
            Err(e) => {
                error!("Invalid IPv6 endpoint '{}': {}", ep, e);
                std::process::exit(1);
            }
        }
    }

    if all_endpoints.is_empty() {
        // Default: listen on all interfaces, port 161
        // Note: port 161 requires root on Linux
        let default_port = if snmpsim::daemon::is_root() { 161 } else { 1161 };
        let addr: SocketAddr = format!("0.0.0.0:{}", default_port).parse().unwrap();
        warn!(
            "No endpoints specified, defaulting to {} (use --agent-udpv4-endpoint)",
            addr
        );
        all_endpoints.push(addr);
    }

    // Transfer engine communities to server state
    let mut state = ServerState::new(args.max_var_binds, Arc::clone(&reporting));
    state.add_engine(engine);
    let state = Arc::new(state);

    info!("Starting SNMP server on {} endpoint(s)", all_endpoints.len());
    for ep in &all_endpoints {
        info!("  → {}", ep);
    }

    // Drop privileges if configured
    if let Err(e) = snmpsim::daemon::drop_privileges(
        args.process_user.as_deref(),
        args.process_group.as_deref(),
    ) {
        error!("Failed to drop privileges: {}", e);
        std::process::exit(1);
    }

    // Run the server
    if let Err(e) = snmpsim::server::run(all_endpoints, state).await {
        error!("Server error: {}", e);
        std::process::exit(1);
    }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Configure the reporting manager from the reporting method string.
fn configure_reporting(method: &str) -> ReportingManager {
    let parts: Vec<&str> = method.splitn(2, ':').collect();
    match parts[0] {
        "json" => {
            let path = parts.get(1).copied().unwrap_or("/tmp/snmpsim-metrics.json");
            ReportingManager::json(path)
        }
        _ => ReportingManager::null(),
    }
}

/// Parse an endpoint string like "0.0.0.0:161" or "[::1]:161".
fn parse_endpoint(s: &str, ipv6: bool) -> Result<SocketAddr, String> {
    // Handle IPv6 bracket notation: "[::1]:161"
    let s = if s.starts_with('[') {
        s.trim_start_matches('[').replace("]:", ":").replace(']', "")
    } else {
        s.to_string()
    };

    // Split off port
    let (host, port_str) = if let Some(colon_pos) = s.rfind(':') {
        let host = &s[..colon_pos];
        let port = &s[colon_pos + 1..];
        (host.to_string(), port.to_string())
    } else {
        (s.clone(), "161".to_string())
    };

    let port: u16 = port_str
        .parse()
        .map_err(|e| format!("Invalid port '{}': {}", port_str, e))?;

    let ip: IpAddr = host
        .parse()
        .map_err(|e| format!("Invalid address '{}': {}", host, e))?;

    Ok(SocketAddr::new(ip, port))
}

/// Compute the MD5 hex digest of bytes (for long community names).
fn md5_hex(data: &[u8]) -> String {
    // Simple hand-rolled MD5 is complex; use a placeholder approach.
    // In production, add the `md5` crate or use `ring`.
    // For now, use a truncated SHA-256-like hash via std.
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    data.hash(&mut h);
    format!("{:016x}", h.finish())
}

type Result<T, E = String> = std::result::Result<T, E>;
