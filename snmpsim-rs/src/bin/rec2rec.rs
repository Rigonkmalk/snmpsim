//! snmp-rec-to-rec — Convert between simulation data file formats.
//!
//! Faithfully ports the Python `snmpsim/commands/rec2rec.py` command.
//!
//! Reads a simulation data file (snmprec, snmpwalk, dump) and writes it in
//! the specified output format.

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use tracing::{error, warn};
use tracing_subscriber::EnvFilter;

use snmpsim::grammar::Grammar;
use snmpsim::record::dump::DumpRecord;
use snmpsim::record::snmprec::SnmprecRecord;
use snmpsim::record::walk::WalkRecord;
use snmpsim::record::{EvalContext, Record};

#[derive(Debug, Clone, ValueEnum)]
enum Format {
    Snmprec,
    Walk,
    Dump,
}

impl Format {
    fn extension(&self) -> &'static str {
        match self {
            Format::Snmprec => "snmprec",
            Format::Walk => "walk",
            Format::Dump => "dump",
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "snmp-rec-to-rec",
    about = "Convert simulation data files between formats",
    version
)]
struct Args {
    /// Input file (stdin if omitted)
    #[arg(long, value_name = "FILE")]
    input_file: Option<PathBuf>,

    /// Input format (auto-detected from extension if not specified)
    #[arg(long, value_enum, value_name = "FORMAT")]
    input_format: Option<Format>,

    /// Output file (stdout if omitted)
    #[arg(long, value_name = "FILE")]
    output_file: Option<PathBuf>,

    /// Output format (default: snmprec)
    #[arg(long, value_enum, default_value = "snmprec", value_name = "FORMAT")]
    output_format: Format,

    /// Start OID: only emit records >= this OID
    #[arg(long, value_name = "OID")]
    start_oid: Option<String>,

    /// Stop OID: only emit records <= this OID
    #[arg(long, value_name = "OID")]
    stop_oid: Option<String>,

    /// Skip records that cannot be parsed
    #[arg(long)]
    continue_on_errors: bool,

    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

fn main() {
    let args = Args::parse();

    let filter = match args.log_level.to_lowercase().as_str() {
        "debug" => "snmpsim=debug",
        "error" => "snmpsim=error",
        _ => "snmpsim=info",
    };

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .with_writer(std::io::stderr)
        .init();

    // Detect input format
    let input_format = args.input_format.clone().or_else(|| {
        args.input_file.as_ref().and_then(|p| {
            let name = p.to_string_lossy();
            if name.ends_with(".snmprec") || name.ends_with(".snmprec.bz2") {
                Some(Format::Snmprec)
            } else if name.ends_with(".snmpwalk") || name.ends_with(".walk") {
                Some(Format::Walk)
            } else if name.ends_with(".dump") {
                Some(Format::Dump)
            } else {
                None
            }
        })
    }).unwrap_or(Format::Snmprec);

    // Build record handlers
    let input_record: Box<dyn Record> = match input_format {
        Format::Snmprec => Box::new(SnmprecRecord::new()),
        Format::Walk => Box::new(WalkRecord::new()),
        Format::Dump => Box::new(DumpRecord::new()),
    };

    let output_record: Box<dyn Record> = match args.output_format {
        Format::Snmprec => Box::new(SnmprecRecord::new()),
        Format::Walk => Box::new(WalkRecord::new()),
        Format::Dump => Box::new(DumpRecord::new()),
    };

    // Parse OID bounds
    let start_oid = args.start_oid.as_ref().and_then(|s| {
        s.parse::<snmpsim::oid::Oid>().ok()
    });
    let stop_oid = args.stop_oid.as_ref().and_then(|s| {
        s.parse::<snmpsim::oid::Oid>().ok()
    });

    // Open input
    let input_reader: Box<dyn BufRead> = match &args.input_file {
        Some(path) => {
            match input_record.open(path) {
                Ok(r) => Box::new(BufReader::new(r)),
                Err(e) => {
                    error!("Failed to open input file: {}", e);
                    std::process::exit(1);
                }
            }
        }
        None => Box::new(BufReader::new(std::io::stdin())),
    };

    // Open output
    let mut output_writer: Box<dyn Write> = match &args.output_file {
        Some(path) => {
            match std::fs::File::create(path) {
                Ok(f) => Box::new(f),
                Err(e) => {
                    error!("Failed to open output file: {}", e);
                    std::process::exit(1);
                }
            }
        }
        None => Box::new(std::io::stdout()),
    };

    let ctx = EvalContext {
        exact_match: true,
        ..Default::default()
    };

    let mut line_num = 0usize;
    let mut converted = 0usize;
    let mut skipped = 0usize;

    for line_result in input_reader.lines() {
        line_num += 1;
        let line = match line_result {
            Ok(l) => l,
            Err(e) => {
                error!("Read error at line {}: {}", line_num, e);
                if args.continue_on_errors {
                    skipped += 1;
                    continue;
                }
                std::process::exit(1);
            }
        };

        let trimmed = line.trim();
        // Skip comments and blank lines
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let line_bytes = format!("{}\n", line).into_bytes();

        // Parse the input line
        let (oid, value) = match input_record.evaluate(&line_bytes, &ctx) {
            Ok((oid, Some(val))) => (oid, val),
            Ok((_, None)) => {
                skipped += 1;
                continue;
            }
            Err(e) => {
                warn!("Line {}: parse error: {}", line_num, e);
                if args.continue_on_errors {
                    skipped += 1;
                    continue;
                }
                std::process::exit(1);
            }
        };

        // Apply OID range filter
        if let Some(ref start) = start_oid {
            if &oid < start {
                continue;
            }
        }
        if let Some(ref stop) = stop_oid {
            if &oid > stop {
                break;
            }
        }

        // Format for output
        let output_line = match output_record.format(&oid, &value) {
            Ok(bytes) => bytes,
            Err(e) => {
                warn!("Line {}: format error: {}", line_num, e);
                if args.continue_on_errors {
                    skipped += 1;
                    continue;
                }
                std::process::exit(1);
            }
        };

        if let Err(e) = output_writer.write_all(&output_line) {
            error!("Write error: {}", e);
            std::process::exit(1);
        }

        converted += 1;
    }

    tracing::info!(
        "Converted {} records ({} skipped, {} lines processed)",
        converted,
        skipped,
        line_num
    );
}
