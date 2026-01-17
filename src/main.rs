use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use vtx_security::{scan_vtx_file, ScanOptions, Severity};

#[derive(Debug, Parser)]
#[command(name = "vtx-security", version, about = "VTX plugin security scanner")]
struct Args {
    /// Path to a .vtx plugin package
    path: PathBuf,

    /// Output format
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Exit non-zero if any finding at/above this severity exists
    #[arg(long)]
    fail_on: Option<FailOn>,

    /// Treat unknown import namespaces as error (default: warning)
    #[arg(long)]
    deny_unknown_imports: bool,
}

#[derive(Debug, Clone, ValueEnum)]
enum OutputFormat {
    Json,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FailOn {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl From<FailOn> for Severity {
    fn from(value: FailOn) -> Self {
        match value {
            FailOn::Info => Severity::Info,
            FailOn::Low => Severity::Low,
            FailOn::Medium => Severity::Medium,
            FailOn::High => Severity::High,
            FailOn::Critical => Severity::Critical,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let options = ScanOptions {
        require_contract_exports: true,
        allow_unknown_imports: !args.deny_unknown_imports,
        ..Default::default()
    };

    let report = scan_vtx_file(&args.path, &options)
        .with_context(|| format!("scan failed: {}", args.path.display()))?;

    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
    }

    if let Some(fail_on) = args.fail_on {
        let min: Severity = fail_on.into();
        if report.has_at_least(min) {
            anyhow::bail!("findings at/above {:?} detected", min);
        }
    }

    Ok(())
}
