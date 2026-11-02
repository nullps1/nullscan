//! Client-facing external exposure PDF.
//!
//! `nullscan report` builds the PDF from a saved JSON export, or scans first
//! when `--input` is omitted. Severity rules live in `severity`. Wording lives
//! in `playbook`.

mod config;
mod model;
mod pdf;
mod playbook;
mod severity;

use std::path::PathBuf;

use anyhow::{bail, Result};
use clap::Args;

use crate::scan_job::ScanJob;

pub use config::ReportOverrides;

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Saved nullscan JSON export. Omit this to scan `--target` and then render.
    #[arg(long)]
    pub input: Option<PathBuf>,

    /// TOML file with client, authorization, and branding fields.
    #[arg(long)]
    pub config: PathBuf,

    /// Where to write the PDF.
    #[arg(short, long)]
    pub output: PathBuf,

    #[command(flatten)]
    pub overrides: ReportOverrides,

    /// Target IP address, hostname, or CIDR notation. Used when --input is omitted.
    #[arg(short, long)]
    pub target: Option<String>,

    /// Port range (e.g., 1-1000, 80,443,8080)
    #[arg(short, long)]
    pub ports: Option<String>,

    /// Use top 100 most common ports
    #[arg(long, conflicts_with = "ports")]
    pub top100: bool,

    /// Use top 1000 most common ports
    #[arg(long, conflicts_with = "ports")]
    pub top1000: bool,

    /// Number of concurrent threads
    #[arg(short = 'c', long, default_value = "100")]
    pub concurrency: usize,

    /// Maximum concurrent hosts to scan (for CIDR ranges)
    #[arg(long, default_value = "1")]
    pub max_hosts: usize,

    /// Perform ping sweep before port scanning
    #[arg(long)]
    pub ping_sweep: bool,

    /// Connection timeout in milliseconds
    #[arg(long, default_value = "3000")]
    pub timeout: u64,

    /// Ping sweep timeout in milliseconds
    #[arg(long, default_value = "800")]
    pub ping_timeout: u64,

    /// Grab service banners
    #[arg(short = 'b', long)]
    pub banners: bool,

    /// Check banners against the local CVE database
    #[arg(long)]
    pub vuln_check: bool,

    /// Verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Quiet mode
    #[arg(short, long)]
    pub quiet: bool,

    /// Fast mode. Disables banners and vulnerability checks.
    #[arg(long)]
    pub fast_mode: bool,
}

pub async fn execute(args: ReportArgs) -> Result<()> {
    let mut config = config::load(&args.config, &args.overrides)?;
    let scan = if let Some(input) = &args.input {
        if args.target.is_some() {
            log::warn!("--input is set, so --target is ignored and nothing is scanned");
        }
        model::load_scan_json(input)?
    } else {
        let Some(target) = args.target.clone() else {
            bail!(
                "Pass --input with a JSON scan export, or --target to scan and then build the report."
            );
        };
        let completed = ScanJob {
            target,
            ports: args.ports.clone(),
            top100: args.top100,
            top1000: args.top1000,
            concurrency: args.concurrency,
            max_hosts: args.max_hosts,
            ping_sweep: args.ping_sweep,
            timeout: args.timeout,
            ping_timeout: args.ping_timeout,
            banners: args.banners,
            vuln_check: args.vuln_check,
            quiet: args.quiet,
            fast_mode: args.fast_mode,
        }
        .run()
        .await?;
        if completed.skipped {
            bail!("No hosts responded to the ping sweep, so the report was not built.");
        }
        model::LoadedScan {
            info: completed.info,
            results: completed.results,
        }
    };

    model::fill_report_id(&mut config, &scan.info);
    let report = model::assemble(&config, &scan.info, &scan.results)?;
    let bytes = pdf::render(&report)?;
    if let Some(parent) = args.output.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.ok();
        }
    }
    tokio::fs::write(&args.output, &bytes).await?;
    log::info!("Wrote client report to {}", args.output.display());
    if !args.quiet {
        println!(
            "Wrote {} ({} bytes, grade {})",
            args.output.display(),
            bytes.len(),
            report.grade.letter
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::config::ReportOverrides;
    use crate::scanner::ScanResult;
    use crate::vuln::{VulnSeverity, Vulnerability};
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn tiny_scan() -> model::LoadedScan {
        let mut info = HashMap::new();
        info.insert("target".into(), "203.0.113.10".into());
        info.insert("total_ports".into(), "3".into());
        info.insert("open_ports".into(), "1".into());
        info.insert("closed_ports".into(), "2".into());
        info.insert("scan_duration".into(), "12ms".into());
        info.insert("timestamp".into(), "2026-10-28T18:30:00Z".into());
        info.insert("scan_started".into(), "2026-10-28T18:29:59Z".into());
        info.insert("scan_ended".into(), "2026-10-28T18:30:00Z".into());
        info.insert("nullscan_version".into(), "1.8.0".into());
        info.insert("vuln_db_updated".into(), "2025-07-13".into());
        model::LoadedScan {
            info,
            results: vec![ScanResult {
                target: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                port: 80,
                is_open: true,
                service: Some("HTTP".into()),
                banner: Some("nginx".into()),
                response_time: Duration::from_millis(4),
                vulnerabilities: vec![Vulnerability {
                    cve: "CVE-2021-23017".into(),
                    description: "example".into(),
                    severity: VulnSeverity::High,
                    cvss_score: Some(7.7),
                    published: None,
                    references: vec![],
                }],
            }],
        }
    }

    #[test]
    fn smoke_pdf_is_produced_and_auth_is_required() {
        let missing = config::parse_config(
            "[client]\nlegal_name = \"Nobody\"\n",
            std::path::Path::new("report.toml"),
            &ReportOverrides::default(),
        );
        assert!(missing
            .unwrap_err()
            .to_string()
            .contains("authorization reference"));

        let mut config = config::parse_config(
            r#"
[client]
legal_name = "Example Co"
[authorization]
reference = "AUTH-SMOKE"
signer_name = "Pat Example"
signed_date = "2026-10-01"
"#,
            std::path::Path::new("report.toml"),
            &ReportOverrides::default(),
        )
        .unwrap();
        let scan = tiny_scan();
        model::fill_report_id(&mut config, &scan.info);
        let report = model::assemble(&config, &scan.info, &scan.results).unwrap();
        assert_eq!(report.grade.letter, 'C');
        let bytes = pdf::render(&report).unwrap();
        assert!(bytes.starts_with(b"%PDF"), "missing PDF header");
        assert!(bytes.windows(5).any(|window| window == b"%%EOF"));
        assert!(
            bytes.len() > 5_000,
            "pdf was unexpectedly small: {}",
            bytes.len()
        );
        pdf::embedded_font_has_shapes().unwrap();
    }

    #[test]
    fn sample_fixture_renders() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let config = config::load(
            &root.join("examples/sample-report.toml"),
            &ReportOverrides::default(),
        )
        .unwrap();
        let scan = model::load_scan_json(&root.join("examples/sample-scan.json")).unwrap();
        let mut config = config;
        model::fill_report_id(&mut config, &scan.info);
        let report = model::assemble(&config, &scan.info, &scan.results).unwrap();
        assert_eq!(report.grade.letter, 'F');
        assert!(report.config.insurance_appendix);
        assert!(report.config.rescan_offer.contains("We'll rescan"));
        assert!(report
            .config
            .monitoring_offer
            .contains("Monthly monitoring"));
        assert!(!report.config.rescan_offer.contains("{{"));
        assert!(!report.config.monitoring_offer.contains("{{"));
        let bytes = pdf::render(&report).unwrap();
        assert!(bytes.starts_with(b"%PDF"));
        assert!(bytes.len() > 5_000);
    }
}
