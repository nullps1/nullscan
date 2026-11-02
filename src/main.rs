use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

mod banner;
mod export;
mod presets;
mod report;
mod scan_job;
mod scanner;
mod vuln;
mod web;

use export::ExportFormat;
use scan_job::ScanJob;

#[derive(Subcommand)]
enum Command {
    /// Build a client-facing external exposure PDF from a live scan or a saved JSON export.
    Report(report::ReportArgs),
}

#[derive(Parser)]
#[command(name = "nullscan")]
#[command(
    about = "A fast, cross-platform Rust tool for scanning TCP ports and grabbing service banners. Authorized use only."
)]
#[command(version = "1.9.0")]
struct Args {
    /// Target IP address, hostname, or CIDR notation (e.g., 192.168.1.0/24)
    #[arg(short, long)]
    target: Option<String>,

    /// Port range (e.g., 1-1000, 80,443,8080)
    #[arg(short, long)]
    ports: Option<String>,

    /// Use top 100 most common ports
    #[arg(long, conflicts_with = "ports")]
    top100: bool,

    /// Use top 1000 most common ports
    #[arg(long, conflicts_with = "ports")]
    top1000: bool,

    /// Number of concurrent threads
    #[arg(short = 'c', long, default_value = "100")]
    concurrency: usize,

    /// Maximum concurrent hosts to scan (for CIDR ranges)
    #[arg(long, default_value = "1")]
    max_hosts: usize,

    /// Perform ping sweep before port scanning (skip unreachable hosts)
    #[arg(long)]
    ping_sweep: bool,

    /// Connection timeout in milliseconds
    #[arg(long, default_value = "3000")]
    timeout: u64,

    /// Ping sweep timeout in milliseconds (faster detection for dead hosts)
    #[arg(long, default_value = "800")]
    ping_timeout: u64,

    /// Grab service banners with intelligent protocol probing
    #[arg(short = 'b', long)]
    banners: bool,

    /// Check for known vulnerabilities based on service banners
    #[arg(long)]
    vuln_check: bool,

    /// Export format (json, markdown, csv, html)
    #[arg(short = 'f', long, default_value = "markdown")]
    format: ExportFormat,

    /// Output file path
    #[arg(short, long)]
    output: Option<String>,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Quiet mode - suppress progress bars and non-essential output
    #[arg(short, long)]
    quiet: bool,

    /// Fast mode - auto-detect CPU cores and optimize for speed (disables banners, vuln checks, verbose)
    #[arg(long)]
    fast_mode: bool,

    /// Start web dashboard on specified port
    #[arg(long)]
    web_dashboard: Option<u16>,

    /// Web dashboard bind address
    #[arg(long, default_value = "127.0.0.1")]
    web_bind: String,

    /// Bearer token for the web dashboard API and UI.
    /// Generated and printed at startup when omitted.
    /// Can also be set with the NULLSCAN_WEB_TOKEN environment variable.
    #[arg(long, env = "NULLSCAN_WEB_TOKEN", hide_env_values = true)]
    web_token: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();

    if let Some(command) = args.command.take() {
        match command {
            Command::Report(mut report_args) => {
                if args.web_dashboard.is_some() {
                    return Err(anyhow::anyhow!(
                        "The report subcommand cannot be combined with --web-dashboard"
                    ));
                }
                if report_args.fast_mode {
                    let logical_cores = num_cpus::get();
                    report_args.concurrency = logical_cores * 150;
                    report_args.timeout = 95;
                    report_args.banners = false;
                    report_args.vuln_check = false;
                    report_args.verbose = false;
                    report_args.quiet = true;
                    eprintln!(
                        "⚡ FAST MODE: {} cores → concurrency={}, timeout={}ms (LUDICROUS SPEED)",
                        logical_cores, report_args.concurrency, report_args.timeout
                    );
                }
                init_logger(report_args.quiet, report_args.verbose);
                return report::execute(report_args).await;
            }
        }
    }

    // Check if web dashboard is requested
    if let Some(port) = args.web_dashboard {
        let (token, generated) = web::resolve_token(args.web_token)?;
        let web_server = web::WebServer::new(token);
        return web_server.start(&args.web_bind, port, generated).await;
    }

    // Apply fast mode optimizations
    if args.fast_mode {
        let logical_cores = num_cpus::get();

        // EXTREME SPEED OPTIMIZATIONS
        // Maximize concurrency based on cores (cores * 150 for better saturation)
        args.concurrency = logical_cores * 150;

        // Ultra-aggressive timeout (95ms - optimized for reliability)
        args.timeout = 95;

        // Disable ALL slow features
        args.banners = false;
        args.vuln_check = false;
        args.verbose = false;
        args.quiet = true; // Enable quiet mode for maximum speed

        // Skip ping sweep in fast mode for single hosts (it's overhead)
        // Network scans can still use it if explicitly requested

        // Log fast mode activation (before quiet mode suppresses logs)
        eprintln!(
            "⚡ FAST MODE: {} cores → concurrency={}, timeout={}ms (LUDICROUS SPEED)",
            logical_cores, args.concurrency, args.timeout
        );
    }

    init_logger(args.quiet, args.verbose);

    info!("🚀 NullScan v1.9.0 - Starting port scan");

    let target = args
        .target
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Target is required for CLI mode"))?;

    let completed = ScanJob {
        target,
        ports: args.ports,
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
        return Ok(());
    }

    export::export_results(
        &completed.results,
        &completed.info,
        args.format,
        args.output,
    )
    .await?;

    Ok(())
}

fn init_logger(quiet: bool, verbose: bool) {
    if quiet {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Error)
            .init();
    } else if verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }
}

#[cfg(test)]
mod cli_tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn help_lists_html_and_dashboard_token() {
        let help = Args::command().render_long_help().to_string();
        assert!(
            help.contains("json, markdown, csv, html"),
            "format help should list html: {help}"
        );
        assert!(help.contains("--web-dashboard <WEB_DASHBOARD>"));
        assert!(help.contains("--web-token"));
        assert!(help.contains("NULLSCAN_WEB_TOKEN"));
        assert!(
            !help.contains("--web-dashboard <WEB_DASHBOARD> [default"),
            "dashboard port has no default"
        );
    }
}
