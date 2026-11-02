use anyhow::Result;
use clap::Parser;
use log::{info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

mod banner;
mod export;
mod presets;
mod scanner;
mod vuln;
mod web;

use export::ExportFormat;
use presets::PortPreset;
use scanner::{ScanConfig, ScanResult, Scanner};

#[derive(Parser)]
#[command(name = "nullscan")]
#[command(
    about = "A fast, cross-platform Rust tool for scanning TCP ports and grabbing service banners. Authorized use only."
)]
#[command(version = "1.7.0")]
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
}

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = Args::parse();

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

    // Initialize logger
    if args.quiet {
        // In quiet mode, only show errors
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Error)
            .init();
    } else if args.verbose {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init();
    } else {
        env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init();
    }

    info!("🚀 NullScan v1.7.0 - Starting port scan");

    // Load vulnerability database if vuln checking is enabled
    let vuln_checker = if args.vuln_check {
        match vuln::VulnChecker::load_from_file("vuln_db.json") {
            Ok(checker) => {
                let stats = checker.get_stats();
                let severities = stats
                    .severity_counts
                    .iter()
                    .map(|(severity, count)| format!("{severity}: {count}"))
                    .collect::<Vec<_>>()
                    .join(", ");
                info!(
                    "🛡️  Vulnerability database loaded: {} patterns, {} vulnerabilities (db {}, updated {}; {})",
                    stats.total_patterns,
                    stats.total_vulnerabilities,
                    stats.version,
                    stats.last_updated,
                    if severities.is_empty() {
                        "no severity counts".to_string()
                    } else {
                        severities
                    }
                );
                Some(Arc::new(checker))
            }
            Err(e) => {
                warn!(
                    "Failed to load vulnerability database: {e}. Continuing without vuln checking."
                );
                None
            }
        }
    } else {
        None
    };

    // Check that target is provided for CLI mode
    let target = args
        .target
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("Target is required for CLI mode"))?;

    // Parse targets (skip DNS in fast mode for performance)
    let targets = if args.fast_mode {
        parse_targets_fast(target)?
    } else {
        parse_targets(target).await?
    };
    info!("Parsed {} target(s) from: {}", targets.len(), target);

    // Determine ports to scan
    let ports = if args.top100 {
        presets::get_top_ports(PortPreset::Top100)
    } else if args.top1000 {
        presets::get_top_ports(PortPreset::Top1000)
    } else if let Some(port_spec) = args.ports {
        parse_port_specification(&port_spec)?
    } else {
        // Default to top 100 if no ports specified
        warn!("No ports specified, using top 100 common ports");
        presets::get_top_ports(PortPreset::Top100)
    };

    info!(
        "Targets: {} | Ports: {} | Concurrency: {} | Max Hosts: {}",
        targets.len(),
        ports.len(),
        args.concurrency,
        args.max_hosts
    );

    // Perform ping sweep if requested (but skip for single hosts in fast mode)
    let final_targets = if args.ping_sweep && !(args.fast_mode && targets.len() == 1) {
        if !args.quiet {
            info!("🏓 Ping sweep enabled, checking host availability...");
        }
        let alive_hosts =
            scanner::ping_sweep(&targets, args.ping_timeout, args.concurrency, args.quiet).await;

        if alive_hosts.is_empty() {
            if !args.quiet {
                warn!("No hosts responded to ping sweep. Exiting.");
            }
            return Ok(());
        }

        if !args.quiet {
            info!(
                "📊 Ping sweep reduced targets from {} to {} hosts",
                targets.len(),
                alive_hosts.len()
            );
        }
        alive_hosts
    } else {
        targets
    };

    // Scan all targets with parallel host scanning
    let start_time = Instant::now();

    // Create semaphore to limit concurrent host scans
    let host_semaphore = Arc::new(Semaphore::new(args.max_hosts));

    // Create futures for all target scans
    let scan_futures = final_targets.iter().enumerate().map(|(i, target)| {
        let host_semaphore = Arc::clone(&host_semaphore);
        let ports = ports.clone();
        let target = *target;
        let concurrency = args.concurrency;
        let timeout = args.timeout;
        let grab_banners = args.banners;
        let total_targets = final_targets.len();
        let vuln_checker = vuln_checker.clone();

        async move {
            // Acquire semaphore permit
            let _permit = host_semaphore.acquire().await.unwrap();

            if !args.quiet {
                info!("📡 Scanning target {}/{}: {}", i + 1, total_targets, target);
            }

            // Create scan configuration for this target
            let config = ScanConfig {
                target,
                ports,
                concurrency,
                timeout_ms: timeout,
                grab_banners,
                quiet: args.quiet,
                fast_mode: args.fast_mode,
            };

            // Perform scan
            let scanner = Scanner::new(config);
            let results = if let Some(ref checker) = vuln_checker {
                scanner.scan_with_vuln_checker(Some(checker)).await?
            } else {
                scanner.scan().await?
            };

            Ok::<(String, Vec<ScanResult>), anyhow::Error>((target.to_string(), results))
        }
    });

    // Execute all scans concurrently and collect results
    let all_results = futures::future::try_join_all(scan_futures).await?;

    let scan_duration = start_time.elapsed();

    // Generate and export results
    if final_targets.len() == 1 {
        // Single target - use existing format
        let (target_str, results) = &all_results[0];
        let report = generate_scan_report(results, target_str, scan_duration);
        export::export_results(results, &report, args.format, args.output).await?;
    } else {
        // Multiple targets - combine results
        let mut combined_results = Vec::new();

        for (target_str, results) in &all_results {
            let open_count = results.iter().filter(|r| r.is_open).count();

            info!(
                "📊 {}: {}/{} ports open",
                target_str,
                open_count,
                results.len()
            );
            combined_results.extend(results.iter().cloned());
        }

        let report = generate_network_scan_report(&all_results, target, scan_duration);
        export::export_results(&combined_results, &report, args.format, args.output).await?;
    }

    if !args.quiet {
        info!("✅ Scan completed in {scan_duration:.2?}");
    }
    Ok(())
}

fn parse_port_specification(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();

    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
            // Range (e.g., "1-1000")
            let range_parts: Vec<&str> = part.split('-').collect();
            if range_parts.len() != 2 {
                return Err(anyhow::anyhow!("Invalid port range: {}", part));
            }
            let start: u16 = range_parts[0].parse()?;
            let end: u16 = range_parts[1].parse()?;
            for port in start..=end {
                ports.push(port);
            }
        } else {
            // Single port
            let port: u16 = part.parse()?;
            ports.push(port);
        }
    }

    Ok(ports)
}

fn parse_targets_fast(target_spec: &str) -> Result<Vec<IpAddr>> {
    let mut targets = Vec::new();

    // Check if it's multiple targets separated by commas
    if target_spec.contains(',') {
        for target in target_spec.split(',') {
            let target = target.trim();

            // Handle each target type individually
            if target.contains('/') {
                // CIDR notation
                let network: ipnet::IpNet = target
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid CIDR notation: {}", target))?;

                for (count, ip) in network.hosts().enumerate() {
                    if count >= 1024 {
                        break; // No warnings in fast mode
                    }
                    targets.push(ip);
                }
            } else {
                // Only accept IP addresses in fast mode
                match target.parse::<IpAddr>() {
                    Ok(ip) => targets.push(ip),
                    Err(_) => {
                        return Err(anyhow::anyhow!(
                            "Fast mode: Only IP addresses supported, got: {}",
                            target
                        ));
                    }
                }
            }
        }
        return Ok(targets);
    }

    // Check if it's CIDR notation
    if target_spec.contains('/') {
        let network: ipnet::IpNet = target_spec
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR notation: {}", target_spec))?;

        // Collect all IPs in the network (limit to reasonable size)
        for (count, ip) in network.hosts().enumerate() {
            if count >= 1024 {
                break; // No warnings in fast mode
            }
            targets.push(ip);
        }

        if targets.is_empty() {
            return Err(anyhow::anyhow!(
                "No hosts found in network: {}",
                target_spec
            ));
        }
    } else {
        // Only accept IP addresses in fast mode
        match target_spec.parse::<IpAddr>() {
            Ok(ip) => targets.push(ip),
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Fast mode: Only IP addresses supported, got: {}",
                    target_spec
                ));
            }
        }
    }

    Ok(targets)
}

async fn parse_targets(target_spec: &str) -> Result<Vec<IpAddr>> {
    let mut targets = Vec::new();

    // Check if it's multiple targets separated by commas
    if target_spec.contains(',') {
        for target in target_spec.split(',') {
            let target = target.trim();

            // Handle each target type individually
            if target.contains('/') {
                // CIDR notation
                let network: ipnet::IpNet = target
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid CIDR notation: {}", target))?;

                for (count, ip) in network.hosts().enumerate() {
                    if count >= 1024 {
                        warn!("Network too large, limiting to first 1024 hosts");
                        break;
                    }
                    targets.push(ip);
                }
            } else {
                // Single IP or hostname
                match target.parse::<IpAddr>() {
                    Ok(ip) => targets.push(ip),
                    Err(_) => {
                        // Try to resolve hostname
                        let resolved = tokio::net::lookup_host(format!("{target}:80"))
                            .await
                            .map_err(|_| {
                                anyhow::anyhow!("Failed to resolve hostname: {}", target)
                            })?;

                        if let Some(addr) = resolved.map(|addr| addr.ip()).next() {
                            targets.push(addr);
                        } else {
                            return Err(anyhow::anyhow!(
                                "No IP addresses found for hostname: {}",
                                target
                            ));
                        }
                    }
                }
            }
        }
        return Ok(targets);
    }

    // Check if it's CIDR notation
    if target_spec.contains('/') {
        let network: ipnet::IpNet = target_spec
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR notation: {}", target_spec))?;

        // Collect all IPs in the network (limit to reasonable size)
        for (count, ip) in network.hosts().enumerate() {
            if count >= 1024 {
                warn!("Network too large, limiting to first 1024 hosts");
                break;
            }
            targets.push(ip);
        }

        if targets.is_empty() {
            return Err(anyhow::anyhow!(
                "No hosts found in network: {}",
                target_spec
            ));
        }
    } else {
        // Single IP or hostname
        match target_spec.parse::<IpAddr>() {
            Ok(ip) => targets.push(ip),
            Err(_) => {
                // Try to resolve hostname
                let resolved = tokio::net::lookup_host(format!("{target_spec}:80"))
                    .await
                    .map_err(|_| anyhow::anyhow!("Failed to resolve hostname: {}", target_spec))?;

                if let Some(addr) = resolved.map(|addr| addr.ip()).next() {
                    targets.push(addr);
                } else {
                    return Err(anyhow::anyhow!(
                        "No addresses found for hostname: {}",
                        target_spec
                    ));
                }
            }
        }
    }

    Ok(targets)
}

fn generate_scan_report(
    results: &[ScanResult],
    target: &str,
    duration: std::time::Duration,
) -> HashMap<String, String> {
    let mut report = HashMap::new();

    let total_ports = results.len();
    let open_ports = results.iter().filter(|r| r.is_open).count();
    let closed_ports = total_ports - open_ports;

    report.insert("target".to_string(), target.to_string());
    report.insert("total_ports".to_string(), total_ports.to_string());
    report.insert("open_ports".to_string(), open_ports.to_string());
    report.insert("closed_ports".to_string(), closed_ports.to_string());
    report.insert("scan_duration".to_string(), format!("{duration:.2?}"));
    report.insert("timestamp".to_string(), chrono::Utc::now().to_rfc3339());

    report
}

fn generate_network_scan_report(
    all_results: &[(String, Vec<ScanResult>)],
    target_spec: &str,
    duration: std::time::Duration,
) -> HashMap<String, String> {
    let mut report = HashMap::new();

    let total_targets = all_results.len();
    let total_ports: usize = all_results.iter().map(|(_, results)| results.len()).sum();
    let total_open_ports: usize = all_results
        .iter()
        .map(|(_, results)| results.iter().filter(|r| r.is_open).count())
        .sum();

    report.insert(
        "target".to_string(),
        format!("{target_spec} ({total_targets} hosts)"),
    );
    report.insert("total_targets".to_string(), total_targets.to_string());
    report.insert("total_ports".to_string(), total_ports.to_string());
    report.insert("open_ports".to_string(), total_open_ports.to_string());
    report.insert(
        "closed_ports".to_string(),
        (total_ports - total_open_ports).to_string(),
    );
    report.insert("scan_duration".to_string(), format!("{duration:.2?}"));
    report.insert("timestamp".to_string(), chrono::Utc::now().to_rfc3339());

    report
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
