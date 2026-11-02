//! Shared scan loop for the CLI and the report subcommand.

use anyhow::Result;
use futures::future::try_join_all;
use log::{info, warn};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;

use crate::presets::PortPreset;
use crate::scanner::{ScanConfig, ScanResult, Scanner};
use crate::vuln;

pub struct ScanJob {
    pub target: String,
    pub ports: Option<String>,
    pub top100: bool,
    pub top1000: bool,
    pub concurrency: usize,
    pub max_hosts: usize,
    pub ping_sweep: bool,
    pub timeout: u64,
    pub ping_timeout: u64,
    pub banners: bool,
    pub vuln_check: bool,
    pub quiet: bool,
    pub fast_mode: bool,
}

pub struct CompletedScan {
    pub results: Vec<ScanResult>,
    pub info: HashMap<String, String>,
    /// True when a ping sweep found nobody alive and the port scan was skipped.
    pub skipped: bool,
}

impl ScanJob {
    pub async fn run(self) -> Result<CompletedScan> {
        let vuln_checker = if self.vuln_check {
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
                Err(err) => {
                    warn!(
                        "Failed to load vulnerability database: {err}. Continuing without vuln checking."
                    );
                    None
                }
            }
        } else {
            None
        };

        let targets = if self.fast_mode {
            parse_targets_fast(&self.target)?
        } else {
            parse_targets(&self.target).await?
        };
        info!("Parsed {} target(s) from: {}", targets.len(), self.target);

        let ports = if self.top100 {
            crate::presets::get_top_ports(PortPreset::Top100)
        } else if self.top1000 {
            crate::presets::get_top_ports(PortPreset::Top1000)
        } else if let Some(port_spec) = &self.ports {
            parse_port_specification(port_spec)?
        } else {
            warn!("No ports specified, using top 100 common ports");
            crate::presets::get_top_ports(PortPreset::Top100)
        };

        info!(
            "Targets: {} | Ports: {} | Concurrency: {} | Max Hosts: {}",
            targets.len(),
            ports.len(),
            self.concurrency,
            self.max_hosts
        );

        let final_targets = if self.ping_sweep && !(self.fast_mode && targets.len() == 1) {
            if !self.quiet {
                info!("🏓 Ping sweep enabled, checking host availability...");
            }
            let alive_hosts = crate::scanner::ping_sweep(
                &targets,
                self.ping_timeout,
                self.concurrency,
                self.quiet,
            )
            .await;
            if alive_hosts.is_empty() {
                if !self.quiet {
                    warn!("No hosts responded to ping sweep. Exiting.");
                }
                let started = chrono::Utc::now();
                let mut info = generate_network_scan_report(
                    &[],
                    &self.target,
                    std::time::Duration::from_secs(0),
                );
                annotate(
                    &mut info,
                    started,
                    vuln_note(self.vuln_check, vuln_checker.as_deref()),
                );
                return Ok(CompletedScan {
                    results: Vec::new(),
                    info,
                    skipped: true,
                });
            }
            if !self.quiet {
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

        let start_time = Instant::now();
        let started = chrono::Utc::now();
        let host_semaphore = Arc::new(Semaphore::new(self.max_hosts));
        let quiet = self.quiet;
        let scan_futures = final_targets.iter().enumerate().map(|(index, target)| {
            let host_semaphore = Arc::clone(&host_semaphore);
            let ports = ports.clone();
            let target = *target;
            let concurrency = self.concurrency;
            let timeout = self.timeout;
            let grab_banners = self.banners;
            let fast_mode = self.fast_mode;
            let total_targets = final_targets.len();
            let vuln_checker = vuln_checker.clone();
            async move {
                let _permit = host_semaphore.acquire().await.unwrap();
                if !quiet {
                    info!(
                        "📡 Scanning target {}/{}: {}",
                        index + 1,
                        total_targets,
                        target
                    );
                }
                let config = ScanConfig {
                    target,
                    ports,
                    concurrency,
                    timeout_ms: timeout,
                    grab_banners,
                    quiet,
                    fast_mode,
                };
                let scanner = Scanner::new(config);
                let results = if let Some(ref checker) = vuln_checker {
                    scanner.scan_with_vuln_checker(Some(checker)).await?
                } else {
                    scanner.scan().await?
                };
                Ok::<(String, Vec<ScanResult>), anyhow::Error>((target.to_string(), results))
            }
        });

        let all_results = try_join_all(scan_futures).await?;
        let scan_duration = start_time.elapsed();
        let note = vuln_note(self.vuln_check, vuln_checker.as_deref());

        let (results, mut info) = if final_targets.len() == 1 {
            let (target_str, results) = &all_results[0];
            let info = generate_scan_report(results, target_str, scan_duration);
            (results.clone(), info)
        } else {
            let mut combined = Vec::new();
            for (target_str, host_results) in &all_results {
                let open_count = host_results.iter().filter(|result| result.is_open).count();
                info!(
                    "📊 {}: {}/{} ports open",
                    target_str,
                    open_count,
                    host_results.len()
                );
                combined.extend(host_results.iter().cloned());
            }
            let info = generate_network_scan_report(&all_results, &self.target, scan_duration);
            (combined, info)
        };
        annotate(&mut info, started, note);

        if !self.quiet {
            info!("✅ Scan completed in {scan_duration:.2?}");
        }
        Ok(CompletedScan {
            results,
            info,
            skipped: false,
        })
    }
}

struct VulnNote {
    updated: String,
    version: Option<String>,
}

fn vuln_note(requested: bool, checker: Option<&vuln::VulnChecker>) -> VulnNote {
    match (requested, checker) {
        (true, Some(checker)) => {
            let stats = checker.get_stats();
            VulnNote {
                updated: stats.last_updated,
                version: Some(stats.version),
            }
        }
        (true, None) => VulnNote {
            updated: "not recorded".to_string(),
            version: None,
        },
        (false, _) => VulnNote {
            updated: "not run".to_string(),
            version: None,
        },
    }
}

fn annotate(
    info: &mut HashMap<String, String>,
    started: chrono::DateTime<chrono::Utc>,
    note: VulnNote,
) {
    let ended = chrono::Utc::now();
    info.insert(
        "nullscan_version".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
    );
    info.insert("scan_started".to_string(), started.to_rfc3339());
    info.insert("scan_ended".to_string(), ended.to_rfc3339());
    info.insert("timestamp".to_string(), ended.to_rfc3339());
    info.insert("vuln_db_updated".to_string(), note.updated);
    if let Some(version) = note.version {
        info.insert("vuln_db_version".to_string(), version);
    }
}

fn generate_scan_report(
    results: &[ScanResult],
    target: &str,
    duration: std::time::Duration,
) -> HashMap<String, String> {
    let mut report = HashMap::new();
    let total_ports = results.len();
    let open_ports = results.iter().filter(|result| result.is_open).count();
    report.insert("target".to_string(), target.to_string());
    report.insert("total_ports".to_string(), total_ports.to_string());
    report.insert("open_ports".to_string(), open_ports.to_string());
    report.insert(
        "closed_ports".to_string(),
        (total_ports - open_ports).to_string(),
    );
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
        .map(|(_, results)| results.iter().filter(|result| result.is_open).count())
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

pub fn parse_port_specification(spec: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.contains('-') {
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
            let port: u16 = part.parse()?;
            ports.push(port);
        }
    }
    Ok(ports)
}

fn parse_targets_fast(target_spec: &str) -> Result<Vec<IpAddr>> {
    let mut targets = Vec::new();
    if target_spec.contains(',') {
        for target in target_spec.split(',') {
            let target = target.trim();
            if target.contains('/') {
                let network: ipnet::IpNet = target
                    .parse()
                    .map_err(|_| anyhow::anyhow!("Invalid CIDR notation: {}", target))?;
                for (count, ip) in network.hosts().enumerate() {
                    if count >= 1024 {
                        break;
                    }
                    targets.push(ip);
                }
            } else {
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
    if target_spec.contains('/') {
        let network: ipnet::IpNet = target_spec
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR notation: {}", target_spec))?;
        for (count, ip) in network.hosts().enumerate() {
            if count >= 1024 {
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
    if target_spec.contains(',') {
        for target in target_spec.split(',') {
            let target = target.trim();
            if target.contains('/') {
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
                match target.parse::<IpAddr>() {
                    Ok(ip) => targets.push(ip),
                    Err(_) => {
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
    if target_spec.contains('/') {
        let network: ipnet::IpNet = target_spec
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid CIDR notation: {}", target_spec))?;
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
        match target_spec.parse::<IpAddr>() {
            Ok(ip) => targets.push(ip),
            Err(_) => {
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
