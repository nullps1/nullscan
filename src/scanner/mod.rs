use anyhow::Result;
use futures::future::join_all;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, info, warn};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::banner::BannerGrabber;

pub async fn ping_host(target: IpAddr, timeout_ms: u64) -> bool {
    debug!("Pinging {target}");

    // Optimized port selection for faster dead host detection
    // Test most common ports in parallel for faster response
    let primary_ports = [80, 443, 22, 135, 445]; // Web, SSH, and Windows common ports

    // Test primary ports in parallel with shorter timeout
    let primary_timeout = Duration::from_millis(timeout_ms / 2);
    let mut tasks = Vec::new();

    for port in primary_ports {
        let addr = SocketAddr::new(target, port);
        let task = tokio::spawn(async move {
            match timeout(primary_timeout, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => {
                    debug!("Host {target} is reachable (TCP connect to port {port})");
                    true
                }
                Ok(Err(_)) => {
                    // Connection refused - host is up but port is closed
                    debug!("Host {target} is reachable (connection refused on port {port})");
                    true
                }
                Err(_) => {
                    // Timeout
                    false
                }
            }
        });
        tasks.push(task);
    }

    // Wait for first success or all failures
    let results = join_all(tasks).await;
    for result in results.into_iter().flatten() {
        if result {
            return true;
        }
    }

    // If primary ports failed, try secondary ports sequentially (fallback)
    let secondary_ports = [21, 25, 53, 110, 993, 995];
    let secondary_timeout = Duration::from_millis(timeout_ms / 4);

    for port in secondary_ports {
        let addr = SocketAddr::new(target, port);

        match timeout(secondary_timeout, TcpStream::connect(addr)).await {
            Ok(Ok(_)) => {
                debug!("Host {target} is reachable (TCP connect to port {port})");
                return true;
            }
            Ok(Err(_)) => {
                // Connection refused - host is up but port is closed
                debug!("Host {target} is reachable (connection refused on port {port})");
                return true;
            }
            Err(_) => {
                // Timeout - try next port
                continue;
            }
        }
    }

    debug!("Host {target} appears to be unreachable");
    false
}

pub async fn ping_sweep(
    targets: &[IpAddr],
    timeout_ms: u64,
    concurrency: usize,
    quiet: bool,
) -> Vec<IpAddr> {
    if !quiet {
        info!("🏓 Starting ping sweep for {} hosts", targets.len());
    }

    let progress = if quiet {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(targets.len() as u64);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {pos}/{len} hosts ({eta})")
                .unwrap()
                .progress_chars("#>-"),
        );
        pb
    };

    let semaphore = Arc::new(tokio::sync::Semaphore::new(concurrency));
    let mut tasks = Vec::new();

    for target in targets {
        let target = *target;
        let semaphore = semaphore.clone();
        let progress = progress.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            let is_alive = ping_host(target, timeout_ms).await;
            progress.inc(1);

            if is_alive {
                Some(target)
            } else {
                None
            }
        });

        tasks.push(task);
    }

    let results = join_all(tasks).await;
    if !quiet {
        progress.finish_with_message("Ping sweep completed");
    }

    let alive_hosts: Vec<IpAddr> = results
        .into_iter()
        .filter_map(|r| r.ok().flatten())
        .collect();

    if !quiet {
        info!(
            "✅ Ping sweep found {}/{} hosts alive",
            alive_hosts.len(),
            targets.len()
        );
    }
    alive_hosts
}

#[derive(Debug, Clone)]
pub struct ScanConfig {
    pub target: IpAddr,
    pub ports: Vec<u16>,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub grab_banners: bool,
    pub quiet: bool,
    pub fast_mode: bool, // New field for ultra optimizations
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanResult {
    pub target: IpAddr,
    pub port: u16,
    pub is_open: bool,
    pub service: Option<String>,
    pub banner: Option<String>,
    #[serde(with = "duration_millis")]
    pub response_time: Duration,
    pub vulnerabilities: Vec<crate::vuln::Vulnerability>,
}

mod duration_millis {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::Duration;

    pub fn serialize<S>(duration: &Duration, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(duration.as_millis() as u64)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let millis = u64::deserialize(deserializer)?;
        Ok(Duration::from_millis(millis))
    }
}

pub struct Scanner {
    config: ScanConfig,
    banner_grabber: BannerGrabber,
}

impl Scanner {
    pub fn new(config: ScanConfig) -> Self {
        Self {
            config,
            banner_grabber: BannerGrabber::new(),
        }
    }

    pub async fn scan(&self) -> Result<Vec<ScanResult>> {
        self.scan_with_vuln_checker(None).await
    }

    pub async fn scan_with_vuln_checker(
        &self,
        vuln_checker: Option<&crate::vuln::VulnChecker>,
    ) -> Result<Vec<ScanResult>> {
        let total_ports = self.config.ports.len();

        // In fast mode, skip ALL logging and progress tracking
        if !self.config.fast_mode && !self.config.quiet {
            info!(
                "🔍 Scanning {} ports on {}",
                total_ports, self.config.target
            );
        }

        // Create progress bar (hidden in fast mode OR quiet mode)
        let pb = if self.config.fast_mode || self.config.quiet {
            ProgressBar::hidden()
        } else {
            let pb = ProgressBar::new(total_ports as u64);
            pb.set_style(
                ProgressStyle::default_bar()
                    .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ports ({eta})")?
                    .progress_chars("#>-"),
            );
            pb
        };

        // FAST MODE: Use batched scanning for better efficiency
        if self.config.fast_mode {
            return self.scan_fast_batch().await;
        }

        // Regular scanning logic for non-fast mode
        // Create semaphore for concurrency control
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));

        // Create scan tasks
        let tasks: Vec<_> = self
            .config
            .ports
            .iter()
            .map(|&port| {
                let config = self.config.clone();
                let semaphore = semaphore.clone();
                let pb = pb.clone();
                let banner_grabber = self.banner_grabber.clone();

                tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let result = scan_port(
                        config.target,
                        port,
                        config.timeout_ms,
                        &banner_grabber,
                        config.grab_banners,
                    )
                    .await;
                    pb.inc(1);
                    result
                })
            })
            .collect();

        // Wait for all tasks to complete
        let results = join_all(tasks).await;
        pb.finish_with_message("Scan completed");

        // Collect results
        let mut scan_results = Vec::new();
        for result in results {
            match result {
                Ok(mut scan_result) => {
                    // Check for vulnerabilities if checker is provided and port is open
                    if let Some(checker) = vuln_checker {
                        if scan_result.is_open {
                            if let Some(banner) = &scan_result.banner {
                                scan_result.vulnerabilities = checker.check_banner(banner);
                            }
                        }
                    }
                    scan_results.push(scan_result);
                }
                Err(e) => warn!("Task error: {e}"),
            }
        }

        // Sort by port number
        scan_results.sort_by_key(|r| r.port);

        Ok(scan_results)
    }

    async fn scan_fast_batch(&self) -> Result<Vec<ScanResult>> {
        let batch_size = 200; // Batch connections for better efficiency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.config.concurrency));

        let mut all_results = Vec::with_capacity(self.config.ports.len());

        // Process ports in batches
        for chunk in self.config.ports.chunks(batch_size) {
            let tasks: Vec<_> = chunk
                .iter()
                .map(|&port| {
                    let semaphore = semaphore.clone();
                    let target = self.config.target;
                    let timeout_ms = self.config.timeout_ms;

                    tokio::spawn(async move {
                        let _permit = semaphore.acquire().await.unwrap();
                        scan_port_ultra_fast(target, port, timeout_ms).await
                    })
                })
                .collect();

            // Wait for batch to complete
            let batch_results = join_all(tasks).await;

            // Collect batch results
            for scan_result in batch_results.into_iter().flatten() {
                all_results.push(scan_result);
            }
        }

        // Sort by port number (fast sort)
        all_results.sort_unstable_by_key(|r| r.port);

        Ok(all_results)
    }
}

async fn scan_port_ultra_fast(target: IpAddr, port: u16, timeout_ms: u64) -> ScanResult {
    let start_time = Instant::now();
    let socket_addr = SocketAddr::new(target, port);
    let timeout_duration = Duration::from_millis(timeout_ms);

    // Fast TCP connect attempt - no banner grabbing, minimal service detection
    let is_open = matches!(
        timeout(timeout_duration, TcpStream::connect(socket_addr)).await,
        Ok(Ok(_))
    );

    let response_time = start_time.elapsed();

    ScanResult {
        target,
        port,
        is_open,
        service: if is_open {
            get_service_name_fast(port)
        } else {
            None
        },
        banner: None, // Never grab banners in ultra-fast mode
        response_time,
        vulnerabilities: Vec::new(), // Never check vulns in ultra-fast mode
    }
}

fn get_service_name_fast(port: u16) -> Option<String> {
    // Only the most essential ports to minimize lookup time
    let service = match port {
        22 => "SSH",
        80 => "HTTP",
        443 => "HTTPS",
        21 => "FTP",
        25 => "SMTP",
        53 => "DNS",
        135 => "RPC",
        445 => "SMB",
        3389 => "RDP",
        _ => return None,
    };
    Some(service.to_string())
}

async fn scan_port(
    target: IpAddr,
    port: u16,
    timeout_ms: u64,
    banner_grabber: &BannerGrabber,
    grab_banners: bool,
) -> ScanResult {
    let start_time = Instant::now();
    let socket_addr = SocketAddr::new(target, port);

    debug!("Scanning port {port}");

    let timeout_duration = Duration::from_millis(timeout_ms);

    match timeout(timeout_duration, TcpStream::connect(socket_addr)).await {
        Ok(Ok(stream)) => {
            let response_time = start_time.elapsed();
            debug!("Port {} is open ({}ms)", port, response_time.as_millis());

            let mut result = ScanResult {
                target,
                port,
                is_open: true,
                service: get_service_name(port),
                banner: None,
                response_time,
                vulnerabilities: Vec::new(),
            };

            // Grab banner if requested
            if grab_banners {
                if let Ok(banner) = banner_grabber.grab_banner(stream, port).await {
                    result.banner = Some(banner);
                }
            }

            result
        }
        Ok(Err(_)) | Err(_) => {
            let response_time = start_time.elapsed();
            debug!("Port {port} is closed/filtered");
            ScanResult {
                target,
                port,
                is_open: false,
                service: None,
                banner: None,
                response_time,
                vulnerabilities: Vec::new(),
            }
        }
    }
}

fn get_service_name(port: u16) -> Option<String> {
    let service = match port {
        21 => "FTP",
        22 => "SSH",
        23 => "Telnet",
        25 => "SMTP",
        53 => "DNS",
        80 => "HTTP",
        110 => "POP3",
        135 => "RPC",
        139 => "NetBIOS",
        143 => "IMAP",
        443 => "HTTPS",
        445 => "SMB",
        993 => "IMAPS",
        995 => "POP3S",
        1433 => "MSSQL",
        3306 => "MySQL",
        3389 => "RDP",
        5432 => "PostgreSQL",
        5900 => "VNC",
        8080 => "HTTP-Alt",
        8443 => "HTTPS-Alt",
        _ => return None,
    };
    Some(service.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vuln::VulnChecker;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    fn localhost() -> IpAddr {
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    }

    fn config(ports: Vec<u16>, banners: bool, fast_mode: bool) -> ScanConfig {
        let target = localhost();
        assert!(target.is_loopback());
        ScanConfig {
            target,
            ports,
            concurrency: 4,
            timeout_ms: 1000,
            grab_banners: banners,
            quiet: true,
            fast_mode,
        }
    }

    async fn ephemeral_listener() -> (TcpListener, u16) {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        (listener, port)
    }

    #[tokio::test]
    async fn scan_reports_open_and_closed_localhost_ports() {
        let (listener, open_port) = ephemeral_listener().await;
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_7.4\r\n").await;
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        });

        let (closed_listener, closed_port) = ephemeral_listener().await;
        drop(closed_listener);

        let scanner = Scanner::new(config(vec![open_port, closed_port], true, false));
        let results = scanner.scan().await.unwrap();
        assert!(results.iter().all(|r| r.target.is_loopback()));

        let open = results.iter().find(|r| r.port == open_port).unwrap();
        assert!(open.is_open);
        let banner = open.banner.as_deref().unwrap_or("");
        assert!(banner.contains("OpenSSH_7.4"), "banner was {banner:?}");

        let closed = results.iter().find(|r| r.port == closed_port).unwrap();
        assert!(!closed.is_open);
        assert!(closed.banner.is_none());
    }

    #[tokio::test]
    async fn fast_mode_scans_only_the_local_listener() {
        let (listener, open_port) = ephemeral_listener().await;
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_millis(200)).await;
                drop(sock);
            }
        });

        let scanner = Scanner::new(config(vec![open_port], false, true));
        let results = scanner.scan().await.unwrap();
        assert_eq!(results.len(), 1);
        assert!(results[0].is_open);
        assert!(results[0].banner.is_none());
        assert!(results[0].target.is_loopback());
    }

    #[tokio::test]
    async fn vuln_checker_matches_local_ssh_banner() {
        let (listener, open_port) = ephemeral_listener().await;
        tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_7.4\r\n").await;
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
        });

        let db = format!("{}/vuln_db.json", env!("CARGO_MANIFEST_DIR"));
        let checker = VulnChecker::load_from_file(&db).unwrap();
        let scanner = Scanner::new(config(vec![open_port], true, false));
        let results = scanner
            .scan_with_vuln_checker(Some(&checker))
            .await
            .unwrap();
        let open = results.iter().find(|r| r.is_open).unwrap();
        assert!(open.target.is_loopback());
        assert!(
            open.vulnerabilities
                .iter()
                .any(|v| v.cve == "CVE-2018-15473"),
            "vulns: {:?}",
            open.vulnerabilities
        );
    }

    #[tokio::test]
    async fn ping_sweep_keeps_localhost() {
        let alive = ping_sweep(&[localhost()], 400, 2, true).await;
        assert_eq!(alive, vec![localhost()]);
    }
}
