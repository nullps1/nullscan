use anyhow::Result;
use log::debug;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct BannerGrabber {
    timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct ProbeResult {
    pub service: String,
    pub banner: String,
}

impl BannerGrabber {
    pub fn new() -> Self {
        Self {
            timeout_ms: 5000, // 5 seconds for banner grabbing
        }
    }

    pub async fn grab_banner(&self, mut stream: TcpStream, port: u16) -> Result<String> {
        if let Ok(probe_result) = self.probe_service(&mut stream, port).await {
            return Ok(format!(
                "{} - {}",
                probe_result.service, probe_result.banner
            ));
        }

        // Fallback to simple banner grab
        self.simple_banner_grab(&mut stream, port).await
    }

    async fn probe_service(&self, stream: &mut TcpStream, port: u16) -> Result<ProbeResult> {
        let timeout_duration = Duration::from_millis(self.timeout_ms);

        match port {
            22 => self.probe_ssh(stream, timeout_duration).await,
            443 | 993 | 995 | 8443 => self.probe_tls(stream, timeout_duration).await,
            80 | 8080 | 8000 | 3000 => self.probe_http(stream, timeout_duration).await,
            21 => self.probe_ftp(stream, timeout_duration).await,
            25 | 587 | 465 => self.probe_smtp(stream, timeout_duration).await,
            110 => self.probe_pop3(stream, timeout_duration).await,
            143 => self.probe_imap(stream, timeout_duration).await,
            53 => self.probe_dns(stream, timeout_duration).await,
            3389 => self.probe_rdp(stream, timeout_duration).await,
            5432 => self.probe_postgresql(stream, timeout_duration).await,
            3306 => self.probe_mysql(stream, timeout_duration).await,
            1433 => self.probe_mssql(stream, timeout_duration).await,
            139 | 445 => self.probe_smb(stream, timeout_duration).await,
            _ => self.probe_generic(stream, timeout_duration, port).await,
        }
    }

    async fn simple_banner_grab(&self, stream: &mut TcpStream, port: u16) -> Result<String> {
        let timeout_duration = Duration::from_millis(self.timeout_ms);

        // Send appropriate probe based on port
        let probe = get_probe_for_port(port);

        if let Some(probe_data) = probe {
            debug!("Sending probe to port {port}");
            let _ = timeout(timeout_duration, stream.write_all(probe_data.as_bytes())).await;
        }

        // Read response
        let mut buffer = vec![0; 1024];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if bytes_read > 0 {
                let banner = String::from_utf8_lossy(&buffer[..bytes_read])
                    .trim()
                    .replace('\r', "")
                    .replace('\n', " ")
                    .to_string();

                if !banner.is_empty() {
                    debug!("Grabbed banner from port {port}: {banner}");
                    return Ok(banner);
                }
            }
        }

        Err(anyhow::anyhow!("No banner received"))
    }

    // SSH Protocol Probe
    async fn probe_ssh(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            let response = String::from_utf8_lossy(&buffer[..bytes_read]);
            if response.starts_with("SSH-") {
                let version_line = response.lines().next().unwrap_or("").trim();
                return Ok(ProbeResult {
                    service: "SSH".to_string(),
                    banner: version_line.to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("SSH probe failed"))
    }

    // TLS/SSL Protocol Probe
    async fn probe_tls(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        // TLS ClientHello handshake (simplified)
        let client_hello = vec![
            0x16, 0x03, 0x01, 0x00, 0x2a, // TLS Handshake, version 3.1, length 42
            0x01, 0x00, 0x00, 0x26, // Client Hello, length 38
            0x03, 0x03, // Version TLS 1.2
            // Random bytes (32 bytes) - simplified to zeros
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, // Session ID length
            0x00, 0x02, // Cipher suites length
            0x00, 0x35, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x01, 0x00, // Compression methods
        ];

        let _ = timeout(timeout_duration, stream.write_all(&client_hello)).await;

        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if bytes_read >= 5 && buffer[0] == 0x16 {
                return Ok(ProbeResult {
                    service: "TLS/SSL".to_string(),
                    banner: format!(
                        "TLS handshake successful (version: {}.{})",
                        buffer[1], buffer[2]
                    ),
                });
            }
        }
        Err(anyhow::anyhow!("TLS probe failed"))
    }

    // HTTP Protocol Probe
    async fn probe_http(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        let http_request = "GET / HTTP/1.1\r\nHost: target\r\nUser-Agent: NullScan/1.0\r\nConnection: close\r\n\r\n";

        let _ = timeout(timeout_duration, stream.write_all(http_request.as_bytes())).await;

        let mut buffer = vec![0; 512];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            let response = String::from_utf8_lossy(&buffer[..bytes_read]);
            if response.starts_with("HTTP/") {
                let status_line = response.lines().next().unwrap_or("").trim();
                let server_header = response
                    .lines()
                    .find(|line| line.to_lowercase().starts_with("server:"))
                    .unwrap_or("")
                    .trim();

                let banner = if !server_header.is_empty() {
                    format!("{status_line} {server_header}")
                } else {
                    status_line.to_string()
                };

                return Ok(ProbeResult {
                    service: "HTTP".to_string(),
                    banner,
                });
            }
        }
        Err(anyhow::anyhow!("HTTP probe failed"))
    }

    // FTP Protocol Probe
    async fn probe_ftp(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            let response = String::from_utf8_lossy(&buffer[..bytes_read]);
            if response.starts_with("220") {
                let welcome_line = response.lines().next().unwrap_or("").trim();
                return Ok(ProbeResult {
                    service: "FTP".to_string(),
                    banner: welcome_line.to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("FTP probe failed"))
    }

    // SMTP Protocol Probe
    async fn probe_smtp(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            let response = String::from_utf8_lossy(&buffer[..bytes_read]);
            if response.starts_with("220") {
                let welcome_line = response.lines().next().unwrap_or("").trim();
                return Ok(ProbeResult {
                    service: "SMTP".to_string(),
                    banner: welcome_line.to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("SMTP probe failed"))
    }

    // POP3 Protocol Probe
    async fn probe_pop3(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            let response = String::from_utf8_lossy(&buffer[..bytes_read]);
            if response.starts_with("+OK") {
                let welcome_line = response.lines().next().unwrap_or("").trim();
                return Ok(ProbeResult {
                    service: "POP3".to_string(),
                    banner: welcome_line.to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("POP3 probe failed"))
    }

    // IMAP Protocol Probe
    async fn probe_imap(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            let response = String::from_utf8_lossy(&buffer[..bytes_read]);
            if response.starts_with("* OK") {
                let welcome_line = response.lines().next().unwrap_or("").trim();
                return Ok(ProbeResult {
                    service: "IMAP".to_string(),
                    banner: welcome_line.to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("IMAP probe failed"))
    }

    // DNS Protocol Probe
    async fn probe_dns(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        // Simple DNS query for version.bind
        let dns_query = vec![
            0x00, 0x1e, // Length
            0x12, 0x34, // Transaction ID
            0x00, 0x00, // Flags
            0x00, 0x01, // Questions: 1
            0x00, 0x00, // Answer RRs: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            0x07, b'v', b'e', b'r', b's', b'i', b'o', b'n', // "version"
            0x04, b'b', b'i', b'n', b'd', // "bind"
            0x00, // End of name
            0x00, 0x10, // Type: TXT
            0x00, 0x03, // Class: CHAOS
        ];

        let _ = timeout(timeout_duration, stream.write_all(&dns_query)).await;

        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if bytes_read >= 12 && buffer[2] & 0x80 != 0 {
                // Response bit set
                return Ok(ProbeResult {
                    service: "DNS".to_string(),
                    banner: "DNS server responding".to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("DNS probe failed"))
    }

    // RDP Protocol Probe
    async fn probe_rdp(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        // RDP Connection Request
        let rdp_probe = vec![
            0x03, 0x00, 0x00, 0x13, // TPKT Header
            0x0e, // X.224 Length
            0xe0, // X.224 Connection Request
            0x00, 0x00, 0x00, 0x00, 0x00, // Cookie
            0x01, 0x00, 0x08, 0x00, // RDP NEG REQ
            0x00, 0x00, 0x00, 0x00,
        ];

        let _ = timeout(timeout_duration, stream.write_all(&rdp_probe)).await;

        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if bytes_read >= 4 && buffer[0] == 0x03 && buffer[1] == 0x00 {
                return Ok(ProbeResult {
                    service: "RDP".to_string(),
                    banner: "Remote Desktop Protocol".to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("RDP probe failed"))
    }

    // PostgreSQL Protocol Probe
    async fn probe_postgresql(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        // PostgreSQL startup message
        let startup_msg = vec![
            0x00, 0x00, 0x00, 0x08, // Length
            0x04, 0xd2, 0x16, 0x2f, // SSL request
        ];

        let _ = timeout(timeout_duration, stream.write_all(&startup_msg)).await;

        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if bytes_read >= 1 && (buffer[0] == b'S' || buffer[0] == b'N') {
                return Ok(ProbeResult {
                    service: "PostgreSQL".to_string(),
                    banner: "PostgreSQL database".to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("PostgreSQL probe failed"))
    }

    // MySQL Protocol Probe
    async fn probe_mysql(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if bytes_read >= 5 && buffer[4] == 0x0a {
                // Protocol version 10
                let version_start = 5;
                let version_end = buffer[version_start..]
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(20)
                    .min(20)
                    + version_start;

                let version = String::from_utf8_lossy(&buffer[version_start..version_end]);
                return Ok(ProbeResult {
                    service: "MySQL".to_string(),
                    banner: format!("MySQL {version}"),
                });
            }
        }
        Err(anyhow::anyhow!("MySQL probe failed"))
    }

    // Microsoft SQL Server Protocol Probe
    async fn probe_mssql(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        // TDS Pre-login packet
        let tds_prelogin = vec![
            0x12, 0x01, 0x00, 0x2f, 0x00, 0x00, 0x01, 0x00, // TDS Header
            0x00, 0x00, 0x15, 0x00, 0x06, 0x01, 0x00, 0x1b, 0x00, 0x01, 0x02, 0x00, 0x1c, 0x00,
            0x01, 0x03, 0x00, 0x1d, 0x00, 0x00, 0xff, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x00, 0xb8, 0x0d, 0x00, 0x00, 0x01,
        ];

        let _ = timeout(timeout_duration, stream.write_all(&tds_prelogin)).await;

        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if bytes_read >= 8 && buffer[0] == 0x04 {
                // TDS Response
                return Ok(ProbeResult {
                    service: "MSSQL".to_string(),
                    banner: "Microsoft SQL Server".to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("MSSQL probe failed"))
    }

    // SMB Protocol Probe
    async fn probe_smb(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
    ) -> Result<ProbeResult> {
        // NetBIOS Session Request
        let netbios_request = vec![
            0x81, 0x00, 0x00, 0x44, // NetBIOS Session Request
        ];

        let _ = timeout(timeout_duration, stream.write_all(&netbios_request)).await;

        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if bytes_read >= 4 && (buffer[0] == 0x82 || buffer[0] == 0x83) {
                return Ok(ProbeResult {
                    service: "SMB/NetBIOS".to_string(),
                    banner: "SMB/CIFS file sharing".to_string(),
                });
            }
        }
        Err(anyhow::anyhow!("SMB probe failed"))
    }

    // Generic probe for unknown services
    async fn probe_generic(
        &self,
        stream: &mut TcpStream,
        timeout_duration: Duration,
        port: u16,
    ) -> Result<ProbeResult> {
        // Try to read initial banner without sending anything
        let mut buffer = vec![0; 256];
        if let Ok(Ok(bytes_read)) = timeout(timeout_duration, stream.read(&mut buffer)).await {
            if bytes_read > 0 {
                let banner = String::from_utf8_lossy(&buffer[..bytes_read])
                    .trim()
                    .replace(['\r', '\n'], " ")
                    .to_string();

                if !banner.is_empty() {
                    return Ok(ProbeResult {
                        service: format!("Unknown:{port}"),
                        banner,
                    });
                }
            }
        }
        Err(anyhow::anyhow!("Generic probe failed"))
    }
}

fn get_probe_for_port(port: u16) -> Option<&'static str> {
    match port {
        21 => None, // FTP sends banner immediately
        22 => None, // SSH sends banner immediately
        25 => None, // SMTP sends banner immediately
        80 => Some("GET / HTTP/1.1\r\nHost: \r\n\r\n"),
        443 => Some("GET / HTTP/1.1\r\nHost: \r\n\r\n"),
        110 => None, // POP3 sends banner immediately
        143 => None, // IMAP sends banner immediately
        993 => None, // IMAPS - would need TLS
        995 => None, // POP3S - would need TLS
        8080 => Some("GET / HTTP/1.1\r\nHost: \r\n\r\n"),
        8443 => Some("GET / HTTP/1.1\r\nHost: \r\n\r\n"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    async fn serve_once<F>(handler: F) -> u16
    where
        F: FnOnce(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((sock, _)) = listener.accept().await {
                handler(sock);
            }
        });
        port
    }

    #[tokio::test]
    async fn detects_ssh_banner_on_localhost() {
        let port = serve_once(|mut sock| {
            tokio::spawn(async move {
                let _ = sock.write_all(b"SSH-2.0-OpenSSH_8.4p1\r\n").await;
            });
        })
        .await;

        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let banner = BannerGrabber::new().grab_banner(stream, 22).await.unwrap();
        assert!(banner.starts_with("SSH - SSH-2.0-OpenSSH_8.4"));
    }

    #[tokio::test]
    async fn detects_http_server_header_on_localhost() {
        let port = serve_once(|mut sock| {
            tokio::spawn(async move {
                let mut buf = [0u8; 512];
                let _ = sock.read(&mut buf).await;
                let _ = sock
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await;
            });
        })
        .await;

        let stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
            .await
            .unwrap();
        let banner = BannerGrabber::new().grab_banner(stream, 80).await.unwrap();
        assert!(banner.contains("HTTP/1.1 200 OK"), "{banner}");
        assert!(banner.to_lowercase().contains("nginx/1.18.0"), "{banner}");
    }
}
