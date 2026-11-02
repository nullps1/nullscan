//! Severity and overall grade for the external exposure report.
//!
//! Finding severity uses the highest matching rule. The rules and the A–F
//! thresholds are the front-office outline, kept here so they can be tested
//! without rendering a PDF.

/// Bracketed severity tag. The letter, the word, and the shape are all text.
/// Color is not part of the tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn word(self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
            Severity::Info => "INFO",
        }
    }

    /// Shape icon required by the outline. These code points are in DejaVu Sans.
    pub fn icon(self) -> &'static str {
        match self {
            Severity::Critical => "✖",
            Severity::High => "■",
            Severity::Medium => "▲",
            Severity::Low => "●",
            Severity::Info => "○",
        }
    }

    pub fn tag(self) -> String {
        format!("[{} {}]", self.word(), self.icon())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeverityCounts {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl SeverityCounts {
    pub fn add(&mut self, severity: Severity) {
        match severity {
            Severity::Critical => self.critical += 1,
            Severity::High => self.high += 1,
            Severity::Medium => self.medium += 1,
            Severity::Low => self.low += 1,
            Severity::Info => self.info += 1,
        }
    }
}

/// Letter, plain-language label, and shape. All three are printed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Grade {
    pub letter: char,
    pub word: &'static str,
    pub icon: &'static str,
    pub meaning: &'static str,
}

impl Grade {
    pub fn badge(&self) -> String {
        format!("{}  {}  {}", self.letter, self.word, self.icon)
    }
}

/// Overall grade. Evaluated in outline order: F, then D, then C, then B, then A.
pub fn overall_grade(counts: &SeverityCounts) -> Grade {
    if counts.critical > 0 {
        Grade {
            letter: 'F',
            word: "Act now",
            icon: "✖",
            meaning: "A critical exposure is reachable from the internet. Act now.",
        }
    } else if counts.high >= 2 {
        Grade {
            letter: 'D',
            word: "At risk",
            icon: "■",
            meaning: "More than one high-severity exposure is reachable from the internet.",
        }
    } else if counts.medium >= 4 || counts.high == 1 {
        Grade {
            letter: 'C',
            word: "Needs attention",
            icon: "▲",
            meaning: "This needs attention: four or more medium findings, or one high finding.",
        }
    } else if counts.medium >= 1 {
        Grade {
            letter: 'B',
            word: "Good, minor fixes",
            icon: "●",
            meaning: "Up to three medium items need minor fixes. Nothing high or critical.",
        }
    } else {
        Grade {
            letter: 'A',
            word: "Solid",
            icon: "✔",
            meaning: "Nothing above low severity showed up in this check.",
        }
    }
}

/// One open port, as the rules see it.
pub struct Exposure<'a> {
    pub port: u16,
    pub service: Option<&'a str>,
    pub banner: Option<&'a str>,
    /// CVSS scores of banner-matched CVEs. Missing scores are omitted by the caller.
    pub cvss_scores: &'a [f32],
    /// True when this host is listed as a known mail host in the report config.
    pub known_mail_host: bool,
}

/// Ports the outline calls critical remote-access or data services.
const CRITICAL_PORTS: &[u16] = &[
    3389, 445, 23, 5900, 3306, 5432, 1433, 1521, 27017, 6379, 9200,
];

const MANAGEMENT_PORTS: &[u16] = &[22, 161, 8080, 8443, 10000];

/// Banner substrings that mean "this looks end-of-life".
///
/// This is a short editable hint list, not a vendor end-of-life feed. nullscan
/// does not query an EOL database. Add a lowercase substring to extend it.
const EOL_MARKERS: &[(&str, &str)] = &[
    ("openssl/1.0.", "OpenSSL 1.0 is end of life"),
    ("openssl/1.1.0", "OpenSSL 1.1.0 is end of life"),
    ("openssl/1.1.1", "OpenSSL 1.1.1 is end of life"),
    ("apache/2.2", "Apache HTTP Server 2.2 is end of life"),
    (
        "apache/2.4.29",
        "This Apache 2.4 build is far past upstream support",
    ),
    ("openssh_5.", "OpenSSH 5.x is end of life"),
    ("openssh_6.", "OpenSSH 6.x is end of life"),
    ("openssh_7.", "OpenSSH 7.x is end of life"),
    ("php/5.", "PHP 5 is end of life"),
    ("php/7.", "PHP 7 is end of life"),
    ("nginx/1.14.", "nginx 1.14 is end of life"),
    ("nginx/1.16.", "nginx 1.16 is end of life"),
    ("iis/6.", "IIS 6 is end of life"),
    ("iis/7.", "IIS 7 is end of life"),
    ("iis/8.0", "IIS 8.0 is end of life"),
    ("iis/8.5", "IIS 8.5 is end of life"),
    ("mysql 5.5", "MySQL 5.5 is end of life"),
    ("mysql 5.6", "MySQL 5.6 is end of life"),
    ("mysql 5.7", "MySQL 5.7 is end of life"),
    ("vsftpd 2.", "vsftpd 2.x is end of life"),
    ("proftpd 1.3.5", "ProFTPD 1.3.5 is end of life"),
];

const CAMERA_OR_PRINTER: &[&str] = &[
    "printer",
    "laserjet",
    "jetdirect",
    "cups/",
    "cups ",
    "hikvision",
    "dahua",
    "ip camera",
    "ipcam",
    "webcam",
    "network camera",
];

/// Highest matching outline rule wins.
pub fn classify(exposure: &Exposure<'_>) -> Severity {
    let mut ranks = [Severity::Info; 8];
    let mut n = 0;
    let mut push = |severity: Severity| {
        if n < ranks.len() {
            ranks[n] = severity;
            n += 1;
        }
    };

    if let Some(score) = max_cvss(exposure.cvss_scores) {
        push(severity_from_cvss(score));
    }
    if CRITICAL_PORTS.contains(&exposure.port) || is_critical_service(exposure.service) {
        push(Severity::Critical);
    }
    if is_cleartext_admin(exposure.port, exposure.service) || eol_note(exposure.banner).is_some() {
        push(Severity::High);
    }
    if is_management(exposure.port, exposure.service, exposure.banner) {
        push(Severity::Medium);
    }
    // A 3xx response is informational. It does not pick up the plain-HTTP or
    // version-leak rules. A CVE score, critical service, cleartext login, or
    // end-of-life banner still outranks it.
    let redirect = is_http_redirect(exposure.banner);
    if !redirect
        && (leaks_version(exposure.banner)
            || (exposure.port == 80 && exposure.cvss_scores.is_empty()))
    {
        push(Severity::Low);
    }
    if redirect || is_expected_quiet(exposure) {
        push(Severity::Info);
    }

    if n == 0 {
        // An open port the outline does not name. It is still reachable, so it
        // is a finding (low), not an informational expected service.
        Severity::Low
    } else {
        ranks[..n].iter().copied().max().unwrap()
    }
}

pub fn eol_note(banner: Option<&str>) -> Option<&'static str> {
    let banner = banner?.to_ascii_lowercase();
    EOL_MARKERS
        .iter()
        .find(|(marker, _)| banner.contains(marker))
        .map(|(_, note)| *note)
}

fn max_cvss(scores: &[f32]) -> Option<f32> {
    scores.iter().copied().reduce(f32::max)
}

fn severity_from_cvss(score: f32) -> Severity {
    if score >= 9.0 {
        Severity::Critical
    } else if score >= 7.0 {
        Severity::High
    } else if score >= 4.0 {
        Severity::Medium
    } else {
        Severity::Low
    }
}

fn is_critical_service(service: Option<&str>) -> bool {
    contains_any(
        service,
        &[
            "rdp",
            "remote desktop",
            "telnet",
            "vnc",
            "smb",
            "mysql",
            "postgres",
            "mssql",
            "oracle",
            "mongodb",
            "mongo",
            "redis",
            "elasticsearch",
        ],
    )
}

fn is_cleartext_admin(port: u16, service: Option<&str>) -> bool {
    let ftp = port == 21
        || (contains_any(service, &["ftp"])
            && !contains_any(service, &["sftp", "ftps"])
            && port != 990);
    let pop = port == 110 || (contains_any(service, &["pop3"]) && port != 995);
    let imap = port == 143
        || (contains_any(service, &["imap"]) && !contains_any(service, &["imaps"]) && port != 993);
    ftp || pop || imap
}

fn is_management(port: u16, service: Option<&str>, banner: Option<&str>) -> bool {
    MANAGEMENT_PORTS.contains(&port)
        || contains_any(service, &["ssh", "snmp"])
        || contains_any(service, CAMERA_OR_PRINTER)
        || contains_any(banner, CAMERA_OR_PRINTER)
}

fn is_expected_quiet(exposure: &Exposure<'_>) -> bool {
    if exposure.port == 443 {
        return true;
    }
    exposure.known_mail_host && (exposure.port == 25 || exposure.port == 587)
}

fn leaks_version(banner: Option<&str>) -> bool {
    banner.is_some_and(has_dotted_version)
}

/// Status code from an HTTP response line in the banner, such as `HTTP/1.1 301`.
pub fn http_status(banner: &str) -> Option<u16> {
    let lower = banner.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(index) = rest.find("http/") {
        let after = &rest[index + 5..];
        let space = after.find(char::is_whitespace)?;
        let version = &after[..space];
        if version.is_empty() || !version.chars().all(|ch| ch.is_ascii_digit() || ch == '.') {
            rest = &after[space..];
            continue;
        }
        let after_space = after[space..].trim_start();
        let mut digits = String::new();
        for ch in after_space.chars() {
            if !ch.is_ascii_digit() {
                break;
            }
            digits.push(ch);
            if digits.len() > 3 {
                break;
            }
        }
        if digits.len() == 3 {
            if let Ok(code) = digits.parse::<u16>() {
                let boundary = after_space[digits.len()..].chars().next();
                if boundary.is_none_or(|ch| !ch.is_ascii_digit()) {
                    return Some(code);
                }
            }
        }
        let mut advanced = after_space.chars();
        advanced.next();
        rest = advanced.as_str();
        if rest.is_empty() {
            break;
        }
    }
    None
}

/// True when the banner is an HTTP 3xx response, including redirects.
pub fn is_http_redirect(banner: Option<&str>) -> bool {
    banner
        .and_then(http_status)
        .is_some_and(|code| (300..400).contains(&code))
}

fn has_dotted_version(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j < bytes.len()
                && bytes[j] == b'.'
                && j + 1 < bytes.len()
                && bytes[j + 1].is_ascii_digit()
            {
                return true;
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    false
}

fn contains_any(value: Option<&str>, keys: &[&str]) -> bool {
    let Some(value) = value else {
        return false;
    };
    let value = value.to_ascii_lowercase();
    keys.iter().any(|key| value.contains(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exposure<'a>(
        port: u16,
        service: Option<&'a str>,
        banner: Option<&'a str>,
        scores: &'a [f32],
        known_mail_host: bool,
    ) -> Exposure<'a> {
        Exposure {
            port,
            service,
            banner,
            cvss_scores: scores,
            known_mail_host,
        }
    }

    #[test]
    fn critical_ports_and_cvss_nine() {
        for port in [
            3389, 445, 23, 5900, 3306, 5432, 1433, 1521, 27017, 6379, 9200,
        ] {
            assert_eq!(
                classify(&exposure(port, None, None, &[], false)),
                Severity::Critical,
                "port {port}"
            );
        }
        assert_eq!(
            classify(&exposure(
                80,
                Some("HTTP"),
                Some("Apache/2.4.49"),
                &[9.0],
                false
            )),
            Severity::Critical
        );
        assert_eq!(
            classify(&exposure(
                80,
                Some("HTTP"),
                Some("Apache/2.4.49"),
                &[9.8],
                false
            )),
            Severity::Critical
        );
    }

    #[test]
    fn critical_service_names_on_other_ports() {
        assert_eq!(
            classify(&exposure(3307, Some("MySQL"), None, &[], false)),
            Severity::Critical
        );
        assert_eq!(
            classify(&exposure(139, Some("SMB/NetBIOS"), None, &[], false)),
            Severity::Critical
        );
    }

    #[test]
    fn highest_rule_wins() {
        // Medium CVSS on a critical port stays critical.
        assert_eq!(
            classify(&exposure(3389, Some("RDP"), None, &[5.0], false)),
            Severity::Critical
        );
        // Critical CVSS on SSH beats the management-port rule.
        assert_eq!(
            classify(&exposure(
                22,
                Some("SSH"),
                Some("SSH-2.0-OpenSSH_9.0"),
                &[9.1],
                false
            )),
            Severity::Critical
        );
        // End-of-life banner beats a medium CVSS and the SSH management rule.
        assert_eq!(
            classify(&exposure(
                22,
                Some("SSH"),
                Some("SSH-2.0-OpenSSH_7.4"),
                &[5.3],
                false
            )),
            Severity::High
        );
    }

    #[test]
    fn high_medium_and_low_cvss_bands() {
        assert_eq!(
            classify(&exposure(8081, None, None, &[8.9], false)),
            Severity::High
        );
        assert_eq!(
            classify(&exposure(8081, None, None, &[7.0], false)),
            Severity::High
        );
        assert_eq!(
            classify(&exposure(8081, None, None, &[6.9], false)),
            Severity::Medium
        );
        assert_eq!(
            classify(&exposure(8081, None, None, &[4.0], false)),
            Severity::Medium
        );
        assert_eq!(
            classify(&exposure(8081, None, None, &[3.9], false)),
            Severity::Low
        );
    }

    #[test]
    fn cleartext_admin_and_eol_are_high() {
        assert_eq!(
            classify(&exposure(
                21,
                Some("FTP"),
                Some("220 vsftpd 3.0.5"),
                &[],
                false
            )),
            Severity::High
        );
        assert_eq!(
            classify(&exposure(110, Some("POP3"), None, &[], false)),
            Severity::High
        );
        assert_eq!(
            classify(&exposure(143, Some("IMAP"), None, &[], false)),
            Severity::High
        );
        // Implicit TLS ports are not treated as cleartext.
        assert_ne!(
            classify(&exposure(993, Some("IMAP"), None, &[], false)),
            Severity::High
        );
        assert_eq!(
            classify(&exposure(
                443,
                Some("TLS/SSL"),
                Some("OpenSSL/1.1.1k"),
                &[],
                false
            )),
            Severity::High
        );
    }

    #[test]
    fn management_surface_is_medium() {
        for port in [22, 161, 8080, 8443, 10000] {
            assert_eq!(
                classify(&exposure(port, None, None, &[], false)),
                Severity::Medium,
                "port {port}"
            );
        }
        assert_eq!(
            classify(&exposure(2222, Some("SSH"), None, &[], false)),
            Severity::Medium
        );
        assert_eq!(
            classify(&exposure(
                81,
                Some("HTTP"),
                Some("Hikvision camera httpd"),
                &[],
                false
            )),
            Severity::Medium
        );
    }

    #[test]
    fn low_and_expected_info() {
        assert_eq!(
            classify(&exposure(80, Some("HTTP"), Some("nginx"), &[], false)),
            Severity::Low
        );
        assert_eq!(
            classify(&exposure(
                8081,
                Some("HTTP"),
                Some("Acme Widget 1.2.3"),
                &[],
                false
            )),
            Severity::Low
        );
        assert_eq!(
            classify(&exposure(9, None, None, &[], false)),
            Severity::Low
        );
        assert_eq!(
            classify(&exposure(
                443,
                Some("TLS/SSL"),
                Some("TLS handshake successful"),
                &[],
                false
            )),
            Severity::Info
        );
        // A version in the banner is a low finding, which outranks expected-service info.
        assert_eq!(
            classify(&exposure(
                443,
                Some("TLS/SSL"),
                Some("nginx/1.18.0"),
                &[],
                false
            )),
            Severity::Low
        );
        assert_eq!(
            classify(&exposure(
                25,
                Some("SMTP"),
                Some("220 mail.example.test ESMTP"),
                &[],
                true
            )),
            Severity::Info
        );
        assert_eq!(
            classify(&exposure(587, Some("SMTP"), None, &[], true)),
            Severity::Info
        );
        // Same mail port, but the host was not listed as a known mail host.
        assert_eq!(
            classify(&exposure(
                25,
                Some("SMTP"),
                Some("220 mail.example.test ESMTP"),
                &[],
                false
            )),
            Severity::Low
        );
    }

    #[test]
    fn http_3xx_redirects_are_info() {
        for banner in [
            "HTTP/1.0 301 Moved Permanently",
            "HTTP/1.1 302 Found",
            "HTTP/1.1 303 See Other",
            "HTTP/2 307 Temporary Redirect",
            "HTTP/1.1 308 Permanent Redirect Server: nginx/1.24.0",
            "HTTP/1.1 300 Multiple Choices",
        ] {
            assert_eq!(
                classify(&exposure(80, Some("HTTP"), Some(banner), &[], false)),
                Severity::Info,
                "{banner}"
            );
        }
        // A normal page on port 80 is still low. A version leak is still low.
        assert_eq!(
            classify(&exposure(
                80,
                Some("HTTP"),
                Some("HTTP/1.1 200 OK Server: nginx"),
                &[],
                false
            )),
            Severity::Low
        );
        assert_eq!(
            classify(&exposure(
                8081,
                Some("HTTP"),
                Some("HTTP/1.1 200 OK Server: nginx/1.24.0"),
                &[],
                false
            )),
            Severity::Low
        );
        // A redirect does not hide a critical CVE, an end-of-life banner, or a
        // management port.
        assert_eq!(
            classify(&exposure(
                80,
                Some("HTTP"),
                Some("HTTP/1.1 301 Moved Permanently Server: Apache/2.4.49"),
                &[9.8],
                false
            )),
            Severity::Critical
        );
        assert_eq!(
            classify(&exposure(
                80,
                Some("HTTP"),
                Some("HTTP/1.1 301 Moved Permanently Server: Apache/2.2.34"),
                &[],
                false
            )),
            Severity::High
        );
        assert_eq!(
            classify(&exposure(
                8080,
                Some("HTTP"),
                Some("HTTP/1.1 302 Found"),
                &[],
                false
            )),
            Severity::Medium
        );
    }

    #[test]
    fn tags_include_word_and_shape() {
        assert_eq!(Severity::Critical.tag(), "[CRITICAL ✖]");
        assert_eq!(Severity::High.tag(), "[HIGH ■]");
        assert_eq!(Severity::Medium.tag(), "[MEDIUM ▲]");
        assert_eq!(Severity::Low.tag(), "[LOW ●]");
        assert_eq!(Severity::Info.tag(), "[INFO ○]");
    }

    #[test]
    fn grade_thresholds() {
        let grade = |c, h, m, l, i| {
            overall_grade(&SeverityCounts {
                critical: c,
                high: h,
                medium: m,
                low: l,
                info: i,
            })
            .letter
        };

        assert_eq!(grade(0, 0, 0, 0, 0), 'A');
        assert_eq!(grade(0, 0, 0, 4, 3), 'A');
        assert_eq!(grade(0, 0, 1, 0, 0), 'B');
        assert_eq!(grade(0, 0, 3, 9, 9), 'B');
        assert_eq!(grade(0, 0, 4, 0, 0), 'C');
        assert_eq!(grade(0, 1, 0, 0, 0), 'C');
        assert_eq!(grade(0, 1, 4, 0, 0), 'C');
        assert_eq!(grade(0, 2, 0, 0, 0), 'D');
        assert_eq!(grade(0, 5, 3, 0, 0), 'D');
        assert_eq!(grade(1, 0, 0, 0, 0), 'F');
        assert_eq!(grade(1, 4, 9, 0, 0), 'F');
    }

    #[test]
    fn grade_badge_has_letter_word_and_shape() {
        let counts = SeverityCounts {
            critical: 1,
            ..SeverityCounts::default()
        };
        let grade = overall_grade(&counts);
        assert_eq!(grade.badge(), "F  Act now  ✖");
        let solid = overall_grade(&SeverityCounts::default());
        assert_eq!(solid.badge(), "A  Solid  ✔");
    }
}
