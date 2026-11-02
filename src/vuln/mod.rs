use anyhow::Result;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vulnerability {
    pub cve: String,
    pub description: String,
    pub severity: VulnSeverity,
    pub cvss_score: Option<f32>,
    pub published: Option<String>,
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VulnSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

impl VulnSeverity {
    pub fn to_color_code(&self) -> &'static str {
        match self {
            VulnSeverity::Critical => "🔴",
            VulnSeverity::High => "🟠",
            VulnSeverity::Medium => "🟡",
            VulnSeverity::Low => "🟢",
            VulnSeverity::Info => "🔵",
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            VulnSeverity::Critical => "Critical",
            VulnSeverity::High => "High",
            VulnSeverity::Medium => "Medium",
            VulnSeverity::Low => "Low",
            VulnSeverity::Info => "Info",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServicePattern {
    pub pattern: String,
    pub service_type: String,
    pub vulnerabilities: Vec<Vulnerability>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VulnDatabase {
    pub version: String,
    pub last_updated: String,
    pub patterns: Vec<ServicePattern>,
}

pub struct VulnChecker {
    database: VulnDatabase,
}

impl VulnChecker {
    pub fn load_from_file(path: &str) -> Result<Self> {
        info!("Loading vulnerability database from: {path}");

        let content = fs::read_to_string(path)?;
        let database: VulnDatabase = serde_json::from_str(&content)?;

        info!(
            "Loaded {} vulnerability patterns (DB version: {})",
            database.patterns.len(),
            database.version
        );

        Ok(VulnChecker { database })
    }

    pub fn check_banner(&self, banner: &str) -> Vec<Vulnerability> {
        let mut vulnerabilities = Vec::new();

        debug!("Checking banner: {banner}");

        // Normalize banner for matching
        let normalized_banner = banner.trim().to_lowercase();

        // Check against all patterns
        for pattern in &self.database.patterns {
            if self.matches_pattern(&normalized_banner, &pattern.pattern) {
                debug!("Banner matches pattern: {}", pattern.pattern);
                vulnerabilities.extend(pattern.vulnerabilities.clone());
            }
        }

        // Sort by severity (Critical first)
        vulnerabilities.sort_by(|a, b| {
            let severity_order = |s: &VulnSeverity| match s {
                VulnSeverity::Critical => 0,
                VulnSeverity::High => 1,
                VulnSeverity::Medium => 2,
                VulnSeverity::Low => 3,
                VulnSeverity::Info => 4,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        if !vulnerabilities.is_empty() {
            info!(
                "Found {} vulnerabilities for banner: {}",
                vulnerabilities.len(),
                banner
            );
        }

        vulnerabilities
    }

    fn matches_pattern(&self, banner: &str, pattern: &str) -> bool {
        // Support different pattern types
        if let Some(regex_pattern) = pattern.strip_prefix("regex:") {
            // Regex pattern matching
            if let Ok(re) = regex::Regex::new(regex_pattern) {
                return re.is_match(banner);
            }
        } else if let Some(substring) = pattern.strip_prefix("contains:") {
            // Simple substring matching
            return banner.contains(substring);
        } else if let Some(version_pattern) = pattern.strip_prefix("version:") {
            // Version-specific matching
            return self.matches_version(banner, version_pattern);
        } else {
            // Default: case-insensitive substring matching
            return banner.contains(&pattern.to_lowercase());
        }

        false
    }

    fn matches_version(&self, banner: &str, version_pattern: &str) -> bool {
        // Extract version from banner (basic implementation)
        // This could be enhanced with more sophisticated version parsing

        // Look for common version patterns
        let version_regex = regex::Regex::new(r"(\d+\.\d+(?:\.\d+)?)")
            .unwrap_or_else(|_| regex::Regex::new(r"").unwrap());

        if let Some(captures) = version_regex.find(banner) {
            let version = captures.as_str();

            // Simple version matching for now
            // TODO: Implement proper version range checking
            return version_pattern.contains(version);
        }

        false
    }

    pub fn get_stats(&self) -> VulnDbStats {
        let total_patterns = self.database.patterns.len();
        let total_vulns = self
            .database
            .patterns
            .iter()
            .map(|p| p.vulnerabilities.len())
            .sum();

        let mut severity_counts: HashMap<String, usize> = HashMap::new();
        for pattern in &self.database.patterns {
            for vuln in &pattern.vulnerabilities {
                *severity_counts
                    .entry(vuln.severity.as_str().to_owned())
                    .or_insert(0) += 1;
            }
        }

        VulnDbStats {
            total_patterns,
            total_vulnerabilities: total_vulns,
            severity_counts,
            version: self.database.version.clone(),
            last_updated: self.database.last_updated.clone(),
        }
    }
}

#[derive(Debug)]
pub struct VulnDbStats {
    pub total_patterns: usize,
    pub total_vulnerabilities: usize,
    pub severity_counts: HashMap<String, usize>,
    pub version: String,
    pub last_updated: String,
}

#[cfg(test)]
fn create_sample_database() -> VulnDatabase {
    VulnDatabase {
        version: "1.8.0".to_string(),
        last_updated: "2025-07-13".to_string(),
        patterns: vec![
            ServicePattern {
                pattern: "openssh 7.4".to_string(),
                service_type: "SSH".to_string(),
                vulnerabilities: vec![
                    Vulnerability {
                        cve: "CVE-2018-15473".to_string(),
                        description: "OpenSSH through 7.7 is prone to a user enumeration vulnerability due to not delaying bailout for an invalid authenticating user until after the packet containing the request has been fully parsed, related to auth2-gss.c, auth2-hostbased.c, and auth2-pubkey.c.".to_string(),
                        severity: VulnSeverity::Medium,
                        cvss_score: Some(5.3),
                        published: Some("2018-08-17".to_string()),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2018-15473".to_string(),
                            "https://security.netapp.com/advisory/ntap-20181221-0001/".to_string(),
                        ],
                    },
                ],
            },
            ServicePattern {
                pattern: "apache 2.4.41".to_string(),
                service_type: "HTTP".to_string(),
                vulnerabilities: vec![
                    Vulnerability {
                        cve: "CVE-2019-0211".to_string(),
                        description: "In Apache HTTP Server 2.4 releases 2.4.17 to 2.4.38, with MPM event, worker or prefork, code executing in less-privileged child processes or threads (including scripts executed by an in-process scripting interpreter) could execute arbitrary code with the privileges of the parent process (usually root) by manipulating the scoreboard.".to_string(),
                        severity: VulnSeverity::High,
                        cvss_score: Some(7.8),
                        published: Some("2019-04-08".to_string()),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2019-0211".to_string(),
                            "https://httpd.apache.org/security/vulnerabilities_24.html".to_string(),
                        ],
                    },
                ],
            },
            ServicePattern {
                pattern: "mysql 8.0.32".to_string(),
                service_type: "Database".to_string(),
                vulnerabilities: vec![
                    Vulnerability {
                        cve: "CVE-2023-21980".to_string(),
                        description: "Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.32 and prior and 8.0.33. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server.".to_string(),
                        severity: VulnSeverity::Medium,
                        cvss_score: Some(4.9),
                        published: Some("2023-04-18".to_string()),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2023-21980".to_string(),
                            "https://www.oracle.com/security-alerts/cpuapr2023.html".to_string(),
                        ],
                    },
                ],
            },
            ServicePattern {
                pattern: "nginx 1.18.0".to_string(),
                service_type: "HTTP".to_string(),
                vulnerabilities: vec![
                    Vulnerability {
                        cve: "CVE-2021-23017".to_string(),
                        description: "A security issue in nginx resolver was identified, which might allow an attacker who is able to forge UDP packets from the DNS server to cause 1-byte memory overwrite, resulting in worker process crash or potential other impact.".to_string(),
                        severity: VulnSeverity::High,
                        cvss_score: Some(7.7),
                        published: Some("2021-06-01".to_string()),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2021-23017".to_string(),
                            "https://nginx.org/en/security_advisories.html".to_string(),
                        ],
                    },
                ],
            },
            ServicePattern {
                pattern: "contains:ssh-2.0-openssh_8.0".to_string(),
                service_type: "SSH".to_string(),
                vulnerabilities: vec![
                    Vulnerability {
                        cve: "CVE-2020-14145".to_string(),
                        description: "The client side in OpenSSH 5.7 through 8.4 has an Observable Discrepancy leading to an information leak in the algorithm negotiation. This allows man-in-the-middle attackers to target initial connection attempts (where no host key for the server has been cached by the client).".to_string(),
                        severity: VulnSeverity::Medium,
                        cvss_score: Some(5.9),
                        published: Some("2020-12-02".to_string()),
                        references: vec![
                            "https://nvd.nist.gov/vuln/detail/CVE-2020-14145".to_string(),
                        ],
                    },
                ],
            },
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vulnerability_matching() {
        let sample_db = create_sample_database();
        let checker = VulnChecker {
            database: sample_db,
        };

        let vulns = checker.check_banner("OpenSSH 7.4p1 Ubuntu-10+deb9u7");
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].cve, "CVE-2018-15473");
    }

    #[test]
    fn test_no_vulnerabilities() {
        let sample_db = create_sample_database();
        let checker = VulnChecker {
            database: sample_db,
        };

        let vulns = checker.check_banner("OpenSSH 9.0 (completely secure version)");
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_severity_ordering() {
        let mut vulns = [
            Vulnerability {
                cve: "CVE-2021-1".to_string(),
                description: "Test".to_string(),
                severity: VulnSeverity::Low,
                cvss_score: None,
                published: None,
                references: vec![],
            },
            Vulnerability {
                cve: "CVE-2021-2".to_string(),
                description: "Test".to_string(),
                severity: VulnSeverity::Critical,
                cvss_score: None,
                published: None,
                references: vec![],
            },
        ];

        vulns.sort_by(|a, b| {
            let severity_order = |s: &VulnSeverity| match s {
                VulnSeverity::Critical => 0,
                VulnSeverity::High => 1,
                VulnSeverity::Medium => 2,
                VulnSeverity::Low => 3,
                VulnSeverity::Info => 4,
            };
            severity_order(&a.severity).cmp(&severity_order(&b.severity))
        });

        assert_eq!(vulns[0].cve, "CVE-2021-2"); // Critical should be first
    }

    fn db_path() -> String {
        format!("{}/vuln_db.json", env!("CARGO_MANIFEST_DIR"))
    }

    #[test]
    fn matches_patterns_from_vuln_db_file() {
        let checker = VulnChecker::load_from_file(&db_path()).expect("vuln_db.json");
        let stats = checker.get_stats();
        assert!(stats.total_patterns > 0);
        assert!(stats.total_vulnerabilities > 0);
        assert!(!stats.version.is_empty());
        assert!(stats.severity_counts.values().sum::<usize>() > 0);

        let openssh = checker.check_banner("SSH-2.0-OpenSSH_7.4");
        assert!(
            openssh.iter().any(|v| v.cve == "CVE-2018-15473"),
            "expected CVE-2018-15473, got {openssh:?}"
        );

        let apache = checker.check_banner("Apache/2.4.29 (Unix)");
        assert!(apache.iter().any(|v| v.cve == "CVE-2018-1312"));
        assert!(apache.iter().any(|v| v.severity.as_str() == "Medium"));

        let nginx = checker.check_banner("nginx 1.18.0");
        assert!(nginx.iter().any(|v| v.cve == "CVE-2021-23017"));
        assert!(nginx.iter().any(|v| v.severity.as_str() == "High"));

        let none = checker.check_banner("completely-unknown-banner-xyz");
        assert!(none.is_empty());
    }

    #[test]
    fn regex_and_version_patterns_order_by_severity() {
        let checker = VulnChecker {
            database: VulnDatabase {
                version: "test".to_string(),
                last_updated: "n/a".to_string(),
                patterns: vec![
                    ServicePattern {
                        pattern: r"regex:openssl/1\.0\.[0-2]".to_string(),
                        service_type: "TLS".to_string(),
                        vulnerabilities: vec![Vulnerability {
                            cve: "CVE-TEST-REGEX".to_string(),
                            description: "regex pattern".to_string(),
                            severity: VulnSeverity::Low,
                            cvss_score: None,
                            published: None,
                            references: vec![],
                        }],
                    },
                    ServicePattern {
                        pattern: "version:1.0.2".to_string(),
                        service_type: "TLS".to_string(),
                        vulnerabilities: vec![Vulnerability {
                            cve: "CVE-TEST-VER".to_string(),
                            description: "version pattern".to_string(),
                            severity: VulnSeverity::Critical,
                            cvss_score: Some(9.0),
                            published: None,
                            references: vec![],
                        }],
                    },
                ],
            },
        };

        let vulns = checker.check_banner("OpenSSL/1.0.2k");
        assert_eq!(vulns.len(), 2);
        assert_eq!(vulns[0].cve, "CVE-TEST-VER");
        assert_eq!(vulns[1].cve, "CVE-TEST-REGEX");
        assert_eq!(vulns[0].severity.to_color_code(), "🔴");
    }
}
