//! Turn a scan export plus report config into the sections the PDF prints.

use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{bail, Context, Result};
use chrono::{DateTime, Utc};

use crate::report::config::ResolvedConfig;
use crate::report::playbook::{self, PlaybookEntry};
use crate::report::severity::{self, Grade, Severity, SeverityCounts};
use crate::scanner::ScanResult;
use crate::vuln::Vulnerability;

pub struct ReportModel {
    pub config: ResolvedConfig,
    pub grade: Grade,
    pub counts: SeverityCounts,
    pub fix_first: Vec<FixRow>,
    pub findings: Vec<Finding>,
    pub appendix: Vec<RawRow>,
    pub top_actions: Vec<String>,
    pub summary_sentence: String,
    pub disclaimers: Vec<String>,
    pub summary: ScanSummary,
}

pub struct FixRow {
    pub name: String,
    pub where_label: String,
    pub severity: Severity,
    pub effort: String,
    pub who: String,
}

pub struct Finding {
    pub title: String,
    pub severity: Severity,
    pub where_label: String,
    pub detected: String,
    pub what: &'static str,
    pub why: &'static str,
    pub steps: Vec<String>,
    pub who: String,
    pub effort: String,
    pub technical: Vec<String>,
}

pub struct RawRow {
    pub host: String,
    pub port: u16,
    pub protocol: &'static str,
    pub service: String,
    pub banner: String,
    pub cves: Vec<String>,
}

pub struct ScanSummary {
    /// Authorized assets from the report config, or the scan target when the config lists none.
    pub scope_assets: String,
    /// Target string stored on the scan export.
    pub scan_target: String,
    pub total_ports: String,
    pub open_ports: String,
    pub closed_ports: String,
    pub duration: String,
    pub window_start: String,
    pub window_end: String,
    pub timezone_label: &'static str,
    pub nullscan_version: String,
    pub vuln_db_date: String,
}

struct BuiltFinding {
    severity: Severity,
    host: IpAddr,
    port: u16,
    entry: &'static PlaybookEntry,
    steps: Vec<String>,
    detected: String,
    technical: Vec<String>,
    cve_lines: Vec<String>,
    service: String,
    banner: String,
}

pub fn assemble(
    config: &ResolvedConfig,
    info: &HashMap<String, String>,
    results: &[ScanResult],
) -> Result<ReportModel> {
    let summary = summarize(config, info);
    let mut built = Vec::new();
    for result in results.iter().filter(|result| result.is_open) {
        built.push(build_finding(config, result));
    }
    built.sort_by(|left, right| {
        severity_rank(left.severity)
            .cmp(&severity_rank(right.severity))
            .then_with(|| left.host.cmp(&right.host))
            .then_with(|| left.port.cmp(&right.port))
    });

    let mut counts = SeverityCounts::default();
    for finding in &built {
        counts.add(finding.severity);
    }
    let grade = severity::overall_grade(&counts);

    let fix_first = built
        .iter()
        .filter(|finding| finding.severity > Severity::Info)
        .map(|finding| FixRow {
            name: finding.entry.plain_name.to_string(),
            where_label: format!("{}:{}", finding.host, finding.port),
            severity: finding.severity,
            effort: finding.entry.effort.label().to_string(),
            who: finding.entry.who.label().to_string(),
        })
        .collect::<Vec<_>>();

    let top_actions = if fix_first.is_empty() {
        vec![
            "Nothing on the fix-first list. Low and informational items are in the appendix."
                .to_string(),
        ]
    } else {
        fix_first
            .iter()
            .take(3)
            .map(|row| {
                let step = built
                    .iter()
                    .find(|finding| {
                        finding.entry.plain_name == row.name
                            && format!("{}:{}", finding.host, finding.port) == row.where_label
                    })
                    .and_then(|finding| finding.steps.first().map(String::as_str))
                    .unwrap_or("Confirm whether this should be reachable.");
                format!("{}: {step}", row.name)
            })
            .collect()
    };

    let findings = built
        .iter()
        .filter(|finding| finding.severity > Severity::Info)
        .map(|finding| Finding {
            title: playbook::title_for(finding.entry),
            severity: finding.severity,
            where_label: format!("{}:{}", finding.host, finding.port),
            detected: finding.detected.clone(),
            what: finding.entry.what,
            why: finding.entry.why,
            steps: finding.steps.clone(),
            who: finding.entry.who.label().to_string(),
            effort: finding.entry.effort.label().to_string(),
            technical: finding.technical.clone(),
        })
        .collect();

    let appendix = built
        .iter()
        .map(|finding| RawRow {
            host: finding.host.to_string(),
            port: finding.port,
            protocol: "TCP",
            service: finding.service.clone(),
            banner: finding.banner.clone(),
            cves: finding.cve_lines.clone(),
        })
        .collect();

    let disclaimers = disclaimers(config, &summary);

    Ok(ReportModel {
        config: config.clone(),
        grade,
        counts,
        fix_first,
        findings,
        appendix,
        top_actions,
        summary_sentence: summary_sentence(&grade, &counts),
        disclaimers,
        summary,
    })
}

/// One sentence for the cover. The letter, the word, and the shape are all in the text.
pub fn summary_sentence(grade: &Grade, counts: &SeverityCounts) -> String {
    format!(
        "Grade {} {} ({}): {} critical, {} high, {} medium, {} low, and {} informational.",
        grade.letter,
        grade.icon,
        grade.word,
        counts.critical,
        counts.high,
        counts.medium,
        counts.low,
        counts.info
    )
}

/// The retention sentence printed in the disclaimer. `days` comes from the TOML.
pub fn retention_clause(days: u32) -> String {
    let unit = if days == 1 { "day" } else { "days" };
    format!("deleted {days} {unit} after report delivery, or within 3 business days on request")
}

fn build_finding(config: &ResolvedConfig, result: &ScanResult) -> BuiltFinding {
    let scores = result
        .vulnerabilities
        .iter()
        .filter_map(|vuln| vuln.cvss_score)
        .collect::<Vec<_>>();
    let known_mail_host = is_known_mail_host(result.target, config);
    let severity = severity::classify(&severity::Exposure {
        port: result.port,
        service: result.service.as_deref(),
        banner: result.banner.as_deref(),
        cvss_scores: &scores,
        known_mail_host,
    });
    let entry = playbook::lookup(result.port, result.service.as_deref());
    let steps = playbook::instructions(entry, result.port);
    let detected = detected_label(result.service.as_deref(), result.banner.as_deref());

    let mut technical = Vec::new();
    match result.banner.as_deref() {
        Some(banner) if !banner.trim().is_empty() => {
            technical.push(format!("Banner: {}", truncate(banner.trim(), 400)));
        }
        _ => technical.push("Banner: none captured.".to_string()),
    }
    if let Some(note) = severity::eol_note(result.banner.as_deref()) {
        technical.push(format!(
            "End-of-life hint: {note}. Confirm the version with the vendor. This hint list is short and editable; it is not a complete end-of-life catalog."
        ));
    }
    let cve_lines = result
        .vulnerabilities
        .iter()
        .map(cve_line)
        .collect::<Vec<_>>();
    if cve_lines.is_empty() {
        technical.push(
            "No CVE was matched from the banner. That does not prove the service is safe."
                .to_string(),
        );
    } else {
        technical.push(
            "CVE matches are inferred from the banner. Each one may be affected, needs confirming. This is not proof the service is affected."
                .to_string(),
        );
        technical.extend(cve_lines.iter().cloned());
    }

    BuiltFinding {
        severity,
        host: result.target,
        port: result.port,
        entry,
        steps,
        detected,
        technical,
        cve_lines,
        service: result
            .service
            .clone()
            .unwrap_or_else(|| "Unknown".to_string()),
        banner: result
            .banner
            .as_deref()
            .map(|banner| truncate(banner.trim(), 240))
            .unwrap_or_else(|| "—".to_string()),
    }
}

fn cve_line(vuln: &Vulnerability) -> String {
    let score = vuln
        .cvss_score
        .map(|score| format!("{score:.1}"))
        .unwrap_or_else(|| "n/a".to_string());
    let cve = vuln.cve.trim();
    format!(
        "{cve}  CVSS {score}  https://nvd.nist.gov/vuln/detail/{cve}  — may be affected, needs confirming"
    )
}

fn detected_label(service: Option<&str>, banner: Option<&str>) -> String {
    let version = banner.and_then(dotted_version);
    match (
        service.map(str::trim).filter(|value| !value.is_empty()),
        version,
    ) {
        (Some(service), Some(version)) => format!("{service} {version}"),
        (Some(service), None) => service.to_string(),
        (None, Some(version)) => version,
        (None, None) => "unknown".to_string(),
    }
}

/// Last dotted number in the banner. SSH banners lead with the protocol
/// version (`SSH-2.0-OpenSSH_7.4`); the software version is the later one.
fn dotted_version(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut found = None;
    let mut i = 0;
    while i + 2 < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let start = i;
            let mut j = i;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j < bytes.len()
                && bytes[j] == b'.'
                && j + 1 < bytes.len()
                && bytes[j + 1].is_ascii_digit()
            {
                j += 2;
                while j < bytes.len() && (bytes[j].is_ascii_digit() || bytes[j] == b'.') {
                    j += 1;
                }
                while j > start && bytes[j - 1] == b'.' {
                    j -= 1;
                }
                found = Some(text[start..j].to_string());
                i = j;
                continue;
            }
            i = j.max(i + 1);
        } else {
            i += 1;
        }
    }
    found
}

fn is_known_mail_host(ip: IpAddr, config: &ResolvedConfig) -> bool {
    let ip_text = ip.to_string();
    config
        .known_mail_hosts
        .iter()
        .any(|host| host.trim().eq_ignore_ascii_case(&ip_text))
}

fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 0,
        Severity::High => 1,
        Severity::Medium => 2,
        Severity::Low => 3,
        Severity::Info => 4,
    }
}

fn truncate(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (index, ch) in text.chars().enumerate() {
        if index >= max_chars {
            out.push('…');
            break;
        }
        if ch == '\n' || ch == '\r' || ch == '\t' {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

fn summarize(config: &ResolvedConfig, info: &HashMap<String, String>) -> ScanSummary {
    let (window_start, window_end) = scan_window(info);

    let vuln_db_date = usable_cve_date(&config.cve_db_date)
        .or_else(|| {
            info.get("vuln_db_updated")
                .and_then(|value| usable_cve_date(value))
        })
        .unwrap_or_else(|| crate::vuln::bundled_last_updated().to_string());

    let nullscan_version = info
        .get("nullscan_version")
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| format!("{} (this report generator)", env!("CARGO_PKG_VERSION")));

    let scan_target = info
        .get("target")
        .cloned()
        .unwrap_or_else(|| "not recorded".to_string());
    let scope_assets = if config.assets.is_empty() {
        scan_target.clone()
    } else {
        config.assets.join(", ")
    };

    ScanSummary {
        scope_assets,
        scan_target,
        total_ports: info
            .get("total_ports")
            .cloned()
            .unwrap_or_else(|| "not recorded".to_string()),
        open_ports: info
            .get("open_ports")
            .cloned()
            .unwrap_or_else(|| "not recorded".to_string()),
        closed_ports: info
            .get("closed_ports")
            .cloned()
            .unwrap_or_else(|| "not recorded".to_string()),
        duration: info
            .get("scan_duration")
            .cloned()
            .unwrap_or_else(|| "not recorded".to_string()),
        window_start,
        window_end,
        timezone_label: "America/Denver",
        nullscan_version,
        vuln_db_date,
    }
}

fn scan_window(info: &HashMap<String, String>) -> (String, String) {
    let end_dt = info
        .get("scan_ended")
        .or_else(|| info.get("timestamp"))
        .and_then(|value| parse_time(value));
    let start_dt = info
        .get("scan_started")
        .and_then(|value| parse_time(value))
        .or_else(|| {
            let end = end_dt?;
            let duration = info
                .get("scan_duration")
                .and_then(|value| parse_loose_duration(value))?;
            let chrono_duration = chrono::Duration::from_std(duration).ok()?;
            Some(end - chrono_duration)
        });
    (format_denver(start_dt), format_denver(end_dt))
}

fn parse_time(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
}

fn format_denver(dt: Option<DateTime<Utc>>) -> String {
    match dt {
        Some(dt) => dt
            .with_timezone(&chrono_tz::America::Denver)
            .format("%B %-d, %Y at %-I:%M:%S %p %Z")
            .to_string(),
        None => "not recorded".to_string(),
    }
}

fn parse_loose_duration(value: &str) -> Option<std::time::Duration> {
    let value = value.trim();
    if let Some(rest) = value.strip_suffix("ms") {
        let millis = rest.trim().parse::<f64>().ok()?;
        return Some(std::time::Duration::from_secs_f64(
            (millis / 1000.0).max(0.0),
        ));
    }
    if let Some(rest) = value.strip_suffix('s') {
        if !rest.contains('m') {
            let seconds = rest.trim().parse::<f64>().ok()?;
            return Some(std::time::Duration::from_secs_f64(seconds.max(0.0)));
        }
    }
    None
}

/// A date worth printing. Placeholder notes such as "not recorded" are skipped.
fn usable_cve_date(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return None;
    }
    // Dates such as "November 2, 2026" are accepted by the config parser.
    // Try the whole string before the first word, or "November" is all that remains.
    if super::config::parse_calendar_date(trimmed).is_some() {
        return Some(trimmed.to_string());
    }
    let token = trimmed.split_whitespace().next().unwrap_or(trimmed);
    if token != trimmed && super::config::parse_calendar_date(token).is_some() {
        return Some(token.to_string());
    }
    None
}

pub fn fill_report_id(config: &mut ResolvedConfig, info: &HashMap<String, String>) {
    if !config.report_id.trim().is_empty() {
        return;
    }
    let stamp = info
        .get("scan_ended")
        .or_else(|| info.get("timestamp"))
        .map(String::as_str)
        .unwrap_or("");
    let day = stamp.get(..10).unwrap_or("undated").replace('-', "");
    let mut hash: u32 = 2_166_136_261;
    for byte in config
        .client_legal_name
        .as_bytes()
        .iter()
        .chain(stamp.as_bytes())
    {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(16_777_619);
    }
    config.report_id = format!("NS-{day}-{:04X}", hash & 0xFFFF);
}

fn disclaimers(config: &ResolvedConfig, summary: &ScanSummary) -> Vec<String> {
    let scan_end = if summary.window_end == "not recorded" {
        "the recorded scan end".to_string()
    } else {
        summary.window_end.clone()
    };
    let client = if config.client_legal_name.trim().is_empty() {
        "the named client"
    } else {
        config.client_legal_name.as_str()
    };
    let signed = if config.signed_date.trim().is_empty() {
        "an unrecorded date"
    } else {
        config.signed_date.as_str()
    };
    vec![
        format!(
            "Point-in-time snapshot of internet-facing services within the authorized scope as of {scan_end}. Your exposure can change at any time."
        ),
        "This is an external exposure check, not a penetration test, compliance certification, or guarantee of security. No exploitation was attempted.".to_string(),
        "Possible vulnerabilities are inferred from software version information and may include false positives or miss issues.".to_string(),
        format!(
            "Performed under written authorization {} signed {signed}. Only the listed assets were scanned.",
            config.auth_ref
        ),
        format!(
            "Confidential: prepared solely for {client}. Scan data is {}.",
            retention_clause(config.retention_days)
        ),
        "Not legal advice.".to_string(),
    ]
}

pub fn load_scan_json(path: &std::path::Path) -> Result<LoadedScan> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read scan export {}", path.display()))?;
    parse_scan_export(&text)
        .with_context(|| format!("Failed to parse scan export {}", path.display()))
}

pub fn parse_scan_export(text: &str) -> Result<LoadedScan> {
    let value: serde_json::Value = serde_json::from_str(text)
        .context("Refusing to build the report: the input is not valid JSON.")?;
    let Some(object) = value.as_object() else {
        bail!(
            "Refusing to build the report: the input is not a nullscan scan export. Expected a JSON object with scan_info and results."
        );
    };
    if !object.contains_key("scan_info") || !object.contains_key("results") {
        bail!(
            "Refusing to build the report: the input is not a nullscan scan export. Expected scan_info and results. An empty results array is valid when the scan found no open ports."
        );
    }
    let parsed: ExportFile = serde_json::from_value(value).context(
        "Refusing to build the report: scan_info must be an object of strings and results must be an array of scan rows.",
    )?;
    Ok(LoadedScan {
        info: parsed.scan_info,
        results: parsed.results,
    })
}

#[derive(Debug, serde::Deserialize)]
struct ExportFile {
    scan_info: HashMap<String, String>,
    results: Vec<ScanResult>,
}

#[derive(Debug)]
pub struct LoadedScan {
    pub info: HashMap<String, String>,
    pub results: Vec<ScanResult>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::config::{parse_config, ReportOverrides};
    use crate::vuln::{VulnSeverity, Vulnerability};
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn config() -> ResolvedConfig {
        parse_config(
            r#"
[client]
legal_name = "Example Co"
contact = "Pat Example"

[authorization]
reference = "AUTH-9"
signer_name = "Pat Example"
signer_title = "Owner"
signed_date = "2026-10-01"

[scope]
known_mail_hosts = ["198.51.100.20"]
"#,
            std::path::Path::new("report.toml"),
            &ReportOverrides::default(),
        )
        .unwrap()
    }

    fn result(
        ip: [u8; 4],
        port: u16,
        service: &str,
        banner: &str,
        cvss: Option<f32>,
    ) -> ScanResult {
        ScanResult {
            target: IpAddr::V4(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3])),
            port,
            is_open: true,
            service: Some(service.to_string()),
            banner: Some(banner.to_string()),
            response_time: Duration::from_millis(5),
            vulnerabilities: cvss
                .map(|score| {
                    vec![Vulnerability {
                        cve: "CVE-2020-0001".to_string(),
                        description: "example".to_string(),
                        severity: VulnSeverity::High,
                        cvss_score: Some(score),
                        published: None,
                        references: vec![],
                    }]
                })
                .unwrap_or_default(),
        }
    }

    #[test]
    fn cve_wording_never_says_is_vulnerable() {
        let mut config = config();
        config.report_id = "NS-TEST".to_string();
        let results = vec![result(
            [203, 0, 113, 10],
            22,
            "SSH",
            "SSH-2.0-OpenSSH_8.4",
            Some(5.3),
        )];
        let mut info = HashMap::new();
        info.insert("timestamp".to_string(), "2026-10-28T18:30:00Z".to_string());
        info.insert("vuln_db_updated".to_string(), "2025-07-13".to_string());
        let model = assemble(&config, &info, &results).unwrap();
        let technical = model
            .findings
            .iter()
            .flat_map(|finding| finding.technical.iter())
            .cloned()
            .collect::<Vec<_>>()
            .join("\n");
        assert!(technical.contains("may be affected, needs confirming"));
        assert!(
            model
                .findings
                .iter()
                .any(|finding| finding.detected.contains("8.4")),
            "software version should win over the SSH protocol version: {:?}",
            model
                .findings
                .iter()
                .map(|finding| finding.detected.clone())
                .collect::<Vec<_>>()
        );
        assert!(!technical.to_lowercase().contains("is vulnerable"));
        assert!(model
            .appendix
            .iter()
            .flat_map(|row| row.cves.iter())
            .all(|line| line.contains("may be affected, needs confirming")));
    }

    #[test]
    fn info_is_counted_and_kept_out_of_fix_first() {
        let mut config = config();
        config.report_id = "NS-TEST".to_string();
        let results = vec![
            result(
                [203, 0, 113, 10],
                443,
                "TLS/SSL",
                "TLS handshake successful",
                None,
            ),
            result(
                [198, 51, 100, 20],
                25,
                "SMTP",
                "220 mail.example.test ESMTP",
                None,
            ),
            result(
                [203, 0, 113, 10],
                3389,
                "RDP",
                "Remote Desktop Protocol",
                None,
            ),
        ];
        let model = assemble(&config, &HashMap::new(), &results).unwrap();
        assert_eq!(model.grade.letter, 'F');
        assert_eq!(model.counts.info, 2);
        assert_eq!(model.counts.critical, 1);
        assert_eq!(model.fix_first.len(), 1);
        assert!(model
            .findings
            .iter()
            .all(|finding| finding.severity > Severity::Info));
        assert_eq!(model.appendix.len(), 3);
    }

    #[test]
    fn mysql_on_3307_tells_the_reader_to_block_3307() {
        let model = assemble(
            &config(),
            &HashMap::new(),
            &[result(
                [203, 0, 113, 10],
                3307,
                "MySQL",
                "MySQL 5.7.33",
                None,
            )],
        )
        .unwrap();
        let steps = model.findings[0].steps.join("\n");
        let actions = model.top_actions.join("\n");
        assert!(steps.contains("3307"), "{steps}");
        assert!(!steps.contains("3306"), "{steps}");
        assert!(actions.contains("3307"), "{actions}");
        assert!(!actions.contains("3306"), "{actions}");
    }

    #[test]
    fn rejects_json_that_is_not_a_scan_export() {
        for text in [
            "{}",
            "[]",
            "{\"version\":\"2\"}",
            "{\"scan_info\":{}}",
            "{\"results\":[]}",
        ] {
            let err = parse_scan_export(text).unwrap_err();
            let message = err.to_string();
            assert!(
                message.contains("scan export") || message.contains("scan_info"),
                "{text}: {message}"
            );
        }
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let err = load_scan_json(&root.join("vuln_db.json")).unwrap_err();
        let message = format!("{err:#}");
        assert!(
            message.contains("not a nullscan scan export"),
            "vuln_db.json should not build a report: {message}"
        );
    }

    #[test]
    fn accepts_an_explicitly_empty_results_array() {
        let loaded = parse_scan_export(
            r#"{"scan_info":{"target":"203.0.113.10","open_ports":"0"},"results":[]}"#,
        )
        .unwrap();
        assert!(loaded.results.is_empty());
        let model = assemble(&config(), &loaded.info, &loaded.results).unwrap();
        assert_eq!(model.grade.letter, 'A');
        assert!(model.findings.is_empty());
        assert!(model.fix_first.is_empty());
    }

    #[test]
    fn summary_sentence_includes_the_grade_shape() {
        let sentence = summary_sentence(
            &severity::overall_grade(&SeverityCounts {
                critical: 1,
                high: 0,
                medium: 2,
                low: 0,
                info: 3,
            }),
            &SeverityCounts {
                critical: 1,
                high: 0,
                medium: 2,
                low: 0,
                info: 3,
            },
        );
        assert_eq!(
            sentence,
            "Grade F ✖ (Act now): 1 critical, 0 high, 2 medium, 0 low, and 3 informational."
        );
        assert!(sentence.contains('✖'));
    }

    #[test]
    fn retention_clause_uses_fourteen_days_by_default() {
        let model = assemble(&config(), &HashMap::new(), &[]).unwrap();
        let text = model.disclaimers.join("\n");
        assert!(
            text.contains(
                "deleted 14 days after report delivery, or within 3 business days on request"
            ),
            "{text}"
        );
        assert!(!text.contains("90 days"));
    }

    #[test]
    fn cve_database_date_falls_back_to_the_bundled_database() {
        let model = assemble(&config(), &HashMap::new(), &[]).unwrap();
        assert_eq!(
            model.summary.vuln_db_date,
            crate::vuln::bundled_last_updated()
        );
        assert!(!model
            .summary
            .vuln_db_date
            .to_ascii_lowercase()
            .contains("not recorded"));

        let mut info = HashMap::new();
        info.insert("vuln_db_updated".to_string(), "not recorded".to_string());
        let model = assemble(&config(), &info, &[]).unwrap();
        assert_eq!(
            model.summary.vuln_db_date,
            crate::vuln::bundled_last_updated()
        );

        info.insert("vuln_db_updated".to_string(), "not run".to_string());
        let model = assemble(&config(), &info, &[]).unwrap();
        assert_eq!(
            model.summary.vuln_db_date,
            crate::vuln::bundled_last_updated()
        );

        info.insert("vuln_db_updated".to_string(), "2024-01-15".to_string());
        let model = assemble(&config(), &info, &[]).unwrap();
        assert_eq!(model.summary.vuln_db_date, "2024-01-15");

        let mut dated = config();
        dated.cve_db_date = "2026-10-30".to_string();
        info.insert("vuln_db_updated".to_string(), "2020-01-01".to_string());
        let model = assemble(&dated, &info, &[]).unwrap();
        assert_eq!(model.summary.vuln_db_date, "2026-10-30");

        dated.cve_db_date = "November 2, 2026".to_string();
        let model = assemble(&dated, &info, &[]).unwrap();
        assert_eq!(model.summary.vuln_db_date, "November 2, 2026");
    }
}
