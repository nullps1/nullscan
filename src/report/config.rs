//! Report metadata from a TOML file, with optional CLI overrides.
//!
//! The generator refuses to build a report when the authorization reference,
//! signer name, or signed date is missing from both the file and the overrides.
//! A blank string counts as missing. The signed date must be a real calendar date.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::Args;
use serde::Deserialize;

#[derive(Debug, Clone, Args, Default)]
pub struct ReportOverrides {
    /// Client legal name. Overrides the config file.
    #[arg(long)]
    pub client: Option<String>,

    /// Client contact (person, role, email). Overrides the config file.
    #[arg(long)]
    pub client_contact: Option<String>,

    /// Written authorization reference. Required from the config or this flag.
    #[arg(long)]
    pub auth_ref: Option<String>,

    /// Name of the person who signed the authorization. Required from the config or this flag.
    #[arg(long)]
    pub signer: Option<String>,

    /// Title of the person who signed the authorization.
    #[arg(long)]
    pub signer_title: Option<String>,

    /// Date the authorization was signed. Required. A real calendar date, such as 2026-10-20.
    #[arg(long)]
    pub signed_date: Option<String>,

    /// Scope summary. Overrides the config file.
    #[arg(long)]
    pub scope: Option<String>,

    /// Who prepared the report.
    #[arg(long)]
    pub prepared_by: Option<String>,

    /// Weeks IT Solutions contact name.
    #[arg(long)]
    pub contact_name: Option<String>,

    /// Weeks IT Solutions contact email.
    #[arg(long)]
    pub contact_email: Option<String>,

    /// Weeks IT Solutions contact phone.
    #[arg(long)]
    pub contact_phone: Option<String>,

    /// Path to a PNG or JPEG logo. Overrides the config file.
    #[arg(long)]
    pub logo: Option<String>,

    /// Accent color as #RRGGBB. Decoration only; it does not encode severity.
    #[arg(long)]
    pub accent: Option<String>,

    /// Days after report delivery before scan data is deleted. The report says
    /// it is deleted this many days after delivery, or within 3 business days
    /// on request. Default in the TOML is 14.
    #[arg(long)]
    pub retention_days: Option<u32>,

    /// CVE database date to print, such as 2026-10-30. Overrides the scan export.
    #[arg(long)]
    pub cve_db_date: Option<String>,

    /// Include the one-page insurance appendix.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub insurance_appendix: bool,

    /// Omit the insurance appendix even if the config turns it on.
    #[arg(long, action = clap::ArgAction::SetTrue, conflicts_with = "insurance_appendix")]
    pub no_insurance_appendix: bool,

    /// Text substituted for {{rescan_offer}}.
    #[arg(long)]
    pub rescan_offer: Option<String>,

    /// Text substituted for {{monitoring_offer}}.
    #[arg(long)]
    pub monitoring_offer: Option<String>,

    /// Report ID. Generated when omitted.
    #[arg(long)]
    pub report_id: Option<String>,

    /// Comma-separated IPs treated as known mail hosts. Replaces the config list.
    #[arg(long)]
    pub known_mail_hosts: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedConfig {
    pub client_legal_name: String,
    pub client_contact: String,
    pub auth_ref: String,
    pub signer_name: String,
    pub signer_title: String,
    pub signed_date: String,
    pub scope: String,
    pub assets: Vec<String>,
    pub known_mail_hosts: Vec<String>,
    pub report_id: String,
    pub report_version: String,
    pub prepared_by: String,
    pub delivery_date: String,
    pub retention_days: u32,
    /// Set from the TOML field or `--cve-db-date`. Empty when neither was set.
    pub cve_db_date: String,
    pub insurance_appendix: bool,
    pub accent: (f32, f32, f32),
    pub logo: Option<Vec<u8>>,
    pub contact_name: String,
    pub contact_email: String,
    pub contact_phone: String,
    pub rescan_offer: String,
    pub monitoring_offer: String,
}

#[derive(Debug, Deserialize, Default)]
struct FileConfig {
    #[serde(default)]
    client: ClientSection,
    #[serde(default)]
    authorization: AuthSection,
    #[serde(default)]
    scope: ScopeSection,
    #[serde(default)]
    report: ReportSection,
    #[serde(default)]
    contact: ContactSection,
    #[serde(default)]
    offers: OfferSection,
}

#[derive(Debug, Deserialize, Default)]
struct ClientSection {
    #[serde(default)]
    legal_name: String,
    #[serde(default)]
    contact: String,
}

#[derive(Debug, Deserialize, Default)]
struct AuthSection {
    #[serde(default)]
    reference: String,
    #[serde(default)]
    signer_name: String,
    #[serde(default)]
    signer_title: String,
    #[serde(default)]
    signed_date: String,
}

#[derive(Debug, Deserialize, Default)]
struct ScopeSection {
    #[serde(default)]
    summary: String,
    #[serde(default)]
    assets: Vec<String>,
    #[serde(default)]
    known_mail_hosts: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReportSection {
    #[serde(default)]
    id: String,
    #[serde(default = "default_version")]
    version: String,
    #[serde(default = "default_prepared_by")]
    prepared_by: String,
    #[serde(default)]
    delivery_date: String,
    #[serde(default = "default_retention")]
    retention_days: u32,
    #[serde(default)]
    cve_db_date: String,
    #[serde(default)]
    insurance_appendix: bool,
    #[serde(default = "default_accent")]
    accent: String,
    #[serde(default)]
    logo_path: String,
}

#[derive(Debug, Deserialize)]
struct ContactSection {
    #[serde(default = "default_contact_name")]
    name: String,
    #[serde(default = "default_contact_email")]
    email: String,
    #[serde(default)]
    phone: String,
}

#[derive(Debug, Deserialize, Default)]
struct OfferSection {
    #[serde(default)]
    rescan: String,
    #[serde(default)]
    monitoring: String,
}

impl Default for ReportSection {
    fn default() -> Self {
        Self {
            id: String::new(),
            version: default_version(),
            prepared_by: default_prepared_by(),
            delivery_date: String::new(),
            retention_days: default_retention(),
            cve_db_date: String::new(),
            insurance_appendix: false,
            accent: default_accent(),
            logo_path: String::new(),
        }
    }
}

impl Default for ContactSection {
    fn default() -> Self {
        Self {
            name: default_contact_name(),
            email: default_contact_email(),
            phone: String::new(),
        }
    }
}

fn default_version() -> String {
    "0.1".to_string()
}
fn default_prepared_by() -> String {
    "Noah Weeks, Weeks IT Solutions".to_string()
}
fn default_retention() -> u32 {
    14
}
fn default_accent() -> String {
    "#1F4E79".to_string()
}
fn default_contact_name() -> String {
    "Noah Weeks".to_string()
}
fn default_contact_email() -> String {
    "noah@weeksitsolutions.com".to_string()
}

pub fn load(path: &Path, overrides: &ReportOverrides) -> Result<ResolvedConfig> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("Failed to read report config {}", path.display()))?;
    parse_config(&text, path, overrides)
}

pub fn parse_config(
    text: &str,
    config_path: &Path,
    overrides: &ReportOverrides,
) -> Result<ResolvedConfig> {
    let file: FileConfig = toml::from_str(text)
        .with_context(|| format!("Failed to parse report config {}", config_path.display()))?;
    resolve(file, config_path, overrides)
}

fn resolve(
    file: FileConfig,
    config_path: &Path,
    overrides: &ReportOverrides,
) -> Result<ResolvedConfig> {
    let auth_ref = override_nonempty(overrides.auth_ref.clone(), file.authorization.reference);
    if auth_ref.trim().is_empty() {
        bail!(
            "Refusing to build the report without an authorization reference. Set authorization.reference in the config or pass --auth-ref."
        );
    }
    let signer_name = override_nonempty(overrides.signer.clone(), file.authorization.signer_name);
    let signer_name = signer_name.trim().to_string();
    if signer_name.is_empty() {
        bail!(
            "Refusing to build the report without the authorization signer name. Set authorization.signer_name in the config or pass --signer."
        );
    }
    let signed_date = require_signed_date(&override_nonempty(
        overrides.signed_date.clone(),
        file.authorization.signed_date,
    ))?;

    let accent_hex = override_nonempty(overrides.accent.clone(), file.report.accent);
    let accent = parse_accent(&accent_hex)?;

    let logo_path = override_nonempty(overrides.logo.clone(), file.report.logo_path);
    let logo = load_logo(config_path, &logo_path)?;

    let known_mail_hosts = if let Some(list) = &overrides.known_mail_hosts {
        split_list(list)
    } else {
        file.scope.known_mail_hosts
    };

    let insurance_appendix = if overrides.no_insurance_appendix {
        false
    } else if overrides.insurance_appendix {
        true
    } else {
        file.report.insurance_appendix
    };

    let rescan_offer = override_nonempty(overrides.rescan_offer.clone(), file.offers.rescan);
    let monitoring_offer =
        override_nonempty(overrides.monitoring_offer.clone(), file.offers.monitoring);
    let cve_db_date = require_optional_date(
        &override_nonempty(overrides.cve_db_date.clone(), file.report.cve_db_date),
        "CVE database date",
    )?;

    Ok(ResolvedConfig {
        client_legal_name: override_nonempty(overrides.client.clone(), file.client.legal_name),
        client_contact: override_nonempty(overrides.client_contact.clone(), file.client.contact),
        auth_ref: auth_ref.trim().to_string(),
        signer_name,
        signer_title: override_nonempty(
            overrides.signer_title.clone(),
            file.authorization.signer_title,
        ),
        signed_date,
        scope: override_nonempty(overrides.scope.clone(), file.scope.summary),
        assets: file.scope.assets,
        known_mail_hosts,
        report_id: override_nonempty(overrides.report_id.clone(), file.report.id),
        report_version: file.report.version,
        prepared_by: override_nonempty(overrides.prepared_by.clone(), file.report.prepared_by),
        delivery_date: blank_to_today(&file.report.delivery_date),
        retention_days: overrides
            .retention_days
            .unwrap_or(file.report.retention_days),
        cve_db_date,
        insurance_appendix,
        accent,
        logo,
        contact_name: override_nonempty(overrides.contact_name.clone(), file.contact.name),
        contact_email: override_nonempty(overrides.contact_email.clone(), file.contact.email),
        contact_phone: override_nonempty(overrides.contact_phone.clone(), file.contact.phone),
        rescan_offer: rescan_offer.trim().to_string(),
        monitoring_offer: monitoring_offer.trim().to_string(),
    })
}

fn override_nonempty(over: Option<String>, file_value: String) -> String {
    match over {
        Some(value) if !value.trim().is_empty() => value,
        _ => file_value,
    }
}

fn require_signed_date(value: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        bail!(
            "Refusing to build the report without the authorization signed date. Set authorization.signed_date in the config or pass --signed-date."
        );
    }
    if parse_calendar_date(trimmed).is_none() {
        bail!(
            "Refusing to build the report because the authorization signed date {trimmed:?} is not a real date. Use a calendar date such as 2026-10-20."
        );
    }
    Ok(trimmed.to_string())
}

fn require_optional_date(value: &str, label: &str) -> Result<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if parse_calendar_date(trimmed).is_none() {
        bail!(
            "Refusing to build the report because the {label} {trimmed:?} is not a real date. Use a calendar date such as 2026-10-30."
        );
    }
    Ok(trimmed.to_string())
}

pub(crate) fn parse_calendar_date(value: &str) -> Option<chrono::NaiveDate> {
    const FORMATS: &[&str] = &[
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%m/%d/%Y",
        "%B %-d, %Y",
        "%b %-d, %Y",
        "%-d %B %Y",
        "%-d %b %Y",
    ];
    FORMATS
        .iter()
        .find_map(|format| chrono::NaiveDate::parse_from_str(value, format).ok())
}

fn blank_to_today(value: &str) -> String {
    if value.trim().is_empty() {
        today_in_denver()
    } else {
        value.trim().to_string()
    }
}

fn today_in_denver() -> String {
    chrono::Utc::now()
        .with_timezone(&chrono_tz::America::Denver)
        .format("%B %-d, %Y")
        .to_string()
}

fn split_list(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn parse_accent(value: &str) -> Result<(f32, f32, f32)> {
    let hex = value.trim().trim_start_matches('#');
    if hex.len() != 6 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        bail!("Accent color must be #RRGGBB, got {value}");
    }
    let channel = |start: usize| -> Result<f32> {
        let byte = u8::from_str_radix(&hex[start..start + 2], 16)
            .context("Accent color must be #RRGGBB")?;
        Ok(byte as f32 / 255.0)
    };
    Ok((channel(0)?, channel(2)?, channel(4)?))
}

fn load_logo(config_path: &Path, logo_path: &str) -> Result<Option<Vec<u8>>> {
    if logo_path.trim().is_empty() {
        return Ok(None);
    }
    let direct = PathBuf::from(logo_path);
    let resolved = if direct.is_file() {
        direct
    } else {
        let beside_config = config_path.parent().unwrap_or(Path::new(".")).join(&direct);
        if beside_config.is_file() {
            beside_config
        } else {
            bail!("Logo file not found: {logo_path}");
        }
    };
    let bytes = fs::read(&resolved)
        .with_context(|| format!("Failed to read logo {}", resolved.display()))?;
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITHOUT_AUTH: &str = r#"
[client]
legal_name = "Example Co"
"#;

    const WITH_AUTH: &str = r#"
[client]
legal_name = "Example Co"
contact = "Pat Example"

[authorization]
reference = "AUTH-1"
signer_name = "Pat Example"
signer_title = "Owner"
signed_date = "2026-10-01"

[report]
accent = '#112233'
retention_days = 30
"#;

    #[test]
    fn refuses_without_authorization_reference() {
        let err = parse_config(
            WITHOUT_AUTH,
            Path::new("report.toml"),
            &ReportOverrides::default(),
        )
        .unwrap_err();
        let message = err.to_string();
        assert!(
            message.contains("authorization reference"),
            "unexpected error: {message}"
        );
    }

    fn complete_cli() -> ReportOverrides {
        ReportOverrides {
            auth_ref: Some("AUTH-CLI".to_string()),
            signer: Some("Pat Example".to_string()),
            signed_date: Some("2026-10-20".to_string()),
            ..ReportOverrides::default()
        }
    }

    #[test]
    fn cli_authorization_block_is_enough() {
        let config = parse_config(WITHOUT_AUTH, Path::new("report.toml"), &complete_cli()).unwrap();
        assert_eq!(config.auth_ref, "AUTH-CLI");
        assert_eq!(config.signer_name, "Pat Example");
        assert_eq!(config.signed_date, "2026-10-20");
        assert_eq!(config.client_legal_name, "Example Co");
        assert_eq!(config.contact_name, "Noah Weeks");
        assert_eq!(config.retention_days, 14);
        assert_eq!(config.cve_db_date, "");
        assert_eq!(config.rescan_offer, "");
        assert_eq!(config.monitoring_offer, "");
        assert_eq!(config.delivery_date, today_in_denver());
    }

    #[test]
    fn blank_signer_or_signed_date_is_refused() {
        let reference_only = "[authorization]\nreference = \"AUTH-1\"\n";
        let err = parse_config(
            reference_only,
            Path::new("report.toml"),
            &ReportOverrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("signer name"), "{}", err);

        let blank_signer = "[authorization]\nreference = \"AUTH-1\"\nsigner_name = \"   \"\nsigned_date = \"2026-10-20\"\n";
        let err = parse_config(
            blank_signer,
            Path::new("report.toml"),
            &ReportOverrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("signer name"), "{}", err);

        let blank_date = "[authorization]\nreference = \"AUTH-1\"\nsigner_name = \"Pat Example\"\nsigned_date = \"\"\n";
        let err = parse_config(
            blank_date,
            Path::new("report.toml"),
            &ReportOverrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("signed date"), "{}", err);

        let whitespace_date = "[authorization]\nreference = \"AUTH-1\"\nsigner_name = \"Pat Example\"\nsigned_date = \"   \"\n";
        let err = parse_config(
            whitespace_date,
            Path::new("report.toml"),
            &ReportOverrides::default(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("signed date"), "{}", err);
    }

    #[test]
    fn signed_date_must_be_a_real_calendar_date() {
        let base = "[authorization]\nreference = \"AUTH-1\"\nsigner_name = \"Pat Example\"\n";
        for bad in [
            "soon",
            "2026-02-31",
            "2026-13-01",
            "2026-02-29",
            "not provided",
        ] {
            let text = format!("{base}signed_date = \"{bad}\"\n");
            let err = parse_config(&text, Path::new("report.toml"), &ReportOverrides::default())
                .unwrap_err();
            assert!(err.to_string().contains("not a real date"), "{bad}: {err}");
        }
        for good in [
            "2026-10-20",
            "2024-02-29",
            "2026/10/20",
            "10/20/2026",
            "October 20, 2026",
            "20 October 2026",
        ] {
            let text = format!("{base}signed_date = \"{good}\"\n");
            let config =
                parse_config(&text, Path::new("report.toml"), &ReportOverrides::default()).unwrap();
            assert_eq!(config.signed_date, good);
        }
    }

    #[test]
    fn cli_signer_and_signed_date_fill_a_blank_file() {
        let text =
            "[authorization]\nreference = \"AUTH-1\"\nsigner_name = \"\"\nsigned_date = \"\"\n";
        let overrides = ReportOverrides {
            signer: Some("  Casey Example  ".to_string()),
            signed_date: Some(" 2026-11-02 ".to_string()),
            ..ReportOverrides::default()
        };
        let config = parse_config(text, Path::new("report.toml"), &overrides).unwrap();
        assert_eq!(config.signer_name, "Casey Example");
        assert_eq!(config.signed_date, "2026-11-02");
    }

    #[test]
    fn blank_delivery_date_is_today_in_denver() {
        let config = parse_config(
            WITH_AUTH,
            Path::new("report.toml"),
            &ReportOverrides::default(),
        )
        .unwrap();
        assert_eq!(config.delivery_date, today_in_denver());

        let dated = r#"
[authorization]
reference = "AUTH-1"
signer_name = "Pat Example"
signed_date = "2026-10-01"

[report]
delivery_date = "  November 2, 2026  "
"#;
        let config =
            parse_config(dated, Path::new("report.toml"), &ReportOverrides::default()).unwrap();
        assert_eq!(config.delivery_date, "November 2, 2026");
    }

    #[test]
    fn file_values_and_overrides_merge() {
        let overrides = ReportOverrides {
            client: Some("Override LLC".to_string()),
            retention_days: Some(14),
            insurance_appendix: true,
            ..ReportOverrides::default()
        };
        let config = parse_config(WITH_AUTH, Path::new("report.toml"), &overrides).unwrap();
        assert_eq!(config.auth_ref, "AUTH-1");
        assert_eq!(config.client_legal_name, "Override LLC");
        assert_eq!(config.retention_days, 14);
        assert!(config.insurance_appendix);
        assert!((config.accent.0 - 17.0 / 255.0).abs() < 0.001);
    }

    #[test]
    fn blank_authorization_reference_is_refused() {
        let text = "[authorization]\nreference = \"   \"\n";
        let err =
            parse_config(text, Path::new("report.toml"), &ReportOverrides::default()).unwrap_err();
        assert!(err.to_string().contains("authorization reference"));
    }

    #[test]
    fn cve_database_date_must_be_a_real_date_when_set() {
        let base = "[authorization]\nreference = \"AUTH-1\"\nsigner_name = \"Pat Example\"\nsigned_date = \"2026-10-20\"\n";
        let bad = format!("{base}[report]\ncve_db_date = \"not recorded\"\n");
        let err =
            parse_config(&bad, Path::new("report.toml"), &ReportOverrides::default()).unwrap_err();
        assert!(err.to_string().contains("CVE database date"), "{err}");

        let good = format!("{base}[report]\ncve_db_date = \"2026-10-30\"\n");
        let config =
            parse_config(&good, Path::new("report.toml"), &ReportOverrides::default()).unwrap();
        assert_eq!(config.cve_db_date, "2026-10-30");

        let overrides = ReportOverrides {
            cve_db_date: Some("2026-11-02".to_string()),
            ..ReportOverrides::default()
        };
        let config = parse_config(&good, Path::new("report.toml"), &overrides).unwrap();
        assert_eq!(config.cve_db_date, "2026-11-02");
    }
}
