use anyhow::Result;
use clap::ValueEnum;
use log::info;
use std::collections::HashMap;
use tokio::fs;

use crate::scanner::ScanResult;

#[derive(ValueEnum, Clone, Debug)]
pub enum ExportFormat {
    Json,
    Markdown,
    Csv,
    Html,
}

fn format_timestamp(timestamp_str: &str) -> String {
    // Try to parse the RFC3339 timestamp and format it nicely
    if let Ok(dt) = chrono::DateTime::parse_from_rfc3339(timestamp_str) {
        // Convert to local time
        let local_dt = dt.with_timezone(&chrono::Local);
        // Try to format with timezone name, fallback to offset if name is not available
        let formatted = local_dt.format("%B %d, %Y at %I:%M:%S %p").to_string();
        let tz_name = local_dt.format("%Z").to_string();

        // If timezone name is just the offset (like +00:00), show it differently
        if tz_name.starts_with('+') || tz_name.starts_with('-') {
            format!("{formatted} (UTC {tz_name})")
        } else {
            format!("{formatted} {tz_name}")
        }
    } else {
        // Fallback to original if parsing fails
        timestamp_str.to_string()
    }
}

pub async fn export_results(
    results: &[ScanResult],
    report: &HashMap<String, String>,
    format: ExportFormat,
    output_path: Option<String>,
) -> Result<()> {
    let content = match format {
        ExportFormat::Json => export_to_json(results, report)?,
        ExportFormat::Markdown => export_to_markdown(results, report),
        ExportFormat::Csv => export_to_csv(results),
        ExportFormat::Html => export_to_html(results, report),
    };

    match output_path {
        Some(path) => {
            fs::write(&path, content).await?;
            info!("📁 Results exported to: {path}");
        }
        None => {
            println!("{content}");
        }
    }

    Ok(())
}

fn export_to_json(results: &[ScanResult], report: &HashMap<String, String>) -> Result<String> {
    let output = serde_json::json!({
        "scan_info": report,
        "results": results.iter().filter(|r| r.is_open).collect::<Vec<_>>()
    });

    Ok(serde_json::to_string_pretty(&output)?)
}

fn export_to_markdown(results: &[ScanResult], report: &HashMap<String, String>) -> String {
    let mut output = String::new();

    // Header
    output.push_str("# 🔍 NullScan Report\n\n");

    // Scan information
    output.push_str("## 📊 Scan Information\n\n");
    output.push_str(&format!(
        "- **Target:** {}\n",
        report.get("target").unwrap_or(&"Unknown".to_string())
    ));
    output.push_str(&format!(
        "- **Total Ports Scanned:** {}\n",
        report.get("total_ports").unwrap_or(&"0".to_string())
    ));
    output.push_str(&format!(
        "- **Open Ports:** {}\n",
        report.get("open_ports").unwrap_or(&"0".to_string())
    ));
    output.push_str(&format!(
        "- **Closed Ports:** {}\n",
        report.get("closed_ports").unwrap_or(&"0".to_string())
    ));
    output.push_str(&format!(
        "- **Scan Duration:** {}\n",
        report
            .get("scan_duration")
            .unwrap_or(&"Unknown".to_string())
    ));
    output.push_str(&format!(
        "- **Timestamp:** {}\n\n",
        format_timestamp(report.get("timestamp").unwrap_or(&"Unknown".to_string()))
    ));

    // Group open ports by host IP
    let open_ports: Vec<_> = results.iter().filter(|r| r.is_open).collect();

    if open_ports.is_empty() {
        output.push_str("## 🚫 No Open Ports Found\n\n");
        output.push_str("All scanned ports were closed or filtered.\n");
    } else {
        // Group results by target IP
        let mut hosts_with_open_ports: std::collections::HashMap<
            std::net::IpAddr,
            Vec<&ScanResult>,
        > = std::collections::HashMap::new();

        for result in &open_ports {
            hosts_with_open_ports
                .entry(result.target)
                .or_default()
                .push(result);
        }

        // Sort hosts by IP address for consistent output
        let mut sorted_hosts: Vec<_> = hosts_with_open_ports.iter().collect();
        sorted_hosts.sort_by_key(|(ip, _)| ip.to_string());

        output.push_str("## 🟢 Open Ports\n\n");

        // Check if we have multiple hosts
        if sorted_hosts.len() == 1 {
            // Single host - use simple table format
            let (_, host_results) = sorted_hosts[0];
            output.push_str("| Port | Service | Banner | Response Time | Vulnerabilities |\n");
            output.push_str("|------|---------|--------|--------------|----------------|\n");

            for result in host_results {
                let service = result.service.as_deref().unwrap_or("Unknown");
                let banner = result.banner.as_deref().unwrap_or("N/A");
                let response_time = format!("{}ms", result.response_time.as_millis());

                // Format vulnerabilities
                let vulnerabilities = if result.vulnerabilities.is_empty() {
                    "None".to_string()
                } else {
                    result
                        .vulnerabilities
                        .iter()
                        .map(|v| {
                            format!(
                                "{} {} ({})",
                                v.severity.to_color_code(),
                                v.cve,
                                v.severity.as_str()
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("<br>")
                };

                output.push_str(&format!(
                    "| {} | {} | {} | {} | {} |\n",
                    result.port,
                    service,
                    banner.replace('|', "\\|"), // Escape pipes for markdown
                    response_time,
                    vulnerabilities.replace('|', "\\|")
                ));
            }
        } else {
            // Multiple hosts - group by host IP
            for (host_ip, host_results) in sorted_hosts {
                output.push_str(&format!("### 🖥️ Host: {host_ip}\n\n"));
                output.push_str("| Port | Service | Banner | Response Time | Vulnerabilities |\n");
                output.push_str("|------|---------|--------|--------------|----------------|\n");

                for result in host_results {
                    let service = result.service.as_deref().unwrap_or("Unknown");
                    let banner = result.banner.as_deref().unwrap_or("N/A");
                    let response_time = format!("{}ms", result.response_time.as_millis());

                    // Format vulnerabilities
                    let vulnerabilities = if result.vulnerabilities.is_empty() {
                        "None".to_string()
                    } else {
                        result
                            .vulnerabilities
                            .iter()
                            .map(|v| {
                                format!(
                                    "{} {} ({})",
                                    v.severity.to_color_code(),
                                    v.cve,
                                    v.severity.as_str()
                                )
                            })
                            .collect::<Vec<_>>()
                            .join("<br>")
                    };

                    output.push_str(&format!(
                        "| {} | {} | {} | {} | {} |\n",
                        result.port,
                        service,
                        banner.replace('|', "\\|"), // Escape pipes for markdown
                        response_time,
                        vulnerabilities.replace('|', "\\|")
                    ));
                }
                output.push('\n');
            }
        }
    }

    output.push_str("\n---\n");
    output.push_str("*Generated by NullScan v1.9.0*\n");

    output
}

fn export_to_csv(results: &[ScanResult]) -> String {
    let mut output = String::new();

    // Header
    output.push_str("Port,Status,Service,Banner,ResponseTime(ms),Vulnerabilities\n");

    // Data
    for result in results.iter().filter(|r| r.is_open) {
        let service = result.service.as_deref().unwrap_or("Unknown");
        let banner = result.banner.as_deref().unwrap_or("N/A");
        let response_time = result.response_time.as_millis();

        // Format vulnerabilities for CSV
        let vulnerabilities = if result.vulnerabilities.is_empty() {
            "None".to_string()
        } else {
            result
                .vulnerabilities
                .iter()
                .map(|v| format!("{} ({})", v.cve, v.severity.as_str()))
                .collect::<Vec<_>>()
                .join("; ")
        };

        output.push_str(&format!(
            "{},Open,\"{}\",\"{}\",{},\"{}\"\n",
            result.port,
            service,
            banner.replace('"', "\"\""), // Escape quotes for CSV
            response_time,
            vulnerabilities.replace('"', "\"\"") // Escape quotes for CSV
        ));
    }

    output
}

fn export_to_html(results: &[ScanResult], report: &HashMap<String, String>) -> String {
    let open_results: Vec<_> = results.iter().filter(|r| r.is_open).collect();

    // Group results by target IP for multi-host reports
    let mut targets: HashMap<String, Vec<_>> = HashMap::new();
    for result in &open_results {
        targets
            .entry(result.target.to_string())
            .or_default()
            .push(result);
    }

    let is_multi_host = targets.len() > 1;
    let timestamp = format_timestamp(
        report
            .get("timestamp")
            .map(|s| s.as_str())
            .unwrap_or("Unknown"),
    );
    let scan_duration = report
        .get("scan_duration")
        .map(|s| s.as_str())
        .unwrap_or("Unknown");
    let total_ports = report.get("total_ports").map(|s| s.as_str()).unwrap_or("0");
    let open_ports = report.get("open_ports").map(|s| s.as_str()).unwrap_or("0");

    let target_info = if is_multi_host {
        format!("{} hosts", targets.len())
    } else {
        targets
            .keys()
            .next()
            .unwrap_or(&"Unknown".to_string())
            .clone()
    };

    let mut html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>🔍 NullScan Report - {target_info}</title>
    <style>
        :root {{
            --primary-color: #2563eb;
            --success-color: #059669;
            --danger-color: #dc2626;
            --warning-color: #d97706;
            --dark-bg: #1f2937;
            --card-bg: #ffffff;
            --text-primary: #111827;
            --text-secondary: #6b7280;
            --border-color: #e5e7eb;
            --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            line-height: 1.6;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: var(--card-bg);
            border-radius: 12px;
            box-shadow: var(--shadow);
            overflow: hidden;
        }}

        .header {{
            background: var(--dark-bg);
            color: white;
            padding: 30px;
            text-align: center;
        }}

        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }}

        .header .subtitle {{
            color: #9ca3af;
            font-size: 1.1rem;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f9fafb;
        }}

        .stat-card {{
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            box-shadow: var(--shadow);
            text-align: center;
        }}

        .stat-value {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--primary-color);
        }}

        .stat-label {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-top: 5px;
        }}

        .results-section {{
            padding: 30px;
        }}

        .section-title {{
            font-size: 1.5rem;
            margin-bottom: 20px;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .host-group {{
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}

        .host-header {{
            background: #f3f4f6;
            padding: 15px 20px;
            border-bottom: 1px solid var(--border-color);
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: background-color 0.2s;
        }}

        .host-header:hover {{
            background: #e5e7eb;
        }}

        .host-title {{
            font-weight: 600;
            color: var(--text-primary);
        }}

        .port-count {{
            background: var(--success-color);
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .collapse-icon {{
            transition: transform 0.3s ease;
        }}

        .collapsed .collapse-icon {{
            transform: rotate(-90deg);
        }}

        .ports-table {{
            width: 100%;
            border-collapse: collapse;
            background: var(--card-bg);
        }}

        .ports-table th {{
            background: var(--primary-color);
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            cursor: pointer;
            user-select: none;
            position: relative;
        }}

        .ports-table th:hover {{
            background: #1d4ed8;
        }}

        .ports-table th::after {{
            content: '↕';
            position: absolute;
            right: 8px;
            opacity: 0.7;
        }}

        .ports-table td {{
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
            vertical-align: top;
        }}

        .ports-table tr:nth-child(even) {{
            background: #f9fafb;
        }}

        .ports-table tr:hover {{
            background: #f3f4f6;
        }}

        .port-number {{
            font-weight: 600;
            color: var(--primary-color);
            font-family: 'Courier New', monospace;
        }}

        .service-tag {{
            display: inline-block;
            padding: 4px 8px;
            background: var(--success-color);
            color: white;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: 600;
        }}

        .banner-text {{
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            background: #f3f4f6;
            padding: 6px 8px;
            border-radius: 4px;
            max-width: 400px;
            word-break: break-all;
            color: #374151;
        }}

        .vuln-cell {{
            font-size: 0.85rem;
            max-width: 300px;
        }}

        .vuln-cell div {{
            padding: 2px 0;
        }}

        .response-time {{
            color: var(--success-color);
            font-weight: 600;
        }}

        .no-results {{
            text-align: center;
            padding: 40px;
            color: var(--text-secondary);
        }}

        .footer {{
            background: #f9fafb;
            padding: 20px;
            text-align: center;
            color: var(--text-secondary);
            border-top: 1px solid var(--border-color);
        }}

        .controls {{
            margin-bottom: 20px;
            display: flex;
            gap: 10px;
            align-items: center;
        }}

        .btn {{
            padding: 8px 16px;
            border: 1px solid var(--border-color);
            background: white;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.9rem;
            transition: all 0.2s;
        }}

        .btn:hover {{
            background: #f3f4f6;
        }}

        .btn.active {{
            background: var(--primary-color);
            color: white;
            border-color: var(--primary-color);
        }}

        @media (max-width: 768px) {{
            .container {{
                margin: 10px;
                border-radius: 8px;
            }}

            .header {{
                padding: 20px;
            }}

            .header h1 {{
                font-size: 2rem;
            }}

            .stats-grid {{
                grid-template-columns: 1fr;
                padding: 20px;
            }}

            .results-section {{
                padding: 20px;
            }}

            .ports-table {{
                font-size: 0.9rem;
            }}

            .controls {{
                flex-direction: column;
                align-items: stretch;
            }}
        }}

        .collapsible-content {{
            max-height: 1000px;
            overflow: hidden;
            transition: max-height 0.3s ease;
        }}

        .collapsed .collapsible-content {{
            max-height: 0;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NullScan Report</h1>
            <div class="subtitle">Professional Port Scanning Results</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-value">{target_info}</div>
                <div class="stat-label">Target{}</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{total_ports}</div>
                <div class="stat-label">Ports Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{open_ports}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">{scan_duration}</div>
                <div class="stat-label">Scan Duration</div>
            </div>
        </div>

        <div class="results-section">
            <div class="section-title">
                🟢 Open Ports
            </div>

            <div class="controls">
                <button class="btn" onclick="expandAll()">Expand All</button>
                <button class="btn" onclick="collapseAll()">Collapse All</button>
                <button class="btn" onclick="exportToClipboard()">📋 Copy Results</button>
            </div>
"#,
        if is_multi_host { "s" } else { "" }
    );

    if open_results.is_empty() {
        html.push_str(
            r#"
            <div class="no-results">
                <h3>🚫 No Open Ports Found</h3>
                <p>All scanned ports were closed or filtered.</p>
            </div>
        "#,
        );
    } else {
        // Sort targets for consistent output
        let mut sorted_targets: Vec<_> = targets.into_iter().collect();
        sorted_targets.sort_by(|a, b| a.0.cmp(&b.0));

        for (target_ip, target_results) in sorted_targets {
            let host_id = target_ip
                .chars()
                .map(|c| if c == '.' || c == ':' { '_' } else { c })
                .collect::<String>();

            html.push_str(&format!(
                r#"
            <div class="host-group">
                <div class="host-header" onclick="toggleHost('{}')">
                    <div class="host-title">📡 {}</div>
                    <div class="port-count">{} ports</div>
                    <div class="collapse-icon">▼</div>
                </div>
                <div class="collapsible-content" id="content_{}">
                    <table class="ports-table">
                        <thead>
                            <tr>
                                <th onclick="sortTable('{}', 0)">Port</th>
                                <th onclick="sortTable('{}', 1)">Service</th>
                                <th onclick="sortTable('{}', 2)">Banner</th>
                                <th onclick="sortTable('{}', 3)">Vulnerabilities</th>
                                <th onclick="sortTable('{}', 4)">Response Time</th>
                            </tr>
                        </thead>
                        <tbody id="tbody_{}">
"#,
                host_id,
                target_ip,
                target_results.len(),
                host_id,
                host_id,
                host_id,
                host_id,
                host_id,
                host_id,
                host_id
            ));

            for result in target_results {
                let service = result.service.as_deref().unwrap_or("Unknown");
                let banner = result.banner.as_deref().unwrap_or("N/A");
                let response_time = result.response_time.as_millis();

                // Format vulnerabilities for HTML
                let vulnerabilities_html = if result.vulnerabilities.is_empty() {
                    "<span style=\"color: #6b7280;\">None</span>".to_string()
                } else {
                    result
                        .vulnerabilities
                        .iter()
                        .map(|v| {
                            let severity_str = v.severity.as_str();
                            let color = match severity_str {
                                "Critical" => "#dc2626",
                                "High" => "#ea580c",
                                "Medium" => "#d97706",
                                "Low" => "#059669",
                                _ => "#6b7280",
                            };
                            format!(
                                "<div style=\"color: {}; font-weight: 600; margin: 2px 0;\">🔴 {} ({})</div>",
                                color, v.cve, severity_str
                            )
                        })
                        .collect::<Vec<_>>()
                        .join("")
                };

                html.push_str(&format!(
                    r#"
                            <tr>
                                <td><span class="port-number">{}</span></td>
                                <td><span class="service-tag">{}</span></td>
                                <td><div class="banner-text">{}</div></td>
                                <td><div class="vuln-cell">{}</div></td>
                                <td><span class="response-time">{}ms</span></td>
                            </tr>
"#,
                    result.port,
                    service,
                    html_escape(banner),
                    vulnerabilities_html,
                    response_time
                ));
            }

            html.push_str(
                r#"
                        </tbody>
                    </table>
                </div>
            </div>
"#,
            );
        }
    }

    html.push_str(&format!(r#"
        </div>

        <div class="footer">
            <p>Generated by <strong>NullScan v1.9.0</strong> • {timestamp}</p>
            <p>nullps1 | systems builder • <a href="https://github.com/nullps1/nullscan" target="_blank">GitHub</a> • <a href="https://weeksitsolutions.com" target="_blank">Weeks IT Solutions</a></p>
        </div>
    </div>

    <script>
        function toggleHost(hostId) {{
            const content = document.getElementById('content_' + hostId);
            const header = content.previousElementSibling;

            if (content.style.maxHeight === '0px' || content.style.maxHeight === '') {{
                content.style.maxHeight = content.scrollHeight + 'px';
                header.classList.remove('collapsed');
            }} else {{
                content.style.maxHeight = '0px';
                header.classList.add('collapsed');
            }}
        }}

        function expandAll() {{
            document.querySelectorAll('.collapsible-content').forEach(content => {{
                content.style.maxHeight = content.scrollHeight + 'px';
                content.previousElementSibling.classList.remove('collapsed');
            }});
        }}

        function collapseAll() {{
            document.querySelectorAll('.collapsible-content').forEach(content => {{
                content.style.maxHeight = '0px';
                content.previousElementSibling.classList.add('collapsed');
            }});
        }}

        function sortTable(hostId, columnIndex) {{
            const table = document.getElementById('tbody_' + hostId);
            const rows = Array.from(table.rows);

            rows.sort((a, b) => {{
                const aVal = a.cells[columnIndex].textContent.trim();
                const bVal = b.cells[columnIndex].textContent.trim();

                // Special handling for port numbers and response times
                if (columnIndex === 0 || columnIndex === 4) {{
                    return parseInt(aVal) - parseInt(bVal);
                }}

                return aVal.localeCompare(bVal);
            }});

            // Re-append sorted rows
            rows.forEach(row => table.appendChild(row));
        }}

        function exportToClipboard() {{
            let text = 'NullScan Results\\n';
            text += '==================\\n\\n';

            document.querySelectorAll('.host-group').forEach(group => {{
                const hostTitle = group.querySelector('.host-title').textContent;
                text += hostTitle + '\\n';
                text += '-'.repeat(hostTitle.length) + '\\n';

                const rows = group.querySelectorAll('tbody tr');
                rows.forEach(row => {{
                    const cells = row.querySelectorAll('td');
                    const vulns = cells[3].textContent.trim() !== 'None' ? ` - Vulns: ${{cells[3].textContent.trim()}}` : '';
                    text += `Port ${{cells[0].textContent.trim()}}: ${{cells[1].textContent.trim()}} - ${{cells[2].textContent.trim()}}${{vulns}}\\n`;
                }});
                text += '\\n';
            }});

            navigator.clipboard.writeText(text).then(() => {{
                alert('Results copied to clipboard!');
            }}).catch(() => {{
                alert('Failed to copy to clipboard. Please select and copy manually.');
            }});
        }}

        // Initialize with all sections expanded
        document.addEventListener('DOMContentLoaded', () => {{
            expandAll();
        }});
    </script>
</body>
</html>"#));

    html
}

fn html_escape(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::ScanResult;
    use crate::vuln::{VulnSeverity, Vulnerability};
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn report() -> HashMap<String, String> {
        let mut report = HashMap::new();
        report.insert("target".to_string(), "127.0.0.1".to_string());
        report.insert("total_ports".to_string(), "2".to_string());
        report.insert("open_ports".to_string(), "1".to_string());
        report.insert("closed_ports".to_string(), "1".to_string());
        report.insert("scan_duration".to_string(), "12ms".to_string());
        report.insert("timestamp".to_string(), "2026-01-02T03:04:05Z".to_string());
        report
    }

    fn results() -> Vec<ScanResult> {
        let target = IpAddr::V4(Ipv4Addr::LOCALHOST);
        vec![
            ScanResult {
                target,
                port: 22,
                is_open: true,
                service: Some("SSH".to_string()),
                banner: Some("SSH-2.0-OpenSSH_7.4 <script>".to_string()),
                response_time: Duration::from_millis(12),
                vulnerabilities: vec![Vulnerability {
                    cve: "CVE-2018-15473".to_string(),
                    description: "user enum".to_string(),
                    severity: VulnSeverity::Medium,
                    cvss_score: Some(5.3),
                    published: None,
                    references: vec![],
                }],
            },
            ScanResult {
                target,
                port: 9,
                is_open: false,
                service: None,
                banner: None,
                response_time: Duration::from_millis(1),
                vulnerabilities: vec![],
            },
        ]
    }

    #[test]
    fn json_markdown_csv_and_html_include_open_ports_only() {
        let report = report();
        let results = results();

        let json = export_to_json(&results, &report).unwrap();
        assert!(json.contains("\"port\": 22"));
        assert!(json.contains("OpenSSH_7.4"));
        assert!(json.contains("CVE-2018-15473"));
        assert!(!json.contains("\"port\": 9"));

        let markdown = export_to_markdown(&results, &report);
        assert!(markdown.contains("# 🔍 NullScan Report"));
        assert!(markdown.contains("| 22 |"));
        assert!(markdown.contains("CVE-2018-15473"));
        assert!(markdown.contains("🟡"));
        assert!(!markdown.contains("| 9 |"));

        let csv = export_to_csv(&results);
        assert!(csv.starts_with("Port,Status,Service,Banner,ResponseTime(ms),Vulnerabilities\n"));
        assert!(csv.contains("22,Open,\"SSH\""));
        assert!(csv.contains("CVE-2018-15473 (Medium)"));
        assert!(!csv.contains("\n9,"));

        let html = export_to_html(&results, &report);
        assert!(html.contains("NullScan Report"));
        assert!(html.contains("https://github.com/nullps1/nullscan"));
        assert!(html.contains("weeksitsolutions.com"));
        assert!(!html.to_lowercase().contains("nullgrimoire"));
        assert!(html.contains("&lt;script&gt;"));
        assert!(html.contains("CVE-2018-15473"));
        assert!(!html.contains(">9<"));
    }

    #[tokio::test]
    async fn export_results_writes_json_file() {
        let path = std::env::temp_dir().join(format!(
            "nullscan-export-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        export_results(
            &results(),
            &report(),
            ExportFormat::Json,
            Some(path.display().to_string()),
        )
        .await
        .unwrap();
        let written = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(written.contains("127.0.0.1"));
        let _ = tokio::fs::remove_file(path).await;
    }
}
