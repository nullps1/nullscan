use axum::{
    extract::{Path, State},
    response::Html,
};
use std::sync::Arc;
use uuid::Uuid;

use crate::web::state::AppState;

pub async fn dashboard_index(State(state): State<Arc<AppState>>) -> Html<String> {
    let summary = state.get_summary().await;

    Html(format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NullScan - Red Team Dashboard</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e94560;
            min-height: 100vh;
            overflow-x: hidden;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        .header {{
            text-align: center;
            margin-bottom: 3rem;
            position: relative;
        }}

        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 50%;
            transform: translateX(-50%);
            width: 100px;
            height: 2px;
            background: linear-gradient(90deg, transparent, #e94560, transparent);
        }}

        .header h1 {{
            font-size: 3rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            text-shadow: 0 0 20px rgba(233, 69, 96, 0.5);
        }}

        .header p {{
            font-size: 1.2rem;
            opacity: 0.8;
            color: #f39c12;
        }}

        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 2rem;
            margin-bottom: 3rem;
        }}

        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(233, 69, 96, 0.3);
            border-radius: 12px;
            padding: 2rem;
            text-align: center;
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }}

        .stat-card::before {{
            content: '';
            position: absolute;
            top: -50%;
            left: -50%;
            width: 200%;
            height: 200%;
            background: radial-gradient(circle, rgba(233, 69, 96, 0.1) 0%, transparent 70%);
            opacity: 0;
            transition: opacity 0.3s ease;
        }}

        .stat-card:hover::before {{
            opacity: 1;
        }}

        .stat-card:hover {{
            transform: translateY(-5px);
            border-color: #e94560;
            box-shadow: 0 10px 30px rgba(233, 69, 96, 0.3);
        }}

        .stat-number {{
            font-size: 2.5rem;
            font-weight: 700;
            color: #e94560;
            margin-bottom: 0.5rem;
        }}

        .stat-label {{
            font-size: 1rem;
            color: #f39c12;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        .actions {{
            display: flex;
            gap: 1rem;
            justify-content: center;
            margin-bottom: 3rem;
            flex-wrap: wrap;
        }}

        .btn {{
            padding: 1rem 2rem;
            border: none;
            border-radius: 8px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .btn-primary {{
            background: linear-gradient(45deg, #e94560, #f39c12);
            color: white;
        }}

        .btn-primary:hover {{
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(233, 69, 96, 0.4);
        }}

        .btn-secondary {{
            background: rgba(255, 255, 255, 0.1);
            color: #e94560;
            border: 1px solid rgba(233, 69, 96, 0.3);
        }}

        .btn-secondary:hover {{
            background: rgba(233, 69, 96, 0.1);
            border-color: #e94560;
        }}

        .scan-form {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(233, 69, 96, 0.3);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 3rem;
        }}

        .form-group {{
            margin-bottom: 1.5rem;
        }}

        .form-group label {{
            display: block;
            margin-bottom: 0.5rem;
            color: #f39c12;
            font-weight: 600;
        }}

        .form-group input,
        .form-group select {{
            width: 100%;
            padding: 0.75rem;
            border: 1px solid rgba(233, 69, 96, 0.3);
            border-radius: 6px;
            background: rgba(255, 255, 255, 0.05);
            color: #e94560;
            font-size: 1rem;
        }}

        .form-group input:focus,
        .form-group select:focus {{
            outline: none;
            border-color: #e94560;
            box-shadow: 0 0 0 2px rgba(233, 69, 96, 0.2);
        }}

        .form-row {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
        }}

        .checkbox-group {{
            display: flex;
            gap: 1rem;
            flex-wrap: wrap;
        }}

        .checkbox-item {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .checkbox-item input[type="checkbox"] {{
            width: auto;
        }}

        .recent-scans {{
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(233, 69, 96, 0.3);
            border-radius: 12px;
            padding: 2rem;
        }}

        .recent-scans h3 {{
            margin-bottom: 1.5rem;
            color: #f39c12;
            font-size: 1.5rem;
        }}

        .scan-list {{
            display: grid;
            gap: 1rem;
        }}

        .scan-item {{
            background: rgba(255, 255, 255, 0.03);
            border: 1px solid rgba(233, 69, 96, 0.2);
            border-radius: 8px;
            padding: 1rem;
            transition: all 0.3s ease;
            cursor: pointer;
            text-decoration: none;
            color: inherit;
            display: block;
        }}

        .scan-item:hover {{
            border-color: #e94560;
            background: rgba(233, 69, 96, 0.05);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(233, 69, 96, 0.2);
        }}

        .scan-item-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}

        .scan-status {{
            padding: 0.25rem 0.75rem;
            border-radius: 4px;
            font-size: 0.875rem;
            font-weight: 600;
        }}

        .status-running {{
            background: rgba(243, 156, 18, 0.2);
            color: #f39c12;
        }}

        .status-completed {{
            background: rgba(39, 174, 96, 0.2);
            color: #27ae60;
        }}

        .status-failed {{
            background: rgba(231, 76, 60, 0.2);
            color: #e74c3c;
        }}

        .footer {{
            text-align: center;
            margin-top: 3rem;
            padding-top: 2rem;
            border-top: 1px solid rgba(233, 69, 96, 0.3);
            color: rgba(255, 255, 255, 0.6);
        }}

        @media (max-width: 768px) {{
            .header h1 {{
                font-size: 2rem;
            }}

            .stats-grid {{
                grid-template-columns: 1fr;
            }}

            .actions {{
                flex-direction: column;
                align-items: center;
            }}

            .btn {{
                width: 100%;
                max-width: 300px;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 NullScan</h1>
            <p>Red Team Network Reconnaissance Dashboard</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">{}</div>
                <div class="stat-label">Total Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{}</div>
                <div class="stat-label">Active Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{}</div>
                <div class="stat-label">Hosts Scanned</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{}</div>
                <div class="stat-label">Open Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{}</div>
                <div class="stat-label">Vulnerabilities</div>
            </div>
        </div>

        <div class="actions">
            <button class="btn btn-primary" onclick="showScanForm()">
                🚀 Start New Scan
            </button>
            <button class="btn btn-secondary" onclick="refreshScans()">
                🔄 Refresh
            </button>
            <button class="btn btn-secondary" onclick="viewAPI()">
                📊 API Documentation
            </button>
        </div>

        <div class="scan-form" id="scanForm" style="display: none;">
            <h3 style="margin-bottom: 1.5rem; color: #f39c12;">Configure New Scan</h3>
            <form id="newScanForm">
                <div class="form-group">
                    <label for="target">Target (IP, hostname, or CIDR)</label>
                    <input type="text" id="target" name="target" placeholder="192.168.1.0/24 or example.com" required>
                </div>

                <div class="form-row">
                    <div class="form-group">
                        <label for="scanName">Scan Name</label>
                        <input type="text" id="scanName" name="scanName" placeholder="Production Network Scan">
                    </div>
                    <div class="form-group">
                        <label for="concurrency">Concurrency</label>
                        <input type="number" id="concurrency" name="concurrency" value="100" min="1" max="1000">
                    </div>
                </div>

                <div class="form-group">
                    <label>Port Selection</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="radio" id="top100" name="portSelection" value="top100" checked>
                            <label for="top100">Top 100 Ports</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="radio" id="top1000" name="portSelection" value="top1000">
                            <label for="top1000">Top 1000 Ports</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="radio" id="custom" name="portSelection" value="custom">
                            <label for="custom">Custom</label>
                        </div>
                    </div>
                    <input type="text" id="customPorts" name="customPorts" placeholder="80,443,8080,1-1000" style="margin-top: 0.5rem; display: none;">
                </div>

                <div class="form-group">
                    <label>Scan Options</label>
                    <div class="checkbox-group">
                        <div class="checkbox-item">
                            <input type="checkbox" id="banners" name="banners">
                            <label for="banners">Banner Grabbing</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="vulnCheck" name="vulnCheck">
                            <label for="vulnCheck">Vulnerability Check</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="pingSweep" name="pingSweep">
                            <label for="pingSweep">Ping Sweep</label>
                        </div>
                        <div class="checkbox-item">
                            <input type="checkbox" id="fastMode" name="fastMode">
                            <label for="fastMode">Fast Mode</label>
                        </div>
                    </div>
                </div>

                <div class="actions">
                    <button type="submit" class="btn btn-primary">🎯 Launch Scan</button>
                    <button type="button" class="btn btn-secondary" onclick="hideScanForm()">Cancel</button>
                </div>
            </form>
        </div>

        <div class="recent-scans">
            <h3>Recent Scans</h3>
            <div class="scan-list" id="scanList">
                <div style="text-align: center; padding: 2rem; color: rgba(255, 255, 255, 0.6);">
                    No scans yet. Start your first scan above!
                </div>
            </div>
        </div>

        <div class="footer">
            <p>NullScan v1.8.0 · nullps1 | systems builder</p>
            <p>Weeks IT Solutions · Authorized use only</p>
        </div>
    </div>

    <script>
        let scans = [];

        async function apiFetch(url, options) {{
            const response = await fetch(url, options);
            if (response.status === 401) {{
                window.location.href = '/login';
                throw new Error('unauthorized');
            }}
            return response;
        }}

        function showScanForm() {{
            document.getElementById('scanForm').style.display = 'block';
        }}

        function hideScanForm() {{
            document.getElementById('scanForm').style.display = 'none';
        }}

        function viewAPI() {{
            window.open('/api/health', '_blank');
        }}

        function viewScanDetails(scanId) {{
            window.location.href = `/scan/${{scanId}}`;
        }}

        document.getElementById('newScanForm').addEventListener('submit', async (e) => {{
            e.preventDefault();

            const formData = new FormData(e.target);
            const portSelection = formData.get('portSelection');

            const scanRequest = {{
                target: formData.get('target'),
                name: formData.get('scanName'),
                concurrency: parseInt(formData.get('concurrency')),
                top100: portSelection === 'top100',
                top1000: portSelection === 'top1000',
                ports: portSelection === 'custom' ? formData.get('customPorts') : null,
                banners: formData.get('banners') === 'on',
                vuln_check: formData.get('vulnCheck') === 'on',
                ping_sweep: formData.get('pingSweep') === 'on',
                fast_mode: formData.get('fastMode') === 'on'
            }};

            try {{
                const response = await apiFetch('/api/scan', {{
                    method: 'POST',
                    headers: {{
                        'Content-Type': 'application/json',
                    }},
                    body: JSON.stringify(scanRequest)
                }});

                const result = await response.json();

                if (result.success) {{
                    alert('Scan started successfully!');
                    hideScanForm();
                    refreshScans();
                }} else {{
                    alert('Error starting scan: ' + result.error);
                }}
            }} catch (error) {{
                alert('Error: ' + error.message);
            }}
        }});

        async function refreshScans() {{
            try {{
                const response = await apiFetch('/api/scans');
                const result = await response.json();

                if (result.success) {{
                    scans = result.data;
                    updateScanList();
                }}
            }} catch (error) {{
                console.error('Error refreshing scans:', error);
            }}
        }}

        function updateScanList() {{
            const scanList = document.getElementById('scanList');

            if (scans.length === 0) {{
                scanList.innerHTML = '<div style="text-align: center; padding: 2rem; color: rgba(255, 255, 255, 0.6);">No scans yet. Start your first scan above!</div>';
                return;
            }}

            scanList.innerHTML = scans.map(scan => `
                <div class="scan-item" onclick="viewScanDetails('${{scan.id}}')">
                    <div class="scan-item-header">
                        <strong>${{scan.name}}</strong>
                        <span class="scan-status status-${{scan.status.toLowerCase()}}">${{scan.status}}</span>
                    </div>
                    <div>Target: ${{scan.target}}</div>
                    <div>Created: ${{new Date(scan.created_at).toLocaleString()}}</div>
                    <div>Progress: ${{scan.progress.ports_scanned}}/${{scan.progress.total_ports}} ports</div>
                    <div style="margin-top: 0.5rem;">
                        <small style="color: rgba(255, 255, 255, 0.6);">Click to view detailed results →</small>
                    </div>
                </div>
            `).join('');
        }}

        // Port selection handling
        document.querySelectorAll('input[name="portSelection"]').forEach(radio => {{
            radio.addEventListener('change', function() {{
                const customPorts = document.getElementById('customPorts');
                if (this.value === 'custom') {{
                    customPorts.style.display = 'block';
                    customPorts.required = true;
                }} else {{
                    customPorts.style.display = 'none';
                    customPorts.required = false;
                }}
            }});
        }});

        // Auto-refresh scans every 5 seconds
        setInterval(refreshScans, 5000);

        // Initial load
        refreshScans();
    </script>
</body>
</html>
"#,
        summary.total_scans,
        summary.active_scans,
        summary.total_hosts_scanned,
        summary.total_open_ports,
        summary.total_vulnerabilities
    ))
}

pub async fn dashboard_scan_detail(
    Path(scan_id): Path<Uuid>,
    State(state): State<Arc<AppState>>,
) -> Html<String> {
    if let Some(scan_ref) = state.scans.get(&scan_id) {
        let scan = scan_ref.value().read().await;
        let status = format!("{:?}", scan.status);
        let open_ports = scan.results.iter().filter(|result| result.is_open).count();
        let vuln_count: usize = scan
            .results
            .iter()
            .map(|result| result.vulnerabilities.len())
            .sum();
        let rows = scan
            .results
            .iter()
            .map(|result| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td class=\"{}\">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{:.2}ms</td></tr>",
                    result.target,
                    result.port,
                    if result.is_open { "open-port" } else { "closed-port" },
                    if result.is_open { "Open" } else { "Closed" },
                    result.service.as_deref().unwrap_or("Unknown"),
                    result.banner.as_deref().unwrap_or("N/A"),
                    result.vulnerabilities.len(),
                    result.response_time.as_millis()
                )
            })
            .collect::<Vec<_>>()
            .join("");

        Html(format!(
            r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Scan Details - {}</title>
    <style>
        /* Include the same styles as dashboard_index */
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e94560;
            min-height: 100vh;
            margin: 0;
            padding: 2rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            text-align: center;
            margin-bottom: 2rem;
        }}
        .header h1 {{
            font-size: 2.5rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            text-shadow: 0 0 20px rgba(233, 69, 96, 0.5);
        }}
        .back-btn {{
            display: inline-block;
            padding: 0.75rem 1.5rem;
            background: rgba(255, 255, 255, 0.1);
            color: #e94560;
            text-decoration: none;
            border-radius: 6px;
            margin-bottom: 2rem;
            transition: all 0.3s ease;
        }}
        .back-btn:hover {{
            background: rgba(233, 69, 96, 0.1);
        }}
        .results-table {{
            width: 100%;
            border-collapse: collapse;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            overflow: hidden;
        }}
        .results-table th,
        .results-table td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(233, 69, 96, 0.2);
        }}
        .results-table th {{
            background: rgba(233, 69, 96, 0.1);
            color: #f39c12;
            font-weight: 600;
        }}
        .open-port {{
            color: #27ae60;
            font-weight: 600;
        }}
        .closed-port {{
            color: #e74c3c;
            opacity: 0.7;
        }}
    </style>
</head>
<body>
    <div class="container">
        <a href="/dashboard" class="back-btn">← Back to Dashboard</a>

        <div class="header">
            <h1>Scan Details</h1>
            <p>{} - {}</p>
        </div>

        <div style="margin-bottom: 2rem;">
            <h3>Scan Information</h3>
            <p><strong>Status:</strong> {}</p>
            <p><strong>Target:</strong> {}</p>
            <p><strong>Created:</strong> {}</p>
            <p><strong>Progress:</strong> {}/{} ports scanned</p>
            <p><strong>Open Ports:</strong> {}</p>
            <p><strong>Vulnerabilities:</strong> {}</p>
        </div>

        <h3>Results</h3>
        <table class="results-table">
            <thead>
                <tr>
                    <th>Host</th>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Service</th>
                    <th>Banner</th>
                    <th>Vulnerabilities</th>
                    <th>Response Time</th>
                </tr>
            </thead>
            <tbody>
                {}
            </tbody>
        </table>
    </div>
</body>
</html>
"#,
            scan.name,
            scan.name,
            scan.description,
            status,
            scan.target,
            scan.created_at.format("%Y-%m-%d %H:%M:%S"),
            scan.progress.ports_scanned,
            scan.progress.total_ports,
            open_ports,
            vuln_count,
            rows
        ))
    } else {
        Html("<h1>Scan not found</h1>".to_string())
    }
}
