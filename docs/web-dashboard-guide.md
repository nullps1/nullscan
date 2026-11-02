# 📊 NullScan Web Dashboard - Report Details Guide

There is **no default port**. Every example below uses `8080` only because that is the port passed to `--web-dashboard`. If you pass `3000`, open port `3000`.

The dashboard binds to `127.0.0.1` unless you set `--web-bind`. Binding any other address prints a warning on startup.

## Authentication

The UI and every `/api/*` route except `POST /api/session` require a bearer token.

- Omit `--web-token` and the process prints a token it generated for this run.
- Or set `--web-token` / the `NULLSCAN_WEB_TOKEN` environment variable. Supplied tokens are 16–256 characters of ASCII letters, digits, `-`, and `_`. They are not reprinted.
- Open `http://127.0.0.1:8080/login` and paste the token. The server sets an `HttpOnly` `SameSite=Strict` cookie named `nullscan_token`.
- Scripts send `Authorization: Bearer <token>` instead of using the cookie.
- Unauthenticated browser pages redirect to `/login`. Unauthenticated API calls return `401`.
- CORS is not enabled. Browser clients are the same-origin dashboard; other programs should call the API directly.

```bash
nullscan --web-dashboard 8080
# URL:   http://127.0.0.1:8080/dashboard
# Token: <printed once>

curl -H "Authorization: Bearer <printed-token>" http://127.0.0.1:8080/api/health
```

## 🎯 How to Access Detailed Reports

### Method 1: Via Web Dashboard
1. **Start the Web Dashboard**
   ```bash
   nullscan --web-dashboard 8080
   ```
2. **Sign in** at `http://127.0.0.1:8080/login` with the printed token.
3. **Open the dashboard** at `http://127.0.0.1:8080/dashboard`.

4. **View Recent Scans**
   - All your scans will be listed in the "Recent Scans" section
   - Each scan shows:
     - Scan name and status
     - Target information
     - Creation timestamp
     - Progress (ports scanned)

5. **Click on Any Scan**
   - Simply click on any scan item to view detailed results
   - You'll see the hint: "Click to view detailed results →"

### Method 2: Direct URL Access
If you know the scan ID, you can access the detailed report directly:
```
http://127.0.0.1:8080/scan/{scan-id}
```

The browser must already have the login cookie. Otherwise this URL redirects to `/login`.

### Method 3: API Access
You can also get scan details via the REST API:

```bash
# Get scan details
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:8080/api/scan/{scan-id}

# Get scan results
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:8080/api/scan/{scan-id}/results

# Export is not a full report yet. This route returns a placeholder.
# Use the CLI `--format json|markdown|csv|html` for a real report.
curl -H "Authorization: Bearer TOKEN" "http://127.0.0.1:8080/api/scan/{scan-id}/export?format=json"
```

## 🔍 What's in the Detailed Reports

### Scan Information Panel
- **Status**: Current scan status (Pending, Running, Completed, Failed)
- **Target**: The scanned target (IP, hostname, or CIDR)
- **Created**: When the scan was initiated
- **Progress**: Ports scanned vs total ports
- **Open Ports**: Number of open ports found
- **Vulnerabilities**: Total vulnerabilities detected

### Interactive Results Table
- **Host**: Target IP address
- **Port**: Port number scanned
- **Status**: Open or Closed
- **Service**: Detected service (HTTP, SSH, etc.)
- **Banner**: Service banner information
- **Response Time**: Connection response time
- **Vulnerabilities**: Number of vulnerabilities found per port

### Export Options

The scan detail page shows results in the browser. Full JSON, Markdown, CSV, and HTML reports are written by the CLI (`--format`). `GET /api/scan/{id}/export` is still a placeholder and does not render those reports.

- **Refresh**: the dashboard list reloads every 5 seconds

## 🚀 Starting Scans

### Via Web Interface
1. Click "🚀 Start New Scan" on the dashboard
2. Fill in the scan configuration form:
   - **Target**: IP address, hostname, or CIDR notation
   - **Scan Name**: Custom name for the scan
   - **Port Selection**: Top 100, Top 1000, or Custom ports
   - **Options**: Banner grabbing, vulnerability checking, etc.
3. Click "🎯 Launch Scan"

### Via API
```bash
# PowerShell example
Invoke-RestMethod -Uri "http://127.0.0.1:8080/api/scan" -Method Post -Headers @{ Authorization = "Bearer TOKEN" } -ContentType "application/json" -Body '{
    "target": "192.168.1.0/24",
    "top100": true,
    "top1000": false,
    "ping_sweep": true,
    "banners": true,
    "vuln_check": true,
    "fast_mode": false,
    "name": "Network Discovery",
    "description": "Full network scan with banners"
}'
```

## 🎨 Dashboard Features

### Real-time Updates
- Dashboard auto-refreshes every 5 seconds
- Live progress tracking for running scans
- Status updates in real-time

### Professional Interface
- Dark theme optimized for red team workflows
- Responsive design for desktop and mobile
- Intuitive navigation and controls

### Team Collaboration
- Multiple users can access the same dashboard
- Shared scan results and history
- Professional reporting for clients

## 🔧 Advanced Usage

### Multiple Concurrent Scans
- Start multiple scans simultaneously
- Monitor all scans from a single dashboard
- Each scan runs independently

### Scan Management
- View all scans in chronological order
- Stop running scans if needed
- Clean history of completed scans

### Integration Options
- RESTful API for automation
- JSON/CSV export for further analysis
- Compatible with existing security workflows

---

**Pro Tip**: Bookmark `http://127.0.0.1:<port>/dashboard` only after you have signed in. The port is whatever you passed to `--web-dashboard`.
