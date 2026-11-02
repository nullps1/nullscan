# 📋 Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- The web dashboard UI and API now require a bearer token (`--web-token` or `NULLSCAN_WEB_TOKEN`, otherwise generated and printed at startup). Unauthenticated API calls return 401. The UI login page stores the token in an HttpOnly cookie.
- Binding the dashboard to anything other than loopback prints a startup warning. The default bind remains `127.0.0.1`.
- Removed permissive CORS. The embedded UI is same-origin; API clients send the bearer token directly.

### Changed
- Project identity now points at github.com/nullps1/nullscan, Noah "Null" Weeks, and noah@weeksitsolutions.com. Removed the old Nullgrimoire URLs, emails, and Buy Me a Coffee link.
- Updated axum 0.7 to 0.8 (path params use `{id}`), tower 0.5, tower-http 0.7, dashmap 6, env_logger 0.11, indicatif 0.18, colored 3, console 0.16, and the rest of the direct dependencies.
- Release workflow publishes assets with the GitHub CLI instead of the archived `actions/create-release` and `actions/upload-release-asset` actions. Checksums name the released asset file.
- `--format` help text lists `html`.

### Added
- Localhost unit tests for the scanner, banner probes, `vuln_db.json` matching, and json/markdown/csv/html export.
- CI lint job: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and `cargo audit`.
- `docs/development.md`.

## [1.6.0] - 2025-07-14

### Added
- Version bump to 1.6.0
- Updated all version references across the codebase
- Enhanced project documentation

### Changed
- Updated version strings in all modules
- Refreshed sample outputs and documentation

## [1.5.0] - 2025-07-14log

All notable changes to NullScan will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.5.0] - 2025-07-14

### ✨ Added

- **Professional Content Creator Kit** - Complete toolkit for technical YouTubers and bloggers
  - Automated benchmark comparison scripts for Windows and Linux/macOS
  - Professional sample outputs for B-roll footage
  - Safe demo targets list for public demonstrations
  - Comprehensive content creator guide with performance statistics
- **Enhanced Demo Scripts** - Completely rewritten professional demonstration suite
  - 6 comprehensive feature demonstrations per platform
  - Cross-platform PowerShell and Bash scripts with identical functionality
  - Professional timing measurements and performance showcases
  - Interactive examples highlighting LUDICROUS SPEED mode

### ⚡ Improved

- **Fast Mode Optimization** - Timeout increased from 50ms to 95ms for improved reliability
  - Better balance between speed and accuracy
  - Reduced false negatives in fast scanning mode
  - Maintained LUDICROUS SPEED performance with enhanced stability
- **Documentation Overhaul** - Professional content creator ready materials
  - Enhanced examples README with content creator focus
  - Professional positioning for technical demonstrations
  - Added performance statistics and talking points

### 🔧 Changed

- Updated all version references across codebase and documentation
- Enhanced demo scripts with professional output formatting
- Improved content creator resources with industry-standard benchmarking

### 📚 Documentation

- Added comprehensive content creator guide
- Enhanced examples with professional demonstration capabilities
- Improved cross-platform compatibility documentation

---

## [1.0.0] - 2025-07-13

### ✨ Initial Release Features

- **Fast Asynchronous Scanning** - Tokio-based concurrent TCP port scanning
- **Network Range Support** - CIDR notation scanning (e.g., `192.168.1.0/24`)
- **Parallel Host Scanning** - Concurrent multi-host scanning with `--max-hosts`
- **Ping Sweep Optimization** - Pre-scan host discovery for large networks
- **Smart Port Selection** - Top 100/1000 common ports or custom ranges
- **Advanced Service Detection** - Protocol-specific probing with confidence scoring
- **Enhanced Banner Grabbing** - Support for SSH, TLS, HTTP, databases, and more
- **Multiple Export Formats** - JSON, Markdown, CSV, and HTML output options
- **Vulnerability Assessment** - Offline CVE database with 44+ vulnerability patterns
- **Rich CLI Interface** - Progress bars, colored output, and verbose logging
- **Cross-Platform Support** - Windows, macOS, and Linux compatibility

### 🛡️ Security Features

- Offline vulnerability database with CVSS scoring
- Real-time CVE detection and classification
- Pattern-based vulnerability matching
- Severity classification (Critical, High, Medium, Low, Info)

### 🚀 Performance Features

- **LUDICROUS SPEED Mode** - Auto-optimized fast scanning with CPU detection
- **115x Faster Network Scanning** - Optimized ping sweep for large ranges
- **Intelligent Concurrency** - Automatic CPU core detection and optimization
- **Memory Efficient** - Optimized for large-scale network scanning

### 🎨 User Experience

- Professional HTML report generation
- Interactive progress indicators
- Colored output with emoji indicators
- Comprehensive help documentation
- Cross-platform demo scripts

---

*For detailed performance benchmarks and technical deep-dives, see the [docs/](docs/) directory.*
