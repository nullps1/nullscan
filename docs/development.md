# Development Guide

How to build, test, and change NullScan. For contribution process and review expectations, see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Authorized use only

Development scans in this repository must target localhost (`127.0.0.1`). Do not point tests or examples at hosts you do not own.

## Setup

- Rust stable, 1.85 or newer ([rustup](https://rustup.rs/))
- Git

```bash
git clone https://github.com/nullps1/nullscan.git
cd nullscan
cargo build
```

The binary is `target/debug/nullscan`. A release build is `cargo build --release`.

## Checks

CI runs these on Ubuntu, and the test job also runs `cargo test` on Windows and macOS:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
cargo audit
```

`cargo audit` needs the `cargo-audit` crate (`cargo install cargo-audit --locked`). Install `rustfmt` and `clippy` with `rustup component add rustfmt clippy`.

Tests bind `TcpListener`s on `127.0.0.1` only. They cover port open/closed detection, fast mode, SSH and HTTP banner probes, `vuln_db.json` matching, JSON/Markdown/CSV/HTML export, and dashboard bearer-token authentication.

## Layout

```text
src/
├── main.rs        # CLI
├── scanner/       # TCP connect scan and ping sweep
├── banner/        # Protocol probes
├── vuln/          # Offline vuln_db.json matcher
├── report/        # Client PDF (nullscan report)
├── export/        # json, markdown, csv, html
├── presets/       # Top 100 / top 1000 ports
└── web/           # axum dashboard, API, and token auth
```

## Web dashboard while developing

There is no default port.

```bash
cargo run -- --web-dashboard 8080
```

The process prints a bearer token. Open `http://127.0.0.1:8080/login` and paste it, or call the API with `Authorization: Bearer <token>`. Set `--web-token` or `NULLSCAN_WEB_TOKEN` to reuse a token. The default bind is `127.0.0.1`; any other address prints a warning.

## CVE database

`vuln_db.json` mixes hand-written banner patterns with a generated section from the CISA Known Exploited Vulnerabilities catalog and NVD. Refresh it with `python3 scripts/refresh-vuln-db.py`. Details are in [vuln-db.md](vuln-db.md).

## Contact

Noah "Null" Weeks — nullps1 | systems builder — [noah@weeksitsolutions.com](mailto:noah@weeksitsolutions.com)
