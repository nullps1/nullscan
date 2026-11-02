#!/usr/bin/env python3
"""Refresh the generated section of vuln_db.json from public CVE sources.

The hand-written patterns already in vuln_db.json are kept. Patterns this
script wrote (``source`` == ``cisa-kev+nvd``) are replaced on each run.

Sources, in order:

1. CISA Known Exploited Vulnerabilities catalog
   https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
2. NVD CVE API 2.0, limited to the vulnerable CPE for each product
   (``virtualMatchString``), for the English description, published date, and CVSS score
   https://services.nvd.nist.gov/rest/json/cves/2.0

NVD allows a small number of requests without an API key. This script waits
between calls. Set NVD_API_KEY to go faster. The date written to
``last_updated`` is the CISA catalog release date (YYYY-MM-DD).

Usage:
    python3 scripts/refresh-vuln-db.py
    python3 scripts/refresh-vuln-db.py --output vuln_db.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GENERATED_SOURCE = "cisa-kev+nvd"
# Newest records only. Older hand-written rows stay in the file.
PUBLISHED_FLOOR = "2024-01-01"
PER_PRODUCT = 6
USER_AGENT = "nullscan-vuln-refresh/1.0 (+https://github.com/nullps1/nullscan)"

# cpe: NVD vendor:product prefix. virtualMatchString is this prefix plus ":*:*:*:*:*:*:*:*".
# A row is kept only when NVD marks that CPE vulnerable, so a passing mention is not enough.
# pattern / service_type: vuln_db.json fields. Several CPEs may share one pattern.
PRODUCTS = [
    {
        "name": "OpenSSH",
        "cpe": "cpe:2.3:a:openbsd:openssh",
        "pattern": "contains:openssh",
        "service_type": "SSH",
    },
    {
        "name": "nginx",
        "cpe": "cpe:2.3:a:f5:nginx",
        "pattern": "contains:nginx",
        "service_type": "HTTP",
    },
    {
        "name": "nginx",
        "cpe": "cpe:2.3:a:nginx:nginx",
        "pattern": "contains:nginx",
        "service_type": "HTTP",
    },
    {
        "name": "Apache HTTP Server",
        "cpe": "cpe:2.3:a:apache:http_server",
        "pattern": "contains:apache/",
        "service_type": "HTTP",
    },
    {
        "name": "OpenSSL",
        "cpe": "cpe:2.3:a:openssl:openssl",
        "pattern": "contains:openssl",
        "service_type": "TLS",
    },
    {
        "name": "PHP",
        "cpe": "cpe:2.3:a:php:php",
        "pattern": "contains:php/",
        "service_type": "HTTP",
    },
    {
        "name": "MySQL",
        "cpe": "cpe:2.3:a:oracle:mysql",
        "pattern": "contains:mysql",
        "service_type": "Database",
    },
    {
        "name": "PostgreSQL",
        "cpe": "cpe:2.3:a:postgresql:postgresql",
        "pattern": "contains:postgresql",
        "service_type": "Database",
    },
    {
        "name": "Apache Tomcat",
        "cpe": "cpe:2.3:a:apache:tomcat",
        "pattern": "contains:tomcat",
        "service_type": "HTTP",
    },
    {
        "name": "MongoDB",
        "cpe": "cpe:2.3:a:mongodb:mongodb",
        "pattern": "contains:mongodb",
        "service_type": "Database",
    },
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        default="vuln_db.json",
        help="Path to vuln_db.json (default: ./vuln_db.json)",
    )
    parser.add_argument(
        "--sleep",
        type=float,
        default=6.0,
        help="Seconds to wait between NVD requests when NVD_API_KEY is unset",
    )
    args = parser.parse_args()
    output = Path(args.output)
    database = json.loads(output.read_text(encoding="utf-8"))
    baseline = [row for row in database["patterns"] if row.get("source") != GENERATED_SOURCE]

    print("Downloading CISA KEV catalog...")
    kev = fetch_json(KEV_URL)
    catalog_version = str(kev.get("catalogVersion", ""))
    released = str(kev.get("dateReleased", ""))[:10]
    if len(released) != 10:
        sys.exit(f"CISA catalog dateReleased was not a date: {kev.get('dateReleased')!r}")
    print(f"CISA KEV {catalog_version} released {released} ({kev.get('count')} entries)")

    selected: dict[str, dict] = {}
    for product in PRODUCTS:
        print(f"Querying NVD CPE {product['cpe']} ({product['name']})...")
        payload = nvd_cpe(product["cpe"], args.sleep)
        added = 0
        for record in newest_matches(payload, product["cpe"]):
            selected[record["cve"]] = {
                **record,
                "pattern": product["pattern"],
                "service_type": product["service_type"],
            }
            added += 1
        print(f"  matched {added} published on or after {PUBLISHED_FLOOR}")

    print("Adding CISA KEV entries whose NVD CPE is one of those products...")
    # A pattern can have more than one CPE prefix (nginx). Keep every prefix.
    prefixes: dict[str, list[str]] = {}
    for product in PRODUCTS:
        prefixes.setdefault(product["pattern"], []).append(product["cpe"])
    for entry in kev.get("vulnerabilities", []):
        route = kev_route(entry)
        if route is None:
            continue
        cve_id = entry["cveID"]
        if not cve_id.startswith(("CVE-2024-", "CVE-2025-", "CVE-2026-", "CVE-2027-")):
            continue
        pattern, service_type = route
        if cve_id in selected:
            selected[cve_id]["from_kev"] = True
            continue
        print(f"  NVD lookup {cve_id} ({entry.get('vendorProject')} / {entry.get('product')})")
        cve = nvd_cve_raw(cve_id, args.sleep)
        if cve is None:
            continue
        allowed = prefixes.get(pattern, [])
        if not any(cpe_is_vulnerable(cve, prefix) for prefix in allowed):
            print(f"    skipped {cve_id}: NVD CPE is not {pattern}")
            continue
        record = record_from_nvd(cve)
        if record is None or record["published"] < PUBLISHED_FLOOR:
            continue
        selected[cve_id] = {
            **record,
            "pattern": pattern,
            "service_type": service_type,
            "from_kev": True,
        }
    selected = cap_per_pattern(selected)

    generated = group_patterns(selected)
    database["patterns"] = baseline + generated
    database["version"] = "2.1.0"
    database["last_updated"] = released
    database["source"] = (
        f"Hand-written banner patterns plus records refreshed from the CISA Known "
        f"Exploited Vulnerabilities catalog {catalog_version} ({released}) and NVD CVE API 2.0"
    )
    database["source_url"] = KEV_URL
    database["nvd_source_url"] = NVD_URL
    database["description"] = (
        "Vulnerability database for nullscan. Hand-written banner patterns are kept. "
        f"Records marked {GENERATED_SOURCE} were refreshed from CISA KEV {catalog_version} "
        f"({released}) with descriptions and CVSS scores from NVD. A banner match means the "
        "service may be affected and needs confirming."
    )
    database["total_patterns"] = len(database["patterns"])
    database["coverage"] = dict(Counter(row["service_type"] for row in database["patterns"]))
    output.write_text(json.dumps(database, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    published = [row["published"] for row in selected.values()]
    newest = max(published) if published else "none"
    print(
        f"Wrote {output} with {len(baseline)} hand-written patterns, "
        f"{len(generated)} generated patterns, {len(selected)} current CVEs. "
        f"Newest published date: {newest}. Database date: {released}."
    )
    return 0


def kev_route(entry: dict) -> tuple[str, str] | None:
    vendor = str(entry.get("vendorProject", "")).lower()
    product = str(entry.get("product", "")).lower()
    blob = f"{vendor} {product}"
    if "openssh" in blob:
        return ("contains:openssh", "SSH")
    if "nginx" in blob:
        return ("contains:nginx", "HTTP")
    if "openssl" in blob and "python" not in blob:
        return ("contains:openssl", "TLS")
    if "apache" in blob and "http server" in blob:
        return ("contains:apache/", "HTTP")
    if "tomcat" in blob:
        return ("contains:tomcat", "HTTP")
    if "mongodb" in blob:
        return ("contains:mongodb", "Database")
    if "mysql" in blob and "mysql connector" not in blob:
        return ("contains:mysql", "Database")
    if "postgresql" in blob:
        return ("contains:postgresql", "Database")
    if product.strip() == "php" and "mailer" not in blob:
        return ("contains:php/", "HTTP")
    if "proftpd" in blob:
        return ("contains:proftpd", "FTP")
    return None


def newest_matches(payload: dict, cpe_prefix: str) -> list[dict]:
    rows = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        if not cpe_is_vulnerable(cve, cpe_prefix):
            continue
        record = record_from_nvd(cve)
        if record is None or record["published"] < PUBLISHED_FLOOR:
            continue
        rows.append(record)
    rows.sort(key=lambda row: row["published"], reverse=True)
    return rows


def cap_per_pattern(selected: dict[str, dict]) -> dict[str, dict]:
    """Keep the newest rows for each banner pattern, and every CISA KEV row."""
    by_pattern: dict[str, list[dict]] = {}
    for row in selected.values():
        by_pattern.setdefault(row["pattern"], []).append(row)
    kept: dict[str, dict] = {}
    for rows in by_pattern.values():
        newest = sorted(rows, key=lambda row: row["published"], reverse=True)[:PER_PRODUCT]
        wanted = {row["cve"] for row in newest}
        wanted.update(row["cve"] for row in rows if row["from_kev"])
        for row in rows:
            if row["cve"] in wanted:
                kept[row["cve"]] = row
    return kept


def cpe_is_vulnerable(cve: dict, prefix: str) -> bool:
    def walk(node: dict) -> bool:
        for match in node.get("cpeMatch") or []:
            criteria = str(match.get("criteria") or "")
            if criteria.startswith(prefix) and match.get("vulnerable", True):
                return True
        return any(walk(child) for child in node.get("children") or [])

    for config in cve.get("configurations") or []:
        for node in config.get("nodes") or []:
            if walk(node):
                return True
    return False


def record_from_nvd(cve: dict) -> dict | None:
    cve_id = cve.get("id") or ""
    if not cve_id.startswith("CVE-"):
        return None
    description = english_description(cve)
    scored = cvss(cve)
    if scored is None:
        return None
    score, _nvd_severity = scored
    return {
        "cve": cve_id,
        "description": clip(description),
        "severity": severity_band(score),
        "cvss_score": score,
        "published": str(cve.get("published", ""))[:10],
        "references": [f"https://nvd.nist.gov/vuln/detail/{cve_id}"],
        "from_kev": False,
    }


def group_patterns(selected: dict[str, dict]) -> list[dict]:
    grouped: dict[tuple[str, str], list[dict]] = {}
    for row in selected.values():
        grouped.setdefault((row["pattern"], row["service_type"]), []).append(row)
    patterns = []
    for (pattern, service_type), rows in grouped.items():
        rows.sort(key=lambda row: row["published"], reverse=True)
        vulnerabilities = []
        for row in rows:
            references = list(row["references"])
            if row["from_kev"]:
                references.append("https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
            vulnerabilities.append(
                {
                    "cve": row["cve"],
                    "description": row["description"],
                    "severity": row["severity"],
                    "cvss_score": row["cvss_score"],
                    "published": row["published"],
                    "references": references,
                }
            )
        patterns.append(
            {
                "pattern": pattern,
                "service_type": service_type,
                "source": GENERATED_SOURCE,
                "vulnerabilities": vulnerabilities,
            }
        )
    patterns.sort(key=lambda row: row["pattern"])
    return patterns


def english_description(cve: dict) -> str:
    for item in cve.get("descriptions") or []:
        if item.get("lang") == "en" and item.get("value"):
            return " ".join(str(item["value"]).split())
    return ""


def cvss(cve: dict) -> tuple[float, str] | None:
    metrics = cve.get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        for metric in metrics.get(key) or []:
            data = metric.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                severity = str(data.get("baseSeverity") or "")
                return (float(score), severity)
    return None


def severity_band(score: float) -> str:
    """Same bands the exposure report uses for a CVSS score."""
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def clip(text: str, limit: int = 500) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def nvd_cpe(prefix: str, pause: float) -> dict:
    """Last page of NVD results for one vulnerable CPE. NVD returns oldest first."""
    virtual = prefix + ":*:*:*:*:*:*:*:*"
    probe = nvd_get({"virtualMatchString": virtual, "resultsPerPage": "1"}, pause)
    total = int(probe.get("totalResults") or 0)
    if total <= 0:
        return {"vulnerabilities": []}
    window = 60
    start = max(0, total - window)
    if start == 0:
        return nvd_get(
            {"virtualMatchString": virtual, "resultsPerPage": str(max(total, 1))},
            pause,
        )
    return nvd_get(
        {
            "virtualMatchString": virtual,
            "resultsPerPage": str(window),
            "startIndex": str(start),
        },
        pause,
    )


def nvd_cve_raw(cve_id: str, pause: float) -> dict | None:
    payload = nvd_get({"cveId": cve_id}, pause)
    items = payload.get("vulnerabilities") or []
    if not items:
        return None
    return items[0].get("cve") or None


def nvd_get(params: dict[str, str], pause: float) -> dict:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    api_key = os.environ.get("NVD_API_KEY", "").strip()
    if api_key:
        headers["apiKey"] = api_key
    else:
        time.sleep(pause)
    url = NVD_URL + "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers=headers)
    for attempt in range(4):
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if error.code in {429, 503} and attempt < 3:
                time.sleep(pause * (attempt + 2))
                continue
            detail = error.read().decode("utf-8", errors="replace")[:300]
            sys.exit(f"NVD request failed ({error.code}) for {url}: {detail}")
        except urllib.error.URLError as error:
            if attempt < 3:
                time.sleep(pause)
                continue
            sys.exit(f"NVD request failed for {url}: {error}")
    sys.exit(f"NVD request failed for {url}")


def fetch_json(url: str) -> dict:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


if __name__ == "__main__":
    raise SystemExit(main())
