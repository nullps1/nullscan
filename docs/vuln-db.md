# CVE database

`vuln_db.json` is the offline database `nullscan --vuln-check` matches against service banners. The report prints its `last_updated` value as the CVE database date.

The file has two kinds of rows:

- Hand-written banner patterns. These stay in the file when it is refreshed.
- Generated rows, marked `"source": "cisa-kev+nvd"`. A refresh replaces this section.

A match means the banner names a product that NVD lists as vulnerable for that CVE. The report still says the service may be affected and needs confirming. This is not a proof, and it is not a complete vulnerability feed.

## Sources

Generated rows come from two public sources:

1. [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json). `last_updated` is the catalog's `dateReleased` date.
2. [NVD CVE API 2.0](https://services.nvd.nist.gov/rest/json/cves/2.0). Each query uses `virtualMatchString` for that product's vulnerable CPE, then keeps the CVSS score, published date, and English description. A CPE matches only when the product component ends at the next separator, so `oracle:mysql` does not include `oracle:mysql_shell`. NVD also files some MySQL Shell, Connector, and Workbench advisories under `oracle:mysql`. Those descriptions are dropped, so a MySQL server banner does not inherit them. CISA KEV entries for the same products are included even when they fall outside the newest handful of NVD rows.

NVD allows a few requests at a time without an API key. The refresh script waits between calls. Set `NVD_API_KEY` if you have one.

## Refresh

From the repository root, with network access:

```bash
python3 scripts/refresh-vuln-db.py
```

That rewrites `vuln_db.json` in place. Commit the file together with any report that should show the new date. `src/vuln/mod.rs` reads `last_updated` from the file that was compiled into the binary, so a rebuilt `nullscan` prints that date even when an older scan export says `not recorded`.

To print a different date on one report, set it in the TOML or pass the flag:

```toml
[report]
cve_db_date = "2026-10-30"
```

```bash
nullscan report --config client.toml --input scan.json --cve-db-date 2026-10-30 --output exposure.pdf
```

The value has to be a real calendar date. A scan export that recorded `vuln_db_updated` is used when the TOML and the flag leave the date blank. `not recorded` and `not run` are ignored, and the bundled date is printed instead.
