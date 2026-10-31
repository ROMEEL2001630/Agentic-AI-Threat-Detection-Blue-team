# Aegis SOC Workspace + Security CLI Tools

## Local SOC dashboard

Run `python dashboard.py` with Python 3.10+ and open http://127.0.0.1:8765.
The dashboard requires only the Python standard library. Load the six demo
alerts or import a JSON array matching `sample_alerts.json` (maximum 2 MB,
1000 alerts). Required text fields: `id`, `rule`, `host`, `severity`.
Severity must be critical, high, medium or low. Optional entities contain
arrays of strings named `ips`, `domains`, and `hashes`.

The responsive investigation workspace ranks alerts using the existing
explainable priority engine, filters by priority or search, shows the
original source row and record, and exports a JSON report. Source rows are
one-based array positions before sorting. Imports and results live in memory;
export before closing. There is no database or case persistence yet.

Dashboard analysis is **offline and rule-based**, even when API keys are set.
No indicators are visited or sent to intelligence services. No AI model is
called by the dashboard. Optional LLM notes and intelligence remain features
of the separate CLI scripts. Priority is not a malicious/benign verdict.
All response actions are suggestions only; the app executes none.

This is a local development tool bound to loopback, without authentication
or production hosting support. It does not implement browser/ad blocking,
mobile OS protection, billing, or cross-platform endpoint protection.

Validation: `python -m unittest test_dashboard -v` and `node --check web/app.js`.

## IOC Enrichment CLI (SOAR-ready)

Auto-detects an indicator's type (IP / domain / URL / hash), queries free
threat-intel sources, and returns an aggregated **risk verdict** as JSON or
Markdown. Built to slot into a **Shuffle** (free, open-source SOAR) workflow:
feed it one IOC, branch on the JSON it returns.

This covers the "security automation with Python" keyword cleanly and shows you
understand how enrichment fits into an automated SOC pipeline.

## Sources (free tiers)
- **AbuseIPDB** — IP reputation (`ABUSEIPDB_API_KEY`)
- **VirusTotal** — IP / domain / hash / URL (`VT_API_KEY`)
- **AlienVault OTX** — pulses across all types (`OTX_API_KEY`)

Runs offline without keys (returns structure + notes) so it's safe to demo.

## Usage
```bash
# Single IOC -> JSON (Shuffle-friendly)
python ioc_enrich.py 203.0.113.77

# Batch a file -> Markdown table
python ioc_enrich.py --file iocs.txt

# Explicit JSON to a file
python ioc_enrich.py evil.example.com --json --out result.json
```

## Aggregated verdict
The tool takes the strongest signal across sources (AbuseIPDB confidence, VT
malicious count, OTX pulse count) → 0-100 → `clean/unknown | suspicious |
malicious`. Logic is explainable and in code.

## Shuffle integration (free SOAR)
1. Install Shuffle (Docker) — https://shuffler.io.
2. Add a trigger (webhook or SIEM alert) that provides an IOC.
3. Run this script in a "Shell"/"Python" node with the IOC as `argv`.
4. Branch on `.verdict`: `malicious` → create ticket / block; else → close.

## Skills demonstrated
Security automation (Python) · threat-intel enrichment · IOC typing &
normalization · SOAR workflow design · API integration.

## Resume line (truthful)
> Built a Python IOC-enrichment tool that auto-detects indicator types and
> aggregates AbuseIPDB, VirusTotal, and OTX reputation into a single risk
> verdict, designed to plug into a Shuffle SOAR workflow.

*Author: Romeel Bhavsar*
