# Aegis SOC Workspace + Security CLI Tools

## Local SOC dashboard

### Security companion update (0.2.0)

The web app now includes scam/link heuristics, a FIRST CVSS **3.1 base**
calculator, normalized networking/sign-in CSV investigations with source
evidence, a platform coverage guide and a session-only safety checklist.
The Browser & devices tab downloads a separate Chrome/Edge blocker prototype
with three third-party domain rules and a pause switch. It must be installed
separately; see `browser_guard/README.md`. No other apps are monitored.

On Windows, double-click **Start Aegis.cmd**. It uses the Codex bundled Python
when available, otherwise your installed Python. Keep the terminal open and
visit http://127.0.0.1:8765. Stop with Ctrl+C. Restart after code updates and
refresh the browser. No Python installer or machine settings are changed.

For optional **local AI**, install Ollama and an appropriate local model yourself.
Set `AEGIS_OLLAMA_MODEL` to its installed model name before starting Aegis.
For example in PowerShell: `$env:AEGIS_OLLAMA_MODEL='your-installed-model'`.
Then run the launcher or `python dashboard.py`. No automatic download or cloud
API call is made by Aegis. Do not configure a cloud-backed local proxy.
Use Explain with local AI per finding, or explicitly opt into batch SOC drafts
(first 25 per import, sequentially). No model is bundled; failures are shown and
rule results remain available. AI drafts may be wrong and execute no actions.

Networking accepts the exact columns in `sample_network.csv`. Convert Splunk
or Cisco exports into that normalized schema first. It is not a native vendor
connector, time-window correlation engine or live network scan. Authentication
sequence is file order; timestamps must be assessed by an analyst.

See `PRODUCT_BLUEPRINT.md` for recovered requirements, implemented/planned
status, platform limitations, remaining integration work and primary references.
Run `python -m unittest test_dashboard test_security_tools -v` for backend checks.

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

Default dashboard analysis is **offline and rule-based**, even when API keys are set.
No indicators are visited or sent to intelligence services. No AI model is
called unless you explicitly request the new local-AI explanation feature.
Hosted LLM notes and intelligence remain features of the separate CLI scripts.
Priority is not a malicious/benign verdict.
All response actions are suggestions only; the app executes none.

This is a local development tool bound to loopback, without authentication
or production hosting support. Its separate browser extension is a limited
prototype. It does not implement mobile OS protection, billing, continuous
monitoring, or cross-platform endpoint protection.

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
