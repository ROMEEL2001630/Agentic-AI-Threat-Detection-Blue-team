# Aegis: personal security companion and expert investigation workspace

## Recovered scope and repository status

Reviewed the earlier chats “Review Threat Detection Repository” and
“AI Cybersecurity Project Ideas” plus the current request. They describe
consumer scam/URL checks, supported ad/tracker blocking, device safety,
Splunk-style investigations, DNS/HTTPS/authentication logs, source evidence,
AI explanations, CVSS/vulnerability prioritization, analyst verdicts and reports.
The earlier primary application was said to be in ROMEEL2001630/RBHAVSAR;
GitHub reported that repository empty during this review. Its unpushed cloud
workspace and prior attachments have not been recovered. The working code here
extends Agentic-AI-Threat-Detection-Blue-team. Prior claims of an existing
prototype or passing tests are not evidence that those files exist here.

## Product direction

Serve individuals who need to understand suspicious messages and device
security, and small IT/security teams who need evidence-based investigations.
One workspace should combine those jobs with clear telemetry coverage. Public
demand and willingness to pay remain hypotheses: test with users before
claiming validation. No billing is implemented.

The long-term aim is a consent-based security companion, not covert surveillance.
Devices, accounts, browsers and network sources must be explicitly connected.
Show last event, permission scope, source health, offline status and disconnect
controls. Never interpret “no data” as “secure.”

## Feature inventory (0.2.0)

| Feature | Verified implementation / gap |
|---|---|
| SOC investigations | JSON import, existing deterministic priorities and ATT&CK mappings, source records, search, filters, JSON export |
| Consumer scam / link checks | Offline pattern evidence; no URL visit, redirect resolution, reputation or safety guarantee |
| CVSS | FIRST CVSS 3.1 base vector validation/calculation, severity and JSON export; no CVSS 4.0 or vulnerability scan |
| Networking / Splunk | Normalized CSV upload; repeated auth failures and success in file order, many ports, long DNS labels; source-row evidence and JSON reports |
| Cisco | Normalized exported events only; no Cisco API, configuration parser or router control |
| AI diagnosis | Optional local Ollama explanation per finding or selected SOC alert; opt-in batch for first 25 imported SOC alerts; configured local model required |
| Ad / tracker blocking | Separate desktop Chrome/Edge MV3 extension with 3 third-party domain rules and pause/resume; not a maintained comprehensive filter |
| Cross-platform web UI | Responsive layout tested at desktop and phone widths; current loopback host is accessible only on the server machine |
| Device safety | Platform-specific guidance and session-only self-reported checklist; no inspection of OS settings |
| Cases / TP-FP labels | Planned: durable cases, analyst verdicts, notes, history and deletion |
| Live alerts / surveillance | Not implemented: no continuous ingestion, installed sensor, background scheduler, push or email notifications |
| Device / app coverage | Not implemented: no antivirus, EDR, ransomware protection, app-content inspection or automatic containment |
| Integrations | Planned: authorized read-only connectors for Splunk, Cisco/security gateways and identity providers |
| Reports | JSON implemented; CSV/PDF investigations still planned |
| Hosting / accounts | Local prototype; secure hosted multi-user product and mobile access not implemented |

## Platform plan

| Platform | Current | Required for continuous protection |
|---|---|---|
| Windows | Local server/web tools; separate browser extension | Signed least-privilege event agent; OS event/Defender integration; explicit install/uninstall |
| macOS | Python web tools (OS execution not tested); desktop browser extension | Signed/notarized agent, approved Endpoint Security / Network Extension capabilities as applicable |
| Linux | Python web tools (OS execution not tested); desktop browser extension | Packaged least-privilege agent, journal/audit/network connectors; distribution-specific testing |
| iOS / iPadOS | Responsive interface; secure hosting pending | Native Safari content-blocker target; appropriate Network Extension entitlement/distribution; sandbox restrictions remain |
| Android | Responsive interface; secure hosting pending | Native user-approved VpnService/DNS component; only one VPN active at a time; app sandbox restrictions remain |

A browser page cannot read arbitrary processes, files, notifications, or other
apps' encrypted content. DNS filtering can block domains but cannot reliably
remove same-domain sponsored posts. No claim of removing Instagram's in-app ads.
Filtering can conflict with another VPN, break sites, or miss traffic; expose
status and bypass/disconnect controls. Do not install a root certificate or
intercept encrypted traffic as an invisible prerequisite.

## AI and alert architecture

Sensors/connectors -> authenticated ingestion -> normalization -> evidence IDs
-> deterministic detections -> optional AI explanation -> analyst review
-> user-configured notification delivery. Separate raw evidence, rule findings,
AI hypotheses and confirmed analyst verdicts. Keep rule alerts available if the
model fails. Evaluate false positives/negatives on held-out labeled data before
selling predictive accuracy. CVSS is vulnerability severity, not alert confidence.

Current AI calls go only to fixed loopback Ollama /api/chat; redirects and proxy
environment variables are disabled. Explicitly configured :cloud models are
rejected. Only install local models; a user-managed local proxy/service remains
outside Aegis's control. There are no AI tools or response execution paths.
Prompt-injection instructions in evidence are treated as untrusted, but AI
output can still be manipulated or wrong; it never replaces raw records.

Do not promise “all alerts in any case.” Coverage depends on sensors,
permissions, encrypted traffic, event delivery, device availability and detection
quality. A model cannot detect activity that was never collected.

## Next release gates

1. Durable cases and verdicts, explicit retention/deletion, sanitized sample sets.
2. Real read-only ingestion for one authorized source, health/lag indicators and
   deduplication. Evaluate results before enabling notifications.
3. Authentication/MFA, authorization, encryption, tenant isolation, audit logging,
   secure secrets and upload controls before accepting public customer data.
4. Hosted responsive app with HTTPS, then one signed device platform pilot;
   build native iOS/Android components as separate tested projects.
5. Maintained, licensed filter feeds with update integrity, allowlisting,
   regression tests and browser-store distribution. Current three rules are a prototype.
6. Consent-based alert delivery with user-selected channels, quiet hours,
   severity thresholds, delivery retries and clear sensor-offline alerts.
7. CVE/KEV/EPSS enrichment with source timestamps and asset matching; CVSS 4.0;
   read-only network diagnosis and connector-specific runbooks.

## User validation

Pilot with individuals and small IT teams using sanitized data. Measure whether
users can identify the source of a warning, choose a safe next action, and
understand coverage. Track useful findings, false alarms, time saved and repeat
use. Broad feature count alone is not evidence of customer demand.

## Primary references

- FIRST CVSS 3.1: https://www.first.org/cvss/v3.1/specification-document
- Chrome declarative blocking: https://developer.chrome.com/docs/extensions/reference/api/declarativeNetRequest
- Apple content blocking: https://developer.apple.com/documentation/safariservices/creating-a-content-blocker
- Android VPN permissions: https://developer.android.com/reference/android/net/VpnService
- Ollama local chat API: https://docs.ollama.com/api/chat
- CISA everyday security: https://www.cisa.gov/secure-our-world
