# Aegis 0.2.0 validation

Verified on Windows, 2026-10-30 (America/Chicago).

- 11 Python unittest cases pass: SOC priority/provenance, strict import handling,
  offline enforcement, HTTP routes and boundaries, CVSS known vectors and invalid
  metrics, scam rules/no URL visits, CSV evidence and port rules, optional AI
  request construction and extension rule structure.
- JavaScript syntax checks pass for app.js, security.js and popup.js.
- Automated Edge browser flows pass at 1440px and 390px widths: SOC demo/search,
  AI-not-configured message, scam checks, text-only result rendering, CVSS 9.8
  and scope-changed 10.0, CSV sample analysis, JSON report download, platform
  guide and extension ZIP download. No JS page errors or horizontal page overflow.
- Screenshots inspected for desktop CVSS and mobile device guide layouts.
- Separate disposable Edge extension profile: extension loads, enabled ruleset
  blocks a third-party doubleclick.net test request, pause allows it, resume
  blocks again. Domain resolved only to loopback for this test. Private-network
  checks were disabled only in that disposable test browser to distinguish
  declarative blocking from Edge's separate loopback-access restriction.
- Git whitespace check passes.

Not verified: actual local model generation (no model configured; API behavior
mocked), live threat reputation, public hosting, native iOS/Android/macOS/Linux
agents, native-app ads, Safari extension, broad real-world blocker efficacy,
production isolation/authentication or notification delivery. This is not a
security effectiveness certification. Coverage and gaps are in PRODUCT_BLUEPRINT.md.
