"""Local, offline SOC dashboard. Run: python dashboard.py."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from soc_triage_assistant import process

ROOT = Path(__file__).resolve().parent
MAX_BODY = 2 * 1024 * 1024


def triage(alerts):
    if not isinstance(alerts, list) or not 1 <= len(alerts) <= 1000:
        raise ValueError("Provide a JSON array containing 1 to 1000 alerts.")
    results = []
    for row, alert in enumerate(alerts, 1):
        if not isinstance(alert, dict):
            raise ValueError(f"Row {row}: expected an alert object.")
        for key in ("id", "rule", "host", "severity"):
            if not isinstance(alert.get(key), str) or not alert[key].strip():
                raise ValueError(f"Row {row}: {key} must be nonempty text.")
        for key in ("asset_criticality", "technique", "user", "timestamp", "raw"):
            if key in alert and not isinstance(alert[key], str):
                raise ValueError(f"Row {row}: {key} must be text.")
        if alert["severity"].lower() not in ("critical", "high", "medium", "low"):
            raise ValueError(f"Row {row}: severity must be critical, high, medium or low.")
        entities = alert.get("entities", {})
        if not isinstance(entities, dict):
            raise ValueError(f"Row {row}: entities must be an object.")
        for key in ("ips", "domains", "hashes"):
            values = entities.get(key, [])
            if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
                raise ValueError(f"Row {row}: entities.{key} must be an array of text.")
        result = process(alert, None, online=False)
        result["source_row"] = row
        result["note_mode"] = "rule-based"
        results.append(result)
    return sorted(results, key=lambda r: r["score"], reverse=True)


class Handler(BaseHTTPRequestHandler):
    def respond(self, status, body, content_type="application/json"):
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        paths = {"/": ("index.html", "text/html"),
                 "/app.js": ("app.js", "text/javascript"),
                 "/style.css": ("style.css", "text/css")}
        if self.path in paths:
            name, mime = paths[self.path]
            self.respond(200, (ROOT / "web" / name).read_text(encoding="utf-8"), mime)
        elif self.path == "/api/sample":
            self.respond(200, (ROOT / "sample_alerts.json").read_text(encoding="utf-8"))
        else:
            self.respond(404, json.dumps({"error": "Not found"}))

    def do_POST(self):
        # Same-origin requests only; no CORS or remote response actions.
        if self.headers.get("Origin") not in (None, "http://127.0.0.1:8765", "http://localhost:8765"):
            self.respond(403, '{"error":"Origin rejected"}')
            return
        if self.path != "/api/triage":
            self.respond(404, '{"error":"Not found"}')
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_BODY:
                raise ValueError("Request must be between 1 byte and 2 MB.")
            alerts = json.loads(self.rfile.read(size))
            results = triage(alerts)
        except (ValueError, UnicodeError) as exc:
            self.respond(400, json.dumps({"error": str(exc)}))
            return
        self.respond(200, json.dumps({"results": results, "mode": "offline", "actions_executed": 0}))


if __name__ == "__main__":
    print("SOC workspace: http://127.0.0.1:8765 (Ctrl+C to stop)")
    ThreadingHTTPServer(("127.0.0.1", 8765), Handler).serve_forever()
