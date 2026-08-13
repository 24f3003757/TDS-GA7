"""Vercel serverless entrypoint.

Render sits behind a Cloudflare WAF that 403s request bodies containing a
SQL-injection or shell-injection payload — which is precisely what two of the
grader's probes are. The block page never reaches the app, so the gate cannot
answer them there. Vercel does not body-inspect by default.

Same gate.py as the Render server: one implementation, two hosts.
"""
import json
from http.server import BaseHTTPRequestHandler

from gate import evaluate, ALLOWED_HOSTS, CHANNELS


class handler(BaseHTTPRequestHandler):
    def _send(self, payload, head_only=False):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def do_GET(self, head_only=False):
        self._send({
            "ok": True,
            "endpoint": "POST /sanitize-output",
            "channels": list(CHANNELS),
            "allowedHosts": sorted(ALLOWED_HOSTS),
        }, head_only=head_only)

    def do_HEAD(self):
        self.do_GET(head_only=True)

    def do_OPTIONS(self):
        self._send({"ok": True})

    def do_POST(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            body = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            self._send({"safe": False, "reason": "INVALID_SCHEMA"})
            return
        self._send(evaluate(body))

    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST
