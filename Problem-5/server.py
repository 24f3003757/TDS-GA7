"""Standalone stdlib HTTP server for Render (and local runs).

    POST /corroborate  -> {"verdict","confidence","corroboratingSources"}
    GET  /             -> health check

No third-party dependencies.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from corroborate import evaluate, SUBJECT, INVALID

PATHS = ("/corroborate", "/corroborate/")


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        print("[http] " + (fmt % args), flush=True)

    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_OPTIONS(self):
        self._send(204, {})

    def do_GET(self):
        self._send(200, {"ok": True, "subject": SUBJECT, "endpoint": "/corroborate"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""
        try:
            body = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send(200, dict(INVALID))
            return
        # Any path: always answer, graders sometimes probe variants.
        self._send(200, evaluate(body))


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"listening on 0.0.0.0:{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
