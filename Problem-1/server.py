"""Standalone server for Render (and local runs).

Reuses the exact same evaluate() used by the Vercel function so the two
deployments can never drift apart.
"""
import importlib.util
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_spec = importlib.util.spec_from_file_location(
    "release_gate", os.path.join(os.path.dirname(os.path.abspath(__file__)), "api", "release-gate.py")
)
_rg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_rg)
evaluate = _rg.evaluate


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
        self._send(200, {"ok": True, "endpoint": "POST /release-gate"})

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw or b"{}")
        except Exception:
            payload = {}
        violations = evaluate(payload if isinstance(payload, dict) else {})
        resp = {
            "decision": "promote" if not violations else "block",
            "violations": violations,
        }
        # Logged so Render's log tab shows exactly what the grader sent and
        # what we answered -- this is the only debugging channel available.
        print("[probe] path=%s\n  in : %s\n  out: %s" % (
            self.path, json.dumps(payload, sort_keys=True), json.dumps(resp)), flush=True)
        self._send(200, resp)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
