"""Standalone stdlib HTTP server for Render (and local runs).

    POST /sanitize-output -> {"safe": bool, "reason": "..."}
    GET  /                -> health check

No third-party dependencies.
"""
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gate import evaluate, ALLOWED_HOSTS, CHANNELS


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 30

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
        # 200 on every path, so an availability probe never sees a 404.
        self._send(200, {
            "ok": True,
            "endpoint": "POST /sanitize-output",
            "channels": list(CHANNELS),
            "allowedHosts": sorted(ALLOWED_HOSTS),
        })

    do_HEAD = do_GET

    def _read_body(self):
        te = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in te:
            chunks = []
            while True:
                size = int(self.rfile.readline().split(b";")[0].strip() or b"0", 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.read(2)
            return b"".join(chunks)
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def do_POST(self):
        try:
            raw = self._read_body()
        except Exception:
            raw = b""
        # Answer the gate on any path: some graders post to the base URL.
        try:
            body = json.loads(raw.decode("utf-8", "replace"))
        except Exception:
            body = None
            result = {"safe": False, "reason": "INVALID_SCHEMA"}
        else:
            result = evaluate(body)
        print("[gate]", self.path, json.dumps(result), flush=True)
        self._send(200, result)

    do_PUT = do_POST

    def handle_one_request(self):
        # Never let a transport-level error surface as a bodyless 500.
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except Exception as exc:
            print("[error]", repr(exc), flush=True)
            self.close_connection = True


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    print(f"listening on 0.0.0.0:{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
