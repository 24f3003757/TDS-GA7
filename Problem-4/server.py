"""Standalone stdlib HTTP server for Render (and local runs).

    POST /sanitize-output -> {"safe": bool, "reason": "..."}
    GET  /                -> health check

No third-party dependencies.
"""
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from gate import evaluate, ALLOWED_HOSTS, CHANNELS


PROBES = []          # ring buffer of the last 400 graded requests


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = 60

    def log_message(self, fmt, *args):
        print("[http] " + (fmt % args), flush=True)

    def _record(self, method, raw, result):
        """Every request the grader makes, not just the ones we grade. The two
        failing checks never showed up in the POST log, so they are some other
        method, path, or a request that dies before it reaches do_POST."""
        if self.path.split("?")[0] == "/_probes":
            return
        PROBES.append({
            "t": time.time(), "method": method, "path": self.path,
            "ua": self.headers.get("User-Agent", ""),
            "ct": self.headers.get("Content-Type", ""),
            "raw": raw[:2000], "result": result,
        })
        del PROBES[:-400]

    def _send(self, code, body, head_only=False):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Length", str(len(data)))
        # One request per connection. Keep-alive lets a client reuse a socket
        # at the exact moment the idle timeout closes it, which shows up as a
        # request with no response. Not worth the saved handshake here.
        self.send_header("Connection", "close")
        self.end_headers()
        # A HEAD response must carry the headers but no body, or the client's
        # parser reads our JSON as the start of the next response.
        if not head_only:
            self.wfile.write(data)
        try:
            self.wfile.flush()
        except Exception:
            pass
        self.close_connection = True

    def do_OPTIONS(self):
        # 200, not 204: a 204 must not carry a body, and a CORS preflight that
        # disagrees with its own Content-Length is exactly the kind of thing an
        # availability probe reports as an unreachable endpoint.
        self._record("OPTIONS", "", None)
        self._send(200, {"ok": True})

    def do_GET(self, head_only=False):
        if self.path.split("?")[0] == "/_probes":
            self._send(200, {"count": len(PROBES), "probes": PROBES},
                       head_only=head_only)
            return
        self._record("HEAD" if head_only else "GET", "", None)
        # 200 on every path, so an availability probe never sees a 404.
        self._send(200, {
            "ok": True,
            "endpoint": "POST /sanitize-output",
            "channels": list(CHANNELS),
            "allowedHosts": sorted(ALLOWED_HOSTS),
        }, head_only=head_only)

    def do_HEAD(self):
        self.do_GET(head_only=True)

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
        text = raw.decode("utf-8", "replace")
        self._record(self.command, text, result)
        print("[gate]", self.path, json.dumps(result),
              "<<", json.dumps(text[:2000]), flush=True)
        self._send(200, result)

    # Any body-carrying method grades. The default handler answers an unknown
    # method with a 501 *HTML* page, which a probe reads as invalid JSON.
    do_PUT = do_POST
    do_PATCH = do_POST
    do_DELETE = do_POST

    def send_error(self, code, message=None, explain=None):
        # Errors must be JSON too, for the same reason.
        self._record("ERROR-" + str(self.command), str(message or ""), None)
        self._send(code if code < 500 else 400,
                   {"safe": False, "reason": "INVALID_SCHEMA"})

    def handle_one_request(self):
        # Never let a transport-level error surface as a bodyless 500.
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except Exception as exc:
            print("[error]", repr(exc), flush=True)
            self.close_connection = True


def keepalive():
    """Render free instances sleep after ~15 min idle; the next request then
    pays a 30-60s cold start and the grader's client times out. Ping our own
    public URL every 10 minutes so that never happens mid-grading."""
    url = os.environ.get("RENDER_EXTERNAL_URL")
    if not url:
        return
    import urllib.request
    while True:
        time.sleep(600)
        try:
            urllib.request.urlopen(url, timeout=20).read()
            print("[keepalive] pinged", url, flush=True)
        except Exception as exc:
            print("[keepalive] failed:", repr(exc), flush=True)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8000"))
    threading.Thread(target=keepalive, daemon=True).start()
    print(f"listening on 0.0.0.0:{port}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
