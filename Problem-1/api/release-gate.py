from http.server import BaseHTTPRequestHandler
import json, re

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_PERMS = {"contents": "read", "packages": "write", "id-token": "none"}


def evaluate(payload: dict) -> list:
    v = []
    wf = payload.get("workflow", {}) or {}
    img = payload.get("image", {}) or {}
    target = payload.get("target")
    event = payload.get("event")
    ref = payload.get("ref")

    perms = wf.get("permissions", {}) or {}
    if perms != REQUIRED_PERMS:
        v.append("EXCESS_PERMISSION")

    # pull_request_target is unsafe regardless of which event is claimed.
    if wf.get("trigger") == "pull_request_target":
        v.append("UNSAFE_PR_TRIGGER")

    # Test/matrix gating applies to any run that reports these fields; a PR is
    # always gated even if the fields are omitted.
    test_keys = ("testsPassed", "matrixComplete", "failFast")
    if event == "pull_request" or any(k in wf for k in test_keys):
        if (not wf.get("testsPassed", False)
                or not wf.get("matrixComplete", False)
                or wf.get("failFast", True)):
            v.append("TESTS_INCOMPLETE")

    for a in wf.get("actions", []) or []:
        owner = a.get("owner", "")
        ref_ = a.get("ref", "") or ""
        if owner == "actions":
            continue
        if not SHA_RE.match(ref_):
            v.append("MUTABLE_ACTION")
            break

    if not img.get("multiStage", False):
        v.append("SINGLE_STAGE_IMAGE")
    if img.get("runsAsRoot", True):
        v.append("ROOT_RUNTIME")
    if img.get("secretMode", "arg") not in ("none", "buildkit"):
        v.append("SECRET_IN_LAYER")
    if int(img.get("criticalVulnerabilities", 1) or 0) > 0:
        v.append("CRITICAL_CVE")
    if not img.get("digestPinned", False):
        v.append("UNPINNED_IMAGE")

    if target == "production":
        if event != "push" or ref != "refs/heads/main":
            v.append("INVALID_PRODUCTION_REF")
        if not wf.get("environmentApproval", False):
            v.append("APPROVAL_REQUIRED")

    return v


class handler(BaseHTTPRequestHandler):
    def _send(self, code, body):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
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
            self._send(400, {"decision": "block", "violations": []})
            return
        violations = evaluate(payload)
        decision = "promote" if not violations else "block"
        self._send(200, {"decision": decision, "violations": violations})
