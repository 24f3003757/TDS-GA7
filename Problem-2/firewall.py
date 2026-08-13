"""Deterministic LLM action firewall.

No LLM, no suspicious-phrase matching. Pure schema + scope + approval +
HTML-safety checks, evaluated in the exact order the question specifies.
"""
import re

TENANT_ID = "tenant-re177kd"
EMAIL_DOMAIN = "notify-2pojh39.example"

ALLOWED_TOOLS = {"search", "lookup_record", "send_email", "render_html"}

# --- ordered reasons -------------------------------------------------------
# 1 top-level schema      -> INVALID_SCHEMA
# 2 tool allowlist        -> TOOL_NOT_ALLOWED
# 3 tool arg schema       -> INVALID_SCHEMA
# 4 tenant scope          -> TENANT_SCOPE
# 5 exact email domain    -> EGRESS_DENIED
# 6 human approval        -> APPROVAL_REQUIRED
# 7 html safety           -> UNSAFE_OUTPUT


def _is_str(v):
    return isinstance(v, str)


def _exact_keys(args, keys):
    return isinstance(args, dict) and set(args.keys()) == set(keys)


def _block(reason):
    return {"decision": "block", "reason": reason}


# --- HTML safety -----------------------------------------------------------
_SCRIPT = re.compile(r"<\s*script\b", re.I)
_IFRAME = re.compile(r"<\s*iframe\b", re.I)
_OBJECTISH = re.compile(r"<\s*(object|embed|svg|math|base|meta|link|form)\b", re.I)
# on<event>= handlers, e.g. onclick=, onerror =, ONLOAD="
_ONHANDLER = re.compile(r"[\s\"'/]on[a-z0-9_\-]+\s*=", re.I)
# javascript: / vbscript: / data:text/html URLs, tolerating entities & whitespace
_JS_URL = re.compile(r"j\s*a\s*v\s*a\s*s\s*c\s*r\s*i\s*p\s*t\s*:", re.I)
_VB_URL = re.compile(r"v\s*b\s*s\s*c\s*r\s*i\s*p\s*t\s*:", re.I)
_DATA_HTML = re.compile(r"data\s*:\s*text/html", re.I)


def _decode_entities(s):
    """Undo the obfuscations that hide a javascript: URL from a naive scan."""
    out = s
    # numeric entities: &#106; &#x6A;
    out = re.sub(r"&#x([0-9a-f]+);?", lambda m: chr(int(m.group(1), 16)), out, flags=re.I)
    out = re.sub(r"&#(\d+);?", lambda m: chr(int(m.group(1))), out)
    named = {"&colon;": ":", "&NewLine;": "\n", "&Tab;": "\t", "&amp;": "&",
             "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'", "&#0;": ""}
    for k, v in named.items():
        out = out.replace(k, v).replace(k.lower(), v)
    # strip NULs and control chars browsers ignore inside URLs
    out = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", out)
    return out


def html_is_unsafe(html):
    for candidate in (html, _decode_entities(html)):
        if (_SCRIPT.search(candidate) or _IFRAME.search(candidate)
                or _OBJECTISH.search(candidate) or _ONHANDLER.search(candidate)
                or _JS_URL.search(candidate) or _VB_URL.search(candidate)
                or _DATA_HTML.search(candidate)):
            return True
    return False


# --- main ------------------------------------------------------------------
def evaluate(body):
    # 1. top-level schema
    if not isinstance(body, dict):
        return _block("INVALID_SCHEMA")

    prov = body.get("provenance")
    if prov not in ("trusted", "untrusted"):
        return _block("INVALID_SCHEMA")

    approved = body.get("humanApproved", False)
    if not isinstance(approved, bool):
        return _block("INVALID_SCHEMA")

    if "untrustedContent" in body and body["untrustedContent"] is not None:
        if not _is_str(body["untrustedContent"]):
            return _block("INVALID_SCHEMA")

    action = body.get("action")
    if not isinstance(action, dict):
        return _block("INVALID_SCHEMA")
    if set(action.keys()) - {"tool", "args"} or "tool" not in action:
        return _block("INVALID_SCHEMA")

    tool = action.get("tool")
    if not _is_str(tool) or not tool:
        return _block("INVALID_SCHEMA")

    # 2. tool allowlist
    if tool not in ALLOWED_TOOLS:
        return _block("TOOL_NOT_ALLOWED")

    args = action.get("args")
    if not isinstance(args, dict):
        return _block("INVALID_SCHEMA")

    # 3..7 per tool
    if tool == "search":
        if not _exact_keys(args, ["query"]) or not _is_str(args["query"]):
            return _block("INVALID_SCHEMA")
        if not (1 <= len(args["query"]) <= 200):
            return _block("INVALID_SCHEMA")
        return {"decision": "allow", "reason": "ALLOW"}

    if tool == "lookup_record":
        if not _exact_keys(args, ["tenantId", "recordId"]):
            return _block("INVALID_SCHEMA")
        if not _is_str(args["tenantId"]) or not _is_str(args["recordId"]):
            return _block("INVALID_SCHEMA")
        if args["recordId"] == "" or args["tenantId"] == "":
            return _block("INVALID_SCHEMA")
        if args["tenantId"] != TENANT_ID:
            return _block("TENANT_SCOPE")
        return {"decision": "allow", "reason": "ALLOW"}

    if tool == "send_email":
        if not _exact_keys(args, ["to", "subject", "body"]):
            return _block("INVALID_SCHEMA")
        if not all(_is_str(args[k]) for k in ("to", "subject", "body")):
            return _block("INVALID_SCHEMA")
        to = args["to"]
        if to.count("@") != 1:
            return _block("INVALID_SCHEMA")
        local, _, domain = to.partition("@")
        if local == "" or domain == "":
            return _block("INVALID_SCHEMA")
        # exact domain match, case-insensitive host comparison only
        if domain.lower() != EMAIL_DOMAIN.lower():
            return _block("EGRESS_DENIED")
        if approved is not True:
            return _block("APPROVAL_REQUIRED")
        return {"decision": "allow", "reason": "ALLOW"}

    if tool == "render_html":
        if not _exact_keys(args, ["html"]) or not _is_str(args["html"]):
            return _block("INVALID_SCHEMA")
        if html_is_unsafe(args["html"]):
            return _block("UNSAFE_OUTPUT")
        return {"decision": "allow", "reason": "ALLOW"}

    return _block("TOOL_NOT_ALLOWED")
