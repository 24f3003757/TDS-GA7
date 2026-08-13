"""Deterministic LLM output handling gate (OWASP LLM05).

No AI, no phrase list. Pure rules, applied in a fixed order.
"""
import re
from urllib.parse import unquote, urlsplit

ALLOWED_HOSTS = {"cdn-20nrl5e.example", "app-ym5llhd.example"}
CHANNELS = ("html", "markdown", "url", "sql", "shell")
MAX_LEN = 20000

# ---------------------------------------------------------------- decoding

_NAMED = {"&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'", "&amp;": "&"}
_NUM_ENT = re.compile(r"&#(x[0-9a-fA-F]+|[0-9]+);")
_NAMED_ENT = re.compile(r"&(?:lt|gt|quot|apos|amp);", re.I)
_U_ESC = re.compile(r"\\u([0-9a-fA-F]{4})")


def _num_ent(m):
    body = m.group(1)
    try:
        cp = int(body[1:], 16) if body[0] in "xX" else int(body, 10)
        if 0 <= cp <= 0x10FFFF:
            return chr(cp)
    except ValueError:
        pass
    return m.group(0)


def decode_once(s):
    """percent-escapes -> HTML entities (numeric + the 5 named) -> \\uXXXX."""
    try:
        s = unquote(s, errors="strict")
    except Exception:
        pass
    s = _NUM_ENT.sub(_num_ent, s)
    s = _NAMED_ENT.sub(lambda m: _NAMED[m.group(0).lower()], s)
    s = _U_ESC.sub(lambda m: chr(int(m.group(1), 16)), s)
    return s


# ---------------------------------------------------------------- patterns

RE_SCRIPT = re.compile(r"<\s*(script|iframe|object|embed)\b", re.I)
# an on...= attribute: preceded by whitespace/quote/start so "python=" won't hit
RE_EVENT = re.compile(r"(?:^|[\s\"'/])on[a-z0-9_\-]+\s*=", re.I)
RE_SCHEME_TEXT = re.compile(r"(?:javascript|data|vbscript)\s*:", re.I)
RE_HTML_URL = re.compile(r"""\b(?:src|href)\s*=\s*("([^"]*)"|'([^']*)')""", re.I)
RE_MD_URL = re.compile(r"\]\(\s*([^)\s]+)")
RE_SQL_UNION = re.compile(r"\bunion\b", re.I)
RE_SQL_OR11 = re.compile(r"or\s+1\s*=\s*1", re.I)
RE_SHELL = re.compile(r"[;&|`<>]|\$\(|\$\{")


def extract_urls(channel, text):
    if channel == "html":
        out = []
        for m in RE_HTML_URL.finditer(text):
            out.append(m.group(2) if m.group(2) is not None else m.group(3))
        return out
    if channel == "markdown":
        return [m.group(1) for m in RE_MD_URL.finditer(text)]
    if channel == "url":
        t = text.strip()
        return [t] if t else []
    return []


def _parts(raw):
    """(is_absolute, scheme, hostname) for one extracted reference."""
    u = raw.strip()
    if not u:
        return False, "", ""
    if u.startswith("//"):                      # protocol-relative -> https:
        sp = urlsplit("https:" + u)
        return True, "https", (sp.hostname or "").lower()
    sp = urlsplit(u)
    if sp.scheme:
        return True, sp.scheme.lower(), (sp.hostname or "").lower()
    return False, "", ""                        # relative: /page, page.html, #x


def check_dangerous_scheme(channel, text):
    if RE_SCHEME_TEXT.search(text):
        return True
    for raw in extract_urls(channel, text):
        absolute, scheme, _ = _parts(raw)
        if absolute and scheme not in ("http", "https"):
            return True
    return False


def check_external_exfil(channel, text):
    for raw in extract_urls(channel, text):
        absolute, _, host = _parts(raw)
        if absolute and host not in ALLOWED_HOSTS:   # exact match only
            return True
    return False


# ---------------------------------------------------------------- channels

def check_channel(channel, text):
    """Return a violation reason, or None if this text is clean."""
    if channel == "html":
        if RE_SCRIPT.search(text):
            return "SCRIPT_TAG"
        if RE_EVENT.search(text):
            return "EVENT_HANDLER"
    if channel in ("html", "markdown", "url"):
        if check_dangerous_scheme(channel, text):
            return "DANGEROUS_SCHEME"
        if check_external_exfil(channel, text):
            return "EXTERNAL_EXFIL"
        return None
    if channel == "sql":
        if ("'" in text or '"' in text or ";" in text or "--" in text
                or "/*" in text or RE_SQL_UNION.search(text)
                or RE_SQL_OR11.search(text)):
            return "SQL_METACHAR"
        return None
    if channel == "shell":
        if RE_SHELL.search(text):
            return "SHELL_METACHAR"
        return None
    return None


def evaluate(body):
    # 1. schema
    if not isinstance(body, dict):
        return {"safe": False, "reason": "INVALID_SCHEMA"}
    channel = body.get("channel")
    output = body.get("output")
    if (channel not in CHANNELS or not isinstance(output, str)
            or isinstance(output, bool) or len(output) > MAX_LEN):
        return {"safe": False, "reason": "INVALID_SCHEMA"}

    # 2. encoded payload
    decoded = decode_once(output)
    if decoded != output and check_channel(channel, decoded) is not None:
        return {"safe": False, "reason": "ENCODED_PAYLOAD"}

    # 3. channel rules on the ORIGINAL output
    reason = check_channel(channel, output)
    if reason:
        return {"safe": False, "reason": reason}
    return {"safe": True, "reason": "SAFE"}
