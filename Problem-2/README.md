# Problem-2 — LLM Action Firewall

`POST /action-firewall` → `{"decision":"allow|block","reason":"..."}`

- `firewall.py` — all the logic (no deps, no LLM, no phrase lists)
- `server.py` — stdlib HTTP server, reads `$PORT`
- `test_firewall.py` — 22 self-checks

Scope: tenant `tenant-re177kd`, email domain `notify-2pojh39.example`.

## Local

```bash
cd Problem-2
python3 test_firewall.py
python3 server.py            # http://localhost:8000/action-firewall
```

## Check order (first failure wins)

1. top-level schema → `INVALID_SCHEMA`
2. tool allowlist → `TOOL_NOT_ALLOWED`
3. tool arg schema (exact key set) → `INVALID_SCHEMA`
4. tenant scope → `TENANT_SCOPE`
5. exact recipient domain → `EGRESS_DENIED`
6. human approval → `APPROVAL_REQUIRED`
7. HTML safety → `UNSAFE_OUTPUT`
