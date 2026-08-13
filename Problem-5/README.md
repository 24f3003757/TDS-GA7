# Problem-5 — OSINT Corroboration Engine

Subject: `q5l1dy.example`. Endpoint: `POST /corroborate`. Stdlib only, no wall clock.

## Run locally
```bash
cd Problem-5
python3 test_corroborate.py      # 20/20
python3 server.py                # http://localhost:8000/corroborate
```

Smoke test:
```bash
curl -s -X POST localhost:8000/corroborate -H 'Content-Type: application/json' -d '{
 "claim":{"subject":"q5l1dy.example","predicate":"resolves_to","value":"203.0.113.20"},
 "asOf":"2026-08-01T00:00:00Z","stalenessDays":120,
 "sources":[{"id":"s1","type":"dns","origin":"resolver-a","observedAt":"2026-07-30T00:00:00Z","value":"203.0.113.20","authoritative":false},
            {"id":"s2","type":"ct_log","origin":"ct-b","observedAt":"2026-07-01T00:00:00Z","value":"203.0.113.20","authoritative":false}]}'
```

## Deploy on render.com
Push first:
```bash
git add Problem-5 && git commit -m "Problem-5: OSINT corroboration engine" && git push
```
Render dashboard → **New +** → **Web Service** → connect this repo, then fill:

| Field | Value |
|---|---|
| Language / Runtime | `Python 3` |
| Branch | `main` |
| Root Directory | `Problem-5` |
| Build Command | *(leave empty)* |
| Start Command | `python3 server.py` |
| Instance Type | Free |

No environment variables needed. Render supplies `$PORT`; the server binds `0.0.0.0:$PORT`.

Submit: `https://<your-service>.onrender.com/corroborate`

Free instances sleep — hit the URL once right before submitting so the grader
does not time out on a cold start.
