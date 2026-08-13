# Problem-3 — Terraform Plan Policy Gate

`POST /terraform/plan` → `{"decision": "...", "reason": "..."}`

Files: `policy.py` (rules), `server.py` (stdlib HTTP server), `test_policy.py` (27 cases).
No dependencies. No AI calls needed — the rules are fully deterministic.

## Run locally

```bash
cd Problem-3
python3 test_policy.py
python3 server.py            # http://localhost:8000
curl -s -X POST localhost:8000/terraform/plan -H 'content-type: application/json' \
  -d '{"environment":"prod-zqtsld","state":{"backend":"gcs","locked":true},"providerVersion":"~> 6.0","destroyApproved":false,"resource":{"address":"google_storage_bucket.data","type":"storage_bucket","action":"create","labels":{"owner":"student-n9bj5","environment":"production","cost_center":"cc-c826"},"secret":null,"forceDestroy":false}}'
```

## Deploy on render.com

1. Commit and push this folder to GitHub.
2. render.com → **New +** → **Web Service** → connect this repo.
3. Fill in exactly:
   - **Name:** `tf-plan-gate` (anything)
   - **Language / Runtime:** `Python 3`
   - **Branch:** `main`
   - **Root Directory:** `Problem-3`
   - **Build Command:** `pip install --upgrade pip` (nothing to install)
   - **Start Command:** `python server.py`
   - **Instance Type:** Free
   - Environment variables: **none** (Render injects `PORT` itself)
4. Create Web Service, wait for "Live".
5. Test the public URL, then submit the **base URL only**:
   `https://tf-plan-gate.onrender.com` — no trailing path, no query, no fragment.

Free instances sleep after inactivity; hit the base URL once right before
submitting so the first grader request isn't a cold start.

## Rule order (first match wins)

| # | Check | Reason |
|---|---|---|
| 1 | types of every field | `INVALID_PLAN` |
| 2 | `environment == prod-zqtsld` | `ENVIRONMENT_MISMATCH` |
| 3 | backend ∈ gcs/s3/azurerm/remote and `locked == true` | `STATE_UNSAFE` |
| 4 | `6.2.1`, `= 6.2.1`, or `~> 6.0` | `UNPINNED_PROVIDER` |
| 5 | all 3 labels exact | `MISSING_LABELS` |
| 6 | secret is `null` or `secret://…` | `PLAINTEXT_SECRET` |
| 7 | delete of bucket/db/disk needs `destroyApproved` | `DELETE_NOT_APPROVED` |
| 8 | storage_bucket with `forceDestroy: true` | `FORCE_DESTROY` |
| — | otherwise | `APPROVE` |
