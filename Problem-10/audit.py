#!/usr/bin/env python3
"""Audit a GitHub Actions workflow against the six finding codes W1..W6.

Pure stdlib (regex over the raw text) so it runs anywhere: python3 audit.py ci.yml
"""
import re
import sys

SRC = open(sys.argv[1] if len(sys.argv) > 1 else "ci.yml", encoding="utf-8").read()

findings = {}
job_at_risk = None

# --- split into jobs (2-space-indented keys under `jobs:`) -------------------
jobs_block = SRC.split("\njobs:\n", 1)[1]
job_names = re.findall(r"^  ([A-Za-z0-9_-]+):$", jobs_block, re.M)
chunks = re.split(r"^  [A-Za-z0-9_-]+:$", jobs_block, flags=re.M)[1:]
JOBS = dict(zip(job_names, chunks))

TRIGGERS = re.findall(r"^  ([a-z_]+):", SRC.split("\non:\n", 1)[1].split("\npermissions:")[0], re.M)

# W1: untrusted PR code runs in a privileged context
# pull_request_target (or workflow_run) + an explicit checkout of the PR head.
privileged_event = "pull_request_target" in TRIGGERS or "workflow_run" in TRIGGERS
for name, body in JOBS.items():
    checks_out_head = re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)", body)
    if privileged_event and checks_out_head:
        findings["W1"] = f"job `{name}` runs on {TRIGGERS} and checks out the PR head"
        job_at_risk = name

# W2: third-party action not pinned to a 40-char SHA
for name, body in JOBS.items():
    for use in re.findall(r"uses:\s*([^\s]+)", body):
        owner = use.split("/")[0]
        ref = use.split("@")[-1]
        if owner == "actions":
            continue  # first-party, major tag allowed
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            findings.setdefault("W2", []).append(f"{use} (job `{name}`)")

# W3: workflow-level permissions broader than any job needs
wf_perms = dict(re.findall(r"^  ([a-z-]+):\s*(read|write)$", SRC.split("\npermissions:\n", 1)[1].split("\njobs:")[0], re.M))
# scopes any job actually declares a need for
needed = set()
for body in JOBS.values():
    m = re.search(r"\n    permissions:\n((?:      .*\n)+)", body)
    if m:
        needed |= {k for k, v in re.findall(r"([a-z-]+):\s*(read|write)", m.group(1)) if v == "write"}
extra = {k for k, v in wf_perms.items() if v == "write"} - needed
if extra:
    findings["W3"] = f"workflow grants write on {sorted(wf_perms)} but no job needs {sorted(extra)}"

# W4: a secret's value can appear in step output
for name, body in JOBS.items():
    for line in body.splitlines():
        if re.search(r"(echo|printf|cat)\b.*\$\{\{\s*secrets\.", line):
            findings.setdefault("W4", []).append(f"job `{name}`: {line.strip()}")

# W5: production deploy with no environment: gate
for name, body in JOBS.items():
    deploys_prod = re.search(r"(--env\s+production|NODE_ENV=production|deploy)", body)
    if deploys_prod and not re.search(r"^\s{4}environment:", body, re.M):
        findings.setdefault("W5", []).append(f"job `{name}` deploys to production with no `environment:`")

# W6: attacker-controlled event data interpolated directly into a shell command
ATTACKER = r"github\.event\.(pull_request\.(title|body|head\.ref|head\.label|user\.login)|issue\.(title|body)|comment\.body|head_commit\.message|review\.body)"
in_run = False
for name, body in JOBS.items():
    for line in body.splitlines():
        if re.match(r"\s*(- )?run:", line):
            in_run = True
        elif re.match(r"\s*(- )?[a-z_]+:", line) and "run:" not in line:
            in_run = in_run and line.startswith("          ")
        if in_run and re.search(r"\$\{\{\s*" + ATTACKER, line):
            findings.setdefault("W6", []).append(f"job `{name}`: {line.strip()}")

codes = ",".join(sorted(findings))
print("=== evidence ===")
for k in sorted(findings):
    print(f"{k}: {findings[k]}")
print("\n=== ANSWER ===")
print(f"{codes}|{job_at_risk}")
