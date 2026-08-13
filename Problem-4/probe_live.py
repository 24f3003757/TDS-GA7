"""Run the whole local case list against the DEPLOYED service.

    python3 probe_live.py https://tds-ga7-problem-4.onrender.com

Also warms the instance and reports per-request latency, so a cold start is
visible as a slow first request rather than as a mystery grader failure.
"""
import json
import sys
import time
import urllib.request

from test_gate import CASES

BASE = (sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000").rstrip("/")


def post(body, timeout=90):
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + "/sanitize-output", data=data,
        headers={"Content-Type": "application/json"})
    t0 = time.time()
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode()), r.status, time.time() - t0


def main():
    t0 = time.time()
    urllib.request.urlopen(BASE + "/", timeout=90).read()
    print(f"warm-up GET / took {time.time() - t0:.1f}s")

    bad = slow = 0
    for name, body, want in CASES:
        try:
            got, status, dt = post(body)
        except Exception as exc:
            bad += 1
            print(f"FAIL {name}: transport error {exc!r}")
            continue
        if dt > 5:
            slow += 1
            print(f"SLOW {name}: {dt:.1f}s")
        if status != 200 or got.get("reason") != want \
                or got.get("safe") != (want == "SAFE") \
                or set(got) != {"safe", "reason"}:
            bad += 1
            print(f"FAIL {name}: want {want}, got {status} {got}")
    print(f"{len(CASES) - bad}/{len(CASES)} passed live, {slow} slow")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
