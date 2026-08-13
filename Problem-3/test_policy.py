"""Self-check: python3 test_policy.py"""
import copy
from policy import evaluate

BASE = {
    "environment": "prod-zqtsld",
    "state": {"backend": "gcs", "locked": True},
    "providerVersion": "~> 6.0",
    "destroyApproved": False,
    "resource": {
        "address": "google_storage_bucket.data",
        "type": "storage_bucket",
        "action": "create",
        "labels": {
            "owner": "student-n9bj5",
            "environment": "production",
            "cost_center": "cc-c826",
        },
        "secret": None,
        "forceDestroy": False,
    },
}


def mod(**kw):
    p = copy.deepcopy(BASE)
    res = kw.pop("resource", None)
    p.update(kw)
    if res:
        p["resource"].update(res)
    return p


CASES = [
    (BASE, "approve", "APPROVE"),
    (mod(resource={"action": "update"}), "approve", "APPROVE"),
    (mod(providerVersion="6.2.1"), "approve", "APPROVE"),
    (mod(providerVersion="= 6.2.1"), "approve", "APPROVE"),
    (mod(resource={"secret": "secret://projects/p/secrets/db"}), "approve", "APPROVE"),
    (mod(destroyApproved=True, resource={"action": "delete"}), "approve", "APPROVE"),
    (mod(resource={"type": "compute_instance", "action": "delete"}), "approve", "APPROVE"),
    (mod(resource={"type": "compute_instance", "forceDestroy": True}), "approve", "APPROVE"),
    # faults, one at a time
    ({"environment": "prod-zqtsld"}, "reject", "INVALID_PLAN"),
    (mod(destroyApproved="false"), "reject", "INVALID_PLAN"),
    (mod(resource={"action": "destroy"}), "reject", "INVALID_PLAN"),
    (mod(state={"backend": "gcs", "locked": "true"}), "reject", "INVALID_PLAN"),
    (mod(environment="prod-other"), "reject", "ENVIRONMENT_MISMATCH"),
    (mod(state={"backend": "local", "locked": True}), "reject", "STATE_UNSAFE"),
    (mod(state={"backend": "gcs", "locked": False}), "reject", "STATE_UNSAFE"),
    (mod(providerVersion=">= 6.0"), "reject", "UNPINNED_PROVIDER"),
    (mod(providerVersion="latest"), "reject", "UNPINNED_PROVIDER"),
    (mod(providerVersion="*"), "reject", "UNPINNED_PROVIDER"),
    (mod(resource={"labels": {"owner": "student-n9bj5"}}), "reject", "MISSING_LABELS"),
    (mod(resource={"labels": dict(BASE["resource"]["labels"], cost_center="cc-x")}),
     "reject", "MISSING_LABELS"),
    (mod(resource={"secret": "hunter2"}), "reject", "PLAINTEXT_SECRET"),
    (mod(resource={"secret": ""}), "reject", "PLAINTEXT_SECRET"),
    (mod(resource={"secret": "secret://"}), "reject", "PLAINTEXT_SECRET"),
    (mod(resource={"action": "delete"}), "reject", "DELETE_NOT_APPROVED"),
    (mod(resource={"type": "sql_database", "action": "delete"}), "reject", "DELETE_NOT_APPROVED"),
    (mod(resource={"forceDestroy": True}), "reject", "FORCE_DESTROY"),
    (mod(destroyApproved=True, resource={"action": "delete", "forceDestroy": True}),
     "reject", "FORCE_DESTROY"),
]

fail = 0
for i, (payload, dec, reason) in enumerate(CASES, 1):
    got = evaluate(payload)
    if got != {"decision": dec, "reason": reason}:
        fail += 1
        print(f"FAIL {i}: expected {dec}/{reason}, got {got}")
print(f"{len(CASES) - fail}/{len(CASES)} passed")
