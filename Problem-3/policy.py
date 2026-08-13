"""Deterministic Terraform plan policy gate.

Pure schema + value checks, evaluated in the exact order the question lists.
No LLM, no Terraform binary.
"""
import re

WORKSPACE = "prod-zqtsld"
REQUIRED_LABELS = {
    "owner": "student-n9bj5",
    "environment": "production",
    "cost_center": "cc-c826",
}

VALID_BACKENDS = {"gcs", "s3", "azurerm", "remote"}
VALID_ACTIONS = {"create", "update", "delete"}
STATEFUL_TYPES = {"storage_bucket", "sql_database", "persistent_disk"}

# ordered reasons
# 1 types           -> INVALID_PLAN
# 2 workspace       -> ENVIRONMENT_MISMATCH
# 3 backend/lock    -> STATE_UNSAFE
# 4 provider pin    -> UNPINNED_PROVIDER
# 5 labels          -> MISSING_LABELS
# 6 secret          -> PLAINTEXT_SECRET
# 7 delete approval -> DELETE_NOT_APPROVED
# 8 force destroy   -> FORCE_DESTROY

_EXACT = re.compile(r"^=?\s*\d+\.\d+\.\d+$")          # 6.2.1  |  = 6.2.1
_PESSIMISTIC = re.compile(r"^~>\s*\d+(\.\d+){1,2}$")  # ~> 6.0 | ~> 6.2.1
_SECRET_REF = re.compile(r"^secret://.+$")


def _reject(reason):
    return {"decision": "reject", "reason": reason}


def _is_str(v):
    return isinstance(v, str)


def _is_bool(v):
    # bool must not be an int like 1/0
    return isinstance(v, bool)


def _valid_shape(p):
    if not isinstance(p, dict):
        return False
    if not _is_str(p.get("environment")):
        return False

    st = p.get("state")
    if not isinstance(st, dict):
        return False
    if not _is_str(st.get("backend")) or not _is_bool(st.get("locked")):
        return False

    if not _is_str(p.get("providerVersion")):
        return False
    if not _is_bool(p.get("destroyApproved")):
        return False

    r = p.get("resource")
    if not isinstance(r, dict):
        return False
    if not _is_str(r.get("address")) or not r.get("address").strip():
        return False
    if not _is_str(r.get("type")) or not r.get("type").strip():
        return False
    if r.get("action") not in VALID_ACTIONS:
        return False

    labels = r.get("labels")
    if not isinstance(labels, dict):
        return False
    for k, v in labels.items():
        if not _is_str(k) or not _is_str(v):
            return False

    secret = r.get("secret")
    if secret is not None and not _is_str(secret):
        return False

    if not _is_bool(r.get("forceDestroy")):
        return False
    return True


def evaluate(payload):
    # 1. shape / types
    if not _valid_shape(payload):
        return _reject("INVALID_PLAN")

    resource = payload["resource"]

    # 2. workspace
    if payload["environment"] != WORKSPACE:
        return _reject("ENVIRONMENT_MISMATCH")

    # 3. remote state + lock
    state = payload["state"]
    if state["backend"] not in VALID_BACKENDS or state["locked"] is not True:
        return _reject("STATE_UNSAFE")

    # 4. provider pinning
    pv = payload["providerVersion"].strip()
    if not (_EXACT.match(pv) or _PESSIMISTIC.match(pv)):
        return _reject("UNPINNED_PROVIDER")

    # 5. labels
    labels = resource["labels"]
    for key, want in REQUIRED_LABELS.items():
        if labels.get(key) != want:
            return _reject("MISSING_LABELS")

    # 6. secret handling
    secret = resource["secret"]
    if secret is not None:
        if not secret.strip() or not _SECRET_REF.match(secret.strip()):
            return _reject("PLAINTEXT_SECRET")

    # 7. unapproved stateful delete
    if resource["action"] == "delete" and resource["type"] in STATEFUL_TYPES:
        if payload["destroyApproved"] is not True:
            return _reject("DELETE_NOT_APPROVED")

    # 8. force destroy on a production bucket
    if resource["type"] == "storage_bucket" and resource["forceDestroy"] is True:
        return _reject("FORCE_DESTROY")

    return {"decision": "approve", "reason": "APPROVE"}
