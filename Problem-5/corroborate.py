"""OSINT corroboration engine — pure logic, no wall clock, no dependencies.

evaluate(body) -> {"verdict": ..., "confidence": ..., "corroboratingSources": [...]}
"""
from datetime import datetime, timezone

SUBJECT = "q5l1dy.example"
VALID_TYPES = {"dns", "ct_log", "registry", "archive", "scan"}

INVALID = {"verdict": "invalid", "confidence": "low", "corroboratingSources": []}
UNVERIFIED = {"verdict": "unverified", "confidence": "low", "corroboratingSources": []}


def parse_ts(s):
    """Parse an ISO-8601 timestamp string. Returns aware datetime or None."""
    if not isinstance(s, str) or not s.strip():
        return None
    t = s.strip()
    if t.endswith("Z") or t.endswith("z"):
        t = t[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def is_number(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def valid_source(s):
    if not isinstance(s, dict):
        return False
    for k in ("id", "origin", "value", "observedAt"):
        if not isinstance(s.get(k), str):
            return False
    return s.get("type") in VALID_TYPES


def evaluate(body):
    # --- Rule 1: invalid ------------------------------------------------
    if not isinstance(body, dict):
        return dict(INVALID)
    claim = body.get("claim")
    if not isinstance(claim, dict) or not isinstance(claim.get("value"), str):
        return dict(INVALID)
    as_of = parse_ts(body.get("asOf"))
    if as_of is None:
        return dict(INVALID)
    staleness = body.get("stalenessDays")
    if not is_number(staleness):
        return dict(INVALID)
    sources = body.get("sources")
    if not isinstance(sources, list):
        return dict(INVALID)

    claim_value = claim["value"]
    window = float(staleness) * 86400.0  # seconds

    fresh = []
    for s in sources:
        if not valid_source(s):
            continue                      # ignored entirely
        obs = parse_ts(s["observedAt"])
        if obs is None:
            continue                      # unparseable -> carries no weight
        age = (as_of - obs).total_seconds()
        if age <= window:                 # fresh (future observations count as fresh)
            fresh.append(s)

    # --- Rule 2: contradicted ------------------------------------------
    contra = sorted(
        s["id"] for s in fresh
        if s.get("authoritative") is True and s["value"] != claim_value
    )
    if contra:
        return {"verdict": "contradicted", "confidence": "low",
                "corroboratingSources": contra}

    # --- Rule 3: supported ---------------------------------------------
    reps = {}  # origin -> source with lexicographically smallest id
    for s in fresh:
        if s["value"] != claim_value:
            continue
        cur = reps.get(s["origin"])
        if cur is None or s["id"] < cur["id"]:
            reps[s["origin"]] = s

    if len(reps) >= 2:
        chosen = list(reps.values())
        types = {s["type"] for s in chosen}
        return {
            "verdict": "supported",
            "confidence": "high" if len(types) >= 2 else "medium",
            "corroboratingSources": sorted(s["id"] for s in chosen),
        }

    # --- Rule 4: unverified --------------------------------------------
    return dict(UNVERIFIED)
