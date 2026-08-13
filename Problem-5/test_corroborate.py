"""Run: python3 test_corroborate.py"""
from corroborate import evaluate

S = "q5l1dy.example"
V = "203.0.113.20"


def body(sources, as_of="2026-08-01T00:00:00Z", days=120, value=V):
    return {"claim": {"subject": S, "predicate": "resolves_to", "value": value},
            "asOf": as_of, "stalenessDays": days, "sources": sources}


def src(i, origin, value=V, t="dns", when="2026-07-30T00:00:00Z", auth=False):
    return {"id": i, "origin": origin, "type": t, "value": value,
            "observedAt": when, "authoritative": auth}


CASES = [
    ("invalid: not object", "x", ("invalid", "low", [])),
    ("invalid: value not str", body([], value=1), ("invalid", "low", [])),
    ("invalid: bad asOf", body([], as_of="nope"), ("invalid", "low", [])),
    ("invalid: staleness str", {"claim": {"value": V}, "asOf": "2026-08-01T00:00:00Z",
                                "stalenessDays": "120", "sources": []},
     ("invalid", "low", [])),
    ("invalid: sources not list", {"claim": {"value": V}, "asOf": "2026-08-01T00:00:00Z",
                                   "stalenessDays": 120, "sources": {}},
     ("invalid", "low", [])),
    ("no sources", body([]), ("unverified", "low", [])),
    ("single source", body([src("s1", "a")]), ("unverified", "low", [])),
    ("mirrors only", body([src("s2", "a"), src("s1", "a")]), ("unverified", "low", [])),
    ("two origins same type", body([src("s1", "a"), src("s2", "b")]),
     ("supported", "medium", ["s1", "s2"])),
    ("two origins two types", body([src("s1", "a"), src("s2", "b", t="ct_log")]),
     ("supported", "high", ["s1", "s2"])),
    ("mirror picks smallest id", body([src("s9", "a"), src("s3", "a"), src("s5", "b")]),
     ("supported", "medium", ["s3", "s5"])),
    ("stale agreement", body([src("s1", "a", when="2025-01-01T00:00:00Z"),
                              src("s2", "b", when="2025-01-01T00:00:00Z")]),
     ("unverified", "low", [])),
    ("fresh authoritative disagreement", body([src("s1", "a"), src("s2", "b"),
                                               src("s3", "c", value="1.2.3.4", auth=True)]),
     ("contradicted", "low", ["s3"])),
    ("stale authoritative disagreement ignored",
     body([src("s1", "a"), src("s2", "b"),
           src("s3", "c", value="1.2.3.4", auth=True, when="2024-01-01T00:00:00Z")]),
     ("supported", "medium", ["s1", "s2"])),
    ("non-authoritative disagreement not counted",
     body([src("s1", "a"), src("s2", "b"), src("s3", "c", value="1.2.3.4")]),
     ("supported", "medium", ["s1", "s2"])),
    ("bad type ignored", body([src("s1", "a"), src("s2", "b", t="whois")]),
     ("unverified", "low", [])),
    ("missing field ignored", body([src("s1", "a"), {"id": "s2", "origin": "b",
                                                     "type": "dns", "value": V}]),
     ("unverified", "low", [])),
    ("boundary exactly at window",
     body([src("s1", "a", when="2026-04-03T00:00:00Z"), src("s2", "b")]),
     ("supported", "medium", ["s1", "s2"])),
    ("one day past window",
     body([src("s1", "a", when="2026-04-02T00:00:00Z"), src("s2", "b")]),
     ("unverified", "low", [])),
    ("contradicting ids sorted",
     body([src("z1", "c", value="1.1.1.1", auth=True),
           src("a1", "d", value="1.1.1.1", auth=True)]),
     ("contradicted", "low", ["a1", "z1"])),
]

fails = 0
for name, b, want in CASES:
    got = evaluate(b)
    g = (got["verdict"], got["confidence"], got["corroboratingSources"])
    ok = g == want
    fails += not ok
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  got={g} want={want}"))
print(f"\n{len(CASES) - fails}/{len(CASES)} passed")
raise SystemExit(1 if fails else 0)
