"""
Shareable dashboard snapshots.

A snapshot is a plain-JSON file: an exported, read-only picture of a dashboard
at one moment, meant to be handed to someone (possibly on a different network)
and opened back inside Argus. It is the air-gap-safe way to share a dashboard —
no live connection, no account, nothing to reach back to.

Security stance — the import side treats every byte as UNTRUSTED:
  * JSON only. Never pickle, never eval, never exec. A snapshot carries data,
    not code.
  * Strict structure validation with a hard size cap. Unknown keys are dropped,
    every value is coerced to a safe type (small ints, short strings), and the
    number of entries is bounded, so a hostile file can't blow up memory or
    smuggle anything through.
  * No markup is ever taken from a snapshot. Values are rendered as text and
    escaped by the template; charts are drawn from numbers only.
  * A SHA-256 over the data lets the viewer detect tampering. It is integrity,
    not authentication — it says the numbers weren't changed in transit, not
    who produced them — and the UI labels snapshots as "as reported by the
    sender" accordingly.
"""

import hashlib
import json

SNAPSHOT_VERSION = 1
MAX_BYTES = 512 * 1024          # a dashboard snapshot is tiny; cap hard
_MAX_INT = 10_000_000
_MAX_ENTRIES = 60


class SnapshotError(ValueError):
    """Raised when a file can't be accepted as a dashboard snapshot."""


def _num(v):
    """Coerce to a non-negative, bounded int. Anything odd becomes 0."""
    try:
        n = int(v)
    except (TypeError, ValueError):
        return 0
    if n < 0:
        return 0
    return min(n, _MAX_INT)


def _counts(d):
    """A dict of short-string keys -> safe ints, bounded in size."""
    if not isinstance(d, dict):
        return {}
    out = {}
    for k, v in d.items():
        if not isinstance(k, str):
            continue
        out[k[:60]] = _num(v)
        if len(out) >= _MAX_ENTRIES:
            break
    return out


def _pairs(lst):
    """A list of [short-string, int] pairs, bounded in size."""
    if not isinstance(lst, list):
        return []
    out = []
    for item in lst:
        if isinstance(item, (list, tuple)) and len(item) == 2 and isinstance(item[0], str):
            out.append([item[0][:80], _num(item[1])])
        if len(out) >= 12:
            break
    return out


_TOTALS_KEYS = ["total", "critical", "high", "open", "fixed", "breached",
                "overdue", "remediation_rate"]


def validate_data(data):
    """Return a sanitised copy of a dashboard-aggregates dict, or raise."""
    if not isinstance(data, dict):
        raise SnapshotError("Snapshot has no dashboard data.")
    totals = data.get("totals")
    if not isinstance(totals, dict):
        raise SnapshotError("Snapshot is missing its totals.")
    clean = {
        "totals": {k: _num(totals.get(k)) for k in _TOTALS_KEYS},
        "by_actual_risk": _counts(data.get("by_actual_risk")),
        "by_reported": _counts(data.get("by_reported")),
        "by_status": _counts(data.get("by_status")),
        "by_rto": _counts(data.get("by_rto")),
        "by_exploit": _counts(data.get("by_exploit")),
        "open_vs_closed": _counts(data.get("open_vs_closed")),
        "top_owners": _pairs(data.get("top_owners")),
    }
    return clean


def _checksum(data):
    return hashlib.sha256(
        json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def build(data, title, source, generated_by, app_version, generated_at):
    """Serialise a dashboard snapshot to a JSON string for download."""
    clean = validate_data(data)
    payload = {
        "argus_snapshot": SNAPSHOT_VERSION,
        "kind": "dashboard",
        "title": (title or "")[:160],
        "source": (source or "")[:160],
        "generated_at": generated_at,
        "generated_by": (generated_by or "")[:120],
        "app_version": (app_version or "")[:40],
        "data": clean,
        "checksum": _checksum(clean),
    }
    return json.dumps(payload, indent=2)


def parse(raw):
    """Parse + validate an uploaded snapshot (bytes or str). Returns
    {meta..., data, integrity_ok}. Raises SnapshotError on anything off."""
    if isinstance(raw, bytes):
        if len(raw) > MAX_BYTES:
            raise SnapshotError("File is too large to be a dashboard snapshot.")
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise SnapshotError("File isn't text — not a snapshot.")
    elif len(raw) > MAX_BYTES:
        raise SnapshotError("File is too large to be a dashboard snapshot.")
    try:
        obj = json.loads(raw)
    except Exception:
        raise SnapshotError("Couldn't read the file as a snapshot (invalid JSON).")
    if not isinstance(obj, dict):
        raise SnapshotError("This isn't an Argus snapshot.")
    if obj.get("argus_snapshot") != SNAPSHOT_VERSION:
        raise SnapshotError("This isn't an Argus dashboard snapshot, or it's a newer version.")
    if obj.get("kind") != "dashboard":
        raise SnapshotError("Only dashboard snapshots can be opened here.")
    raw_data = obj.get("data")
    clean = validate_data(raw_data)
    # integrity: the sender's checksum is over their data as sent
    integrity_ok = isinstance(obj.get("checksum"), str) and obj["checksum"] == _checksum(clean)
    return {
        "title": str(obj.get("title", ""))[:160],
        "source": str(obj.get("source", ""))[:160],
        "generated_at": str(obj.get("generated_at", ""))[:40],
        "generated_by": str(obj.get("generated_by", ""))[:120],
        "app_version": str(obj.get("app_version", ""))[:40],
        "data": clean,
        "integrity_ok": integrity_ok,
    }


def _self_test():
    data = {
        "totals": {"total": 13, "critical": 5, "high": 4, "open": 8, "fixed": 1,
                   "breached": 4, "overdue": 3, "remediation_rate": 15},
        "by_actual_risk": {"Critical": 5, "High": 4, "Medium": 2, "Low": 1, "Information": 1},
        "by_reported": {"High": 6}, "by_status": {"Pending": 7, "Fixed": 1},
        "by_rto": {"Met": 1, "Breached": 4, "Open": 8}, "by_exploit": {"No": 7, "Yes": 5, "Unknown": 1},
        "open_vs_closed": {"Open": 8, "Fixed": 1}, "top_owners": [["Systems Team", 4], ["Platform Team", 3]],
    }
    js = build(data, "PAIX — posture", "PAIX Argus", "patricia", "1.0", "2026-11-23T05:00:00")
    got = parse(js)
    assert got["integrity_ok"] is True
    assert got["data"]["totals"]["total"] == 13
    assert got["title"] == "PAIX — posture" and got["source"] == "PAIX Argus"

    # tampering flips integrity but still parses safely
    tampered = json.loads(js); tampered["data"]["totals"]["total"] = 999
    assert parse(json.dumps(tampered))["integrity_ok"] is False

    # hostile / malformed inputs are refused, never executed
    for bad in ["not json", "[]", json.dumps({"argus_snapshot": 2}),
                json.dumps({"argus_snapshot": 1, "kind": "evil"}),
                json.dumps({"argus_snapshot": 1, "kind": "dashboard"})]:
        try:
            parse(bad); assert False, f"should have rejected: {bad[:40]}"
        except SnapshotError:
            pass

    # injection-ish strings survive only as truncated text; sizes bounded
    eviln = parse(json.dumps({"argus_snapshot": 1, "kind": "dashboard",
        "title": "<script>x</script>" * 50,
        "data": {"totals": {"total": "99"}, "by_status": {k * 100: i for i, k in enumerate("abcdefghij" * 20)}}}))
    assert len(eviln["title"]) <= 160
    assert len(eviln["data"]["by_status"]) <= _MAX_ENTRIES
    assert eviln["data"]["totals"]["total"] == 99     # coerced from string
    assert parse(b"x" * (MAX_BYTES + 1)).__class__ if False else True  # size path below
    try:
        parse(b"x" * (MAX_BYTES + 1)); assert False
    except SnapshotError:
        pass
    print("snapshots self-tests passed")


if __name__ == "__main__":
    _self_test()
