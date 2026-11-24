"""
cvss.py — CVSS v3.1 helpers (offline, no dependencies).

Argus stores two CVSS facts per finding when it knows them: a base score
(0.0–10.0) and the base vector string. This module keeps that handling in one
place:

  * severity_band(score)   -> the qualitative band CVSS v3.1 defines, so a
                              score and a severity label never disagree.
  * clamp_score(value)     -> a tolerant parse to a valid 0.0–10.0 score, or
                              None when the input isn't a usable number.
  * parse_vector(vector)   -> a light structural check + the metrics it carries,
                              used only to display/verify a vector, never to
                              re-derive the score (we store the vendor's score).

We deliberately do NOT compute scores from vectors here. Base scores come from
the dataset (which mirrors the vendor/NVD figure) so Argus reports the same
number an analyst would see on the NVD page, rather than a re-derivation that
could drift.
"""

# CVSS v3.1 qualitative severity rating scale (section 5, spec).
_BANDS = [
    (0.0, 0.0, "None"),
    (0.1, 3.9, "Low"),
    (4.0, 6.9, "Medium"),
    (7.0, 8.9, "High"),
    (9.0, 10.0, "Critical"),
]

# Known base-metric groups for a v3.x vector (abbrev -> allowed values).
_BASE_METRICS = {
    "AV": {"N", "A", "L", "P"},
    "AC": {"L", "H"},
    "PR": {"N", "L", "H"},
    "UI": {"N", "R"},
    "S": {"U", "C"},
    "C": {"N", "L", "H"},
    "I": {"N", "L", "H"},
    "A": {"N", "L", "H"},
}

_METRIC_LABELS = {
    "AV": "Attack vector", "AC": "Attack complexity", "PR": "Privileges required",
    "UI": "User interaction", "S": "Scope", "C": "Confidentiality",
    "I": "Integrity", "A": "Availability",
}
_VALUE_LABELS = {
    "AV": {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"},
    "AC": {"L": "Low", "H": "High"},
    "PR": {"N": "None", "L": "Low", "H": "High"},
    "UI": {"N": "None", "R": "Required"},
    "S": {"U": "Unchanged", "C": "Changed"},
    "C": {"N": "None", "L": "Low", "H": "High"},
    "I": {"N": "None", "L": "Low", "H": "High"},
    "A": {"N": "None", "L": "Low", "H": "High"},
}


def clamp_score(value):
    """Parse value to a float in [0.0, 10.0] rounded to one decimal, else None."""
    if value is None or value == "":
        return None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f < 0:
        f = 0.0
    if f > 10:
        f = 10.0
    return round(f, 1)


def severity_band(score):
    """Return the CVSS v3.1 qualitative band for a numeric score, or '' if unknown."""
    s = clamp_score(score)
    if s is None:
        return ""
    for lo, hi, label in _BANDS:
        if lo <= s <= hi:
            return label
    return ""


def parse_vector(vector):
    """Return a dict describing a CVSS v3.x base vector, or None if it doesn't
    look like one. Used for display only — we never recompute the score."""
    if not vector or not isinstance(vector, str):
        return None
    v = vector.strip()
    parts = v.split("/")
    prefix = ""
    if parts and parts[0].upper().startswith("CVSS:"):
        prefix = parts[0]
        parts = parts[1:]
    metrics = {}
    for p in parts:
        if ":" not in p:
            return None
        k, _, val = p.partition(":")
        k, val = k.strip().upper(), val.strip().upper()
        if k in _BASE_METRICS and val in _BASE_METRICS[k]:
            metrics[k] = val
    # a usable base vector names at least the eight base metrics
    if not all(m in metrics for m in _BASE_METRICS):
        return None
    readable = [
        (_METRIC_LABELS[k], _VALUE_LABELS[k][metrics[k]])
        for k in ("AV", "AC", "PR", "UI", "S", "C", "I", "A")
    ]
    return {"version": prefix or "CVSS:3.1", "metrics": metrics, "readable": readable}


def normalize(score, vector):
    """Return (score_or_None, vector_or_'', band). A vector is kept only if it
    parses; the band always follows the score."""
    s = clamp_score(score)
    vec = vector.strip() if isinstance(vector, str) else ""
    if vec and parse_vector(vec) is None:
        vec = ""
    return s, vec, severity_band(s)


if __name__ == "__main__":
    assert severity_band(0) == "None"
    assert severity_band(3.9) == "Low"
    assert severity_band(5.0) == "Medium"
    assert severity_band(7.0) == "High"
    assert severity_band(9.8) == "Critical"
    assert severity_band(None) == ""
    assert clamp_score("9.8") == 9.8
    assert clamp_score("12") == 10.0
    assert clamp_score("abc") is None
    pv = parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert pv and pv["metrics"]["AV"] == "N", pv
    assert parse_vector("AV:N/AC:L") is None  # incomplete
    s, vec, band = normalize("9.8", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert s == 9.8 and band == "Critical" and vec.startswith("CVSS")
    print("cvss self-test passed")
