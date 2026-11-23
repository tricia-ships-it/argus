"""
Zoho Creator inventory sync (read-only).

The operator's asset inventory can live in a Zoho Creator app (cloud). This
module pulls that inventory into Argus's asset register. It is the one place
Argus deliberately reaches OUT to the internet, so it is tightly constrained:

  * READ ONLY. It makes exactly two kinds of request: a token-exchange POST to
    Zoho's accounts host, and GET requests to Zoho's data API. There is no code
    path that writes, updates or deletes anything in Zoho.
  * Host-pinned. The data centre is chosen from a fixed allowlist and hosts are
    built as accounts.zoho.<dc> / www.zohoapis.<dc>. No host is ever taken from
    user input, and every request URL is re-checked against the allowed hosts
    before it is sent.
  * Secrets (client id/secret, refresh token) come from the ENVIRONMENT only,
    never the UI or the database. Non-secret connection details (data centre,
    owner, app, report) and the field mapping live in settings.
  * Everything is transport-injectable, so the whole flow is unit-tested with no
    network and no real credentials.

Mapping reuses asset_classify.classify(), so a synced asset is classified
exactly like an imported one — including the OT "do not actively scan"
interlock.
"""

import json
import os
import urllib.parse
import urllib.request

import asset_classify

DATA_CENTERS = ["com", "eu", "in", "com.au", "jp", "ca", "sa", "uk"]
MAX_RECORDS = 10000
_PAGE = 200

# canonical asset fields the operator maps their Zoho fields onto
MAP_FIELDS = [
    ("ip", "IP address"),
    ("hostname", "Hostname / name"),
    ("description", "Description / role"),
    ("criticality", "Criticality"),
    ("type", "Asset type"),
    ("owner", "Owner / team"),
]


class ZohoError(Exception):
    pass


def secrets():
    return {
        "client_id": (os.environ.get("ARGUS_ZOHO_CLIENT_ID") or "").strip(),
        "client_secret": (os.environ.get("ARGUS_ZOHO_CLIENT_SECRET") or "").strip(),
        "refresh_token": (os.environ.get("ARGUS_ZOHO_REFRESH_TOKEN") or "").strip(),
    }


def secrets_configured():
    s = secrets()
    return bool(s["client_id"] and s["client_secret"] and s["refresh_token"])


def _accounts_host(dc):
    return "accounts.zoho." + dc


def _api_host(dc):
    return "www.zohoapis." + dc


def _check_host(url, allowed):
    host = urllib.parse.urlparse(url).hostname or ""
    if host != allowed:
        raise ZohoError(f"Refused request to unexpected host {host!r}")


# --- default transports (urllib); injectable for tests --------------------
def _real_post(url, data, headers=None, timeout=30):
    body = urllib.parse.urlencode(data).encode()
    req = urllib.request.Request(url, data=body, method="POST", headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec - host-checked
        return r.status, r.read().decode("utf-8", "ignore")


def _real_get(url, headers=None, timeout=30):
    req = urllib.request.Request(url, method="GET", headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # nosec - host-checked
        return r.status, r.read().decode("utf-8", "ignore")


# --- OAuth + fetch --------------------------------------------------------
def get_access_token(dc, http_post=None):
    http_post = http_post or _real_post
    if dc not in DATA_CENTERS:
        raise ZohoError(f"Unknown Zoho data centre {dc!r}")
    s = secrets()
    if not (s["client_id"] and s["client_secret"] and s["refresh_token"]):
        raise ZohoError("Zoho credentials are not configured in the environment.")
    url = f"https://{_accounts_host(dc)}/oauth/v2/token"
    _check_host(url, _accounts_host(dc))
    status, body = http_post(url, {
        "grant_type": "refresh_token",
        "client_id": s["client_id"],
        "client_secret": s["client_secret"],
        "refresh_token": s["refresh_token"],
    })
    try:
        obj = json.loads(body)
    except Exception:
        raise ZohoError(f"Token endpoint returned a non-JSON response (HTTP {status}).")
    tok = obj.get("access_token")
    if not tok:
        raise ZohoError("Zoho refused the token request: " +
                        str(obj.get("error") or obj.get("message") or f"HTTP {status}"))
    return tok


def fetch_records(conn, http_post=None, http_get=None):
    """conn: dict with dc, owner, app, report. Returns a list of record dicts.
    GET only against the data API; never writes."""
    http_get = http_get or _real_get
    dc = conn.get("dc") or "com"
    if dc not in DATA_CENTERS:
        raise ZohoError(f"Unknown Zoho data centre {dc!r}")
    for k in ("owner", "app", "report"):
        if not conn.get(k):
            raise ZohoError("Zoho connection is incomplete — set the owner, app and report in settings.")
    token = get_access_token(dc, http_post)
    api = _api_host(dc)
    base = (f"https://{api}/creator/v2.1/data/"
            + "/".join(urllib.parse.quote(conn[k], safe="") for k in ("owner", "app"))
            + "/report/" + urllib.parse.quote(conn["report"], safe=""))
    headers = {"Authorization": "Zoho-oauthtoken " + token}
    records, start = [], 0
    while len(records) < MAX_RECORDS:
        url = base + f"?from={start + 1}&limit={_PAGE}"
        _check_host(url, api)
        status, body = http_get(url, headers)
        if status == 404 or (status == 400 and "no records" in body.lower()):
            break
        try:
            obj = json.loads(body)
        except Exception:
            raise ZohoError(f"Data API returned a non-JSON response (HTTP {status}).")
        code = obj.get("code")
        if code == 3100:            # Zoho's "no more records"
            break
        if code not in (3000, None):
            raise ZohoError("Zoho data API error: " + str(obj.get("message") or code))
        chunk = obj.get("data") or []
        if not isinstance(chunk, list) or not chunk:
            break
        records.extend(chunk)
        if len(chunk) < _PAGE:
            break
        start += len(chunk)
    return records[:MAX_RECORDS]


def map_records(records, mapping):
    """Turn Zoho records into classified asset dicts using the field mapping
    (canonical field -> Zoho field name). Reuses asset_classify so OT governance
    and types match a normal import. Records with neither ip nor hostname are
    skipped."""
    out = []
    for rec in records:
        if not isinstance(rec, dict):
            continue
        row = {}
        for canon, _label in MAP_FIELDS:
            zf = (mapping or {}).get(canon)
            if zf:
                val = rec.get(zf, "")
                # Zoho can return nested objects (e.g. lookups) — take a string
                if isinstance(val, dict):
                    val = val.get("display_value") or val.get("zc_display_value") or ""
                row[canon] = str(val).strip()
        if not (row.get("ip") or row.get("hostname")):
            continue
        out.append(asset_classify.classify(row))
    return out


def _self_test():
    # fake token + data transports — no network, no creds
    os.environ["ARGUS_ZOHO_CLIENT_ID"] = "cid"
    os.environ["ARGUS_ZOHO_CLIENT_SECRET"] = "sec"
    os.environ["ARGUS_ZOHO_REFRESH_TOKEN"] = "rt"
    assert secrets_configured()

    posts = []
    def fake_post(url, data, headers=None, timeout=30):
        posts.append((url, data))
        assert url.startswith("https://accounts.zoho.com/")        # token host only
        assert data["grant_type"] == "refresh_token"
        return 200, json.dumps({"access_token": "AT123"})

    pages = [
        json.dumps({"code": 3000, "data": [{"IP": "10.0.0.1", "Name": "web-01", "Crit": "High", "Kind": "Server"}]}),
        json.dumps({"code": 3100}),   # no more
    ]
    gets = []
    def fake_get(url, headers=None, timeout=30):
        gets.append(url)
        assert url.startswith("https://www.zohoapis.com/creator/v2.1/data/")  # GET data only
        assert headers["Authorization"] == "Zoho-oauthtoken AT123"
        return 200, pages[len(gets) - 1]

    conn = {"dc": "com", "owner": "patricia", "app": "assets_app", "report": "All_Assets"}
    recs = fetch_records(conn, http_post=fake_post, http_get=fake_get)
    assert len(recs) == 1 and recs[0]["IP"] == "10.0.0.1", recs
    assert len(posts) == 1    # exactly one token exchange

    mapping = {"ip": "IP", "hostname": "Name", "criticality": "Crit", "type": "Kind"}
    assets = map_records(recs, mapping)
    assert len(assets) == 1
    a = assets[0]
    assert a["ip"] == "10.0.0.1" and a["hostname"] == "web-01"
    assert a["criticality"] == "High" and a["scan_eligible"] == 1

    # an OT record is classified do-not-scan, exactly like an import
    ot = map_records([{"IP": "10.0.9.9", "Name": "plc-7", "Kind": "OT"}],
                     {"ip": "IP", "hostname": "Name", "type": "Kind"})
    assert ot[0]["scan_eligible"] == 0, ot

    # host-pinning: a tampered conn can't redirect the request elsewhere
    try:
        _check_host("https://evil.example/x", "www.zohoapis.com")
        assert False
    except ZohoError:
        pass

    # bad refresh token surfaces cleanly
    def bad_post(url, data, headers=None, timeout=30):
        return 400, json.dumps({"error": "invalid_code"})
    try:
        get_access_token("com", http_post=bad_post); assert False
    except ZohoError as e:
        assert "invalid_code" in str(e)
    print("zoho self-tests passed")


if __name__ == "__main__":
    _self_test()
