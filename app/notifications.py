"""
notifications.py, in-system notifications + assignment emails.

When a finding is assigned to an owner, the people behind that owner are
notified two ways:

  * an in-app notification (the bell in the top bar), and
  * an email, when a mail server is configured (reuses delivery.EmailProvider).

An owner is either a single user-backed owner or a team with members, so
resolving "who to notify" walks asset_owners -> (user_id | team_members).
Everything takes an explicit db connection and an injectable email provider, so
it is unit-tested offline with no SMTP and no real accounts.
"""
from datetime import datetime

import delivery


def resolve_recipients(db, owner_name):
    """Return the active user rows behind an owner name (user-owner -> that user;
    team -> its members; otherwise a user whose name/username matches)."""
    name = (owner_name or "").strip()
    if not name:
        return []
    row = db.execute("SELECT * FROM asset_owners WHERE name=? COLLATE NOCASE", (name,)).fetchone()
    users = []
    if row:
        kind = (row["kind"] or "team")
        if kind == "user" and row["user_id"]:
            u = db.execute("SELECT * FROM users WHERE id=? AND active=1", (row["user_id"],)).fetchone()
            if u:
                users = [u]
        else:
            users = db.execute(
                "SELECT u.* FROM team_members tm JOIN users u ON u.id=tm.user_id "
                "WHERE tm.owner_id=? AND u.active=1", (row["id"],)).fetchall()
    if not users:
        # Fallback: the owner label is simply a user's name/username.
        u = db.execute(
            "SELECT * FROM users WHERE active=1 AND "
            "(display_name=? COLLATE NOCASE OR username=? COLLATE NOCASE)",
            (name, name)).fetchone()
        if u:
            users = [u]
    seen, out = set(), []
    for u in users:
        if u["id"] in seen:
            continue
        seen.add(u["id"])
        out.append(u)
    return out


def create(db, user_id, title, body, link="", kind="assignment", now=None):
    now = now or datetime.now().isoformat(timespec="seconds")
    db.execute(
        "INSERT INTO notifications(user_id, kind, title, body, link, read, created_at) "
        "VALUES (?,?,?,?,?,0,?)",
        (user_id, kind, title, body, link, now))
    db.commit()


def notify_assignment(db, owner_name, finding, assigned_by, base_url="",
                      email_provider=None, exclude_user_id=None, now=None):
    """Notify everyone behind `owner_name` that `finding` was assigned to them.

    `finding` is a row/dict with id, ip_hostname, vulnerability, reported_risk.
    Returns a summary dict. Never raises on email failure, in-app always lands.
    """
    recips = resolve_recipients(db, owner_name)
    res = {"recipients": 0, "in_app": 0, "emailed": 0, "errors": []}
    if not recips:
        return res
    now = now or datetime.now().isoformat(timespec="seconds")
    fid = finding["id"]
    host = (finding["ip_hostname"] or "an asset")
    vuln = (finding["vulnerability"] or "a finding")
    risk = (finding["reported_risk"] or "")
    link = (base_url.rstrip("/") if base_url else "") + "/finding/%s/edit" % fid
    title = "A finding was assigned to you"
    body = (f"{assigned_by} assigned you a finding on {host}: {vuln}"
            + (f" (risk: {risk})." if risk else "."))
    prov = email_provider if email_provider is not None else delivery.EmailProvider()
    ready = False
    try:
        ready = prov.ready()
    except Exception:
        ready = False
    for u in recips:
        if exclude_user_id and u["id"] == exclude_user_id:
            continue
        create(db, u["id"], title, body, link, kind="assignment", now=now)
        res["in_app"] += 1
        email = (u["email"] or "").strip()
        if email and ready:
            try:
                ok, err = prov.send(email, f"[Argus] Finding assigned on {host}",
                                    body + f"\n\nOpen it in Argus: {link}")
            except Exception as e:
                ok, err = False, f"{type(e).__name__}: {e}"
            if ok:
                res["emailed"] += 1
            else:
                res["errors"].append(f"{email}: {err}")
    res["recipients"] = res["in_app"]
    return res


def unread_count(db, user_id):
    return db.execute("SELECT COUNT(*) FROM notifications WHERE user_id=? AND read=0",
                      (user_id,)).fetchone()[0]


def recent(db, user_id, limit=20):
    return db.execute(
        "SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC, id DESC LIMIT ?",
        (user_id, limit)).fetchall()


def mark_all_read(db, user_id):
    db.execute("UPDATE notifications SET read=1 WHERE user_id=? AND read=0", (user_id,))
    db.commit()


def mark_read(db, user_id, nid):
    db.execute("UPDATE notifications SET read=1 WHERE id=? AND user_id=?", (nid, user_id))
    db.commit()


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sqlite3

    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.executescript("""
        CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, display_name TEXT,
                           email TEXT, active INTEGER DEFAULT 1);
        CREATE TABLE asset_owners(id INTEGER PRIMARY KEY, name TEXT, kind TEXT, user_id INTEGER);
        CREATE TABLE team_members(owner_id INTEGER, user_id INTEGER);
        CREATE TABLE notifications(id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
                           kind TEXT, title TEXT, body TEXT, link TEXT, read INTEGER DEFAULT 0, created_at TEXT);
    """)
    db.execute("INSERT INTO users(id,username,display_name,email) VALUES (1,'ama','Ama Mensah','ama@x.co')")
    db.execute("INSERT INTO users(id,username,display_name,email) VALUES (2,'kofi','Kofi B','kofi@x.co')")
    db.execute("INSERT INTO users(id,username,display_name,email) VALUES (3,'yaa','Yaa','')")
    # a user-owner and a team
    db.execute("INSERT INTO asset_owners(id,name,kind,user_id) VALUES (10,'Ama Mensah','user',1)")
    db.execute("INSERT INTO asset_owners(id,name,kind,user_id) VALUES (20,'Network Team','team',NULL)")
    db.execute("INSERT INTO team_members(owner_id,user_id) VALUES (20,2)")
    db.execute("INSERT INTO team_members(owner_id,user_id) VALUES (20,3)")
    db.commit()

    class FakeProvider:
        def __init__(self): self.sent = []
        def ready(self): return True
        def send(self, to, subj, body): self.sent.append((to, subj)); return True, ""

    # user-owner -> 1 recipient
    assert [u["id"] for u in resolve_recipients(db, "Ama Mensah")] == [1]
    # team -> its members
    assert sorted(u["id"] for u in resolve_recipients(db, "Network Team")) == [2, 3]
    # fallback by username
    assert [u["id"] for u in resolve_recipients(db, "kofi")] == [2]

    fp = FakeProvider()
    finding = {"id": 7, "ip_hostname": "10.0.0.5", "vulnerability": "Open SSH", "reported_risk": "High"}
    r = notify_assignment(db, "Network Team", finding, "Patricia", base_url="http://host:5000/", email_provider=fp)
    assert r["in_app"] == 2, r                      # both members notified in-app
    assert r["emailed"] == 1, r                     # only kofi has an email (yaa has none)
    assert unread_count(db, 2) == 1 and unread_count(db, 3) == 1
    assert fp.sent and fp.sent[0][0] == "kofi@x.co"

    # not configured -> in-app still lands, no email
    class NotReady(FakeProvider):
        def ready(self): return False
    r2 = notify_assignment(db, "Ama Mensah", finding, "Patricia", email_provider=NotReady())
    assert r2["in_app"] == 1 and r2["emailed"] == 0, r2
    mark_all_read(db, 1)
    assert unread_count(db, 1) == 0
    print("notifications self-test passed")
