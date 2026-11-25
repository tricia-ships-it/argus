"""
VAPT Assessment & Remediation Tracker — offline Flask application.

Runs entirely on the internal network. No internet calls, no telemetry, no outbound data.
Data lives in a local SQLite file (vapt.db) next to this script.

Usage:
    pip install flask openpyxl   # one-time, on a machine that can reach PyPI,
                                 # or install from an offline wheel cache
    python app.py                # serves on http://127.0.0.1:5000 by default

Bind to the internal interface for team access, e.g.:
    python app.py --host 10.0.0.5 --port 8080
"""
import argparse
import io
import os
import re
import sqlite3
from datetime import date, datetime

from flask import (
    Flask, g, render_template, request, redirect, url_for,
    jsonify, send_file, abort, flash, session,
)

import engine
import cvss as cvss_mod
import cred_audit
import notifications
from parsers import detect_and_parse
import scanner as scanner_mod
import auth
import compliance
import asset_classify
import threatintel
import phishing
import delivery
import sending
import snapshots
import zoho
import csv as _csv
import json as _json
import threading
import time
import uuid
from datetime import timedelta

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "vapt.db")
APP_VERSION = "1.0"

app = Flask(__name__)
app.secret_key = auth.load_or_create_secret(APP_DIR)
app.permanent_session_lifetime = timedelta(hours=12)
auth.register_db_getter(lambda: get_db())

# --- session cookie hardening -------------------------------------------------
# HttpOnly keeps the cookie out of JS; SameSite=Lax blocks it on cross-site POSTs
# (a strong CSRF mitigation on its own); Secure is enabled when serving over
# HTTPS — set VAPT_HTTPS=1 behind a TLS reverse proxy.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("VAPT_HTTPS", "") in ("1", "true", "yes"),
    MAX_CONTENT_LENGTH=64 * 1024 * 1024,  # cap uploads at 64 MB
)

import secrets as _secrets

# --- CSRF protection ----------------------------------------------------------
# Session-bound token, required on every state-changing (non-GET) request.
# SameSite=Lax already blocks cross-site form POSTs; this token defends the
# JSON/fetch endpoints and gives defence-in-depth against same-site attacks.
CSRF_EXEMPT = set()  # none currently


def csrf_token():
    tok = session.get("_csrf")
    if not tok:
        tok = _secrets.token_urlsafe(32)
        session["_csrf"] = tok
    return tok


@app.before_request
def _csrf_protect():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.endpoint in CSRF_EXEMPT:
        return
    sent = (request.form.get("_csrf")
            or request.headers.get("X-CSRF-Token")
            or (request.get_json(silent=True) or {}).get("_csrf"))
    if not sent or sent != session.get("_csrf"):
        abort(400, description="Invalid or missing CSRF token. Reload the page and try again.")


@app.before_request
def _require_first_run_setup():
    # Until the first account exists, send everything to the setup page so the
    # admin can create their own profile. Static assets and the setup endpoint
    # itself are exempt.
    if request.endpoint in ("setup", "static") or request.endpoint is None:
        return
    if auth.needs_setup(get_db()):
        return redirect(url_for("setup"))


@app.after_request
def _security_headers(resp):
    # The same headers the scanner flags when missing on a host — set them here.
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    # Self-only CSP: the UI uses only same-origin assets and inline scripts.
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
    )
    return resp


@app.context_processor
def _inject_csrf():
    return {"csrf_token": csrf_token}

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
# Input columns are stored; derived columns (actual_risk, target_fix_date,
# time_to_fix, risk_tolerance_objective) are computed by engine.py on read,
# so the logic lives in exactly one place.
INPUT_COLUMNS = [
    "ip_hostname", "device", "asset_classification", "vulnerability",
    "synopsis", "definition", "cve", "risk_statement", "reported_risk",
    "exploit_available", "exploit_reference", "solution", "asset_owner",
    "detection_date", "remediation_status", "actual_fix_date",
    "exception_requested", "exception_approved_by", "revised_target_fix_date",
    "asset_owners_comment", "comment", "source_tool",
]
DATE_COLUMNS = {"detection_date", "actual_fix_date", "revised_target_fix_date"}


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT,
            scan_date TEXT,
            source_tool TEXT,
            imported_at TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            ip_hostname TEXT, device TEXT, asset_classification TEXT,
            vulnerability TEXT, synopsis TEXT, definition TEXT, cve TEXT,
            risk_statement TEXT, reported_risk TEXT, exploit_available TEXT,
            exploit_reference TEXT, solution TEXT, asset_owner TEXT,
            detection_date TEXT, remediation_status TEXT DEFAULT 'Pending',
            actual_fix_date TEXT, exception_requested TEXT DEFAULT 'No',
            exception_approved_by TEXT, revised_target_fix_date TEXT,
            asset_owners_comment TEXT, comment TEXT, source_tool TEXT,
            cvss_score REAL, cvss_vector TEXT,
            created_at TEXT, updated_at TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        );
        CREATE TABLE IF NOT EXISTS asset_owners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE
        );
        -- Members of a team owner (asset_owners.kind='team').
        CREATE TABLE IF NOT EXISTS team_members (
            owner_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            PRIMARY KEY (owner_id, user_id),
            FOREIGN KEY(owner_id) REFERENCES asset_owners(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        -- In-system notifications (assignment alerts, etc.).
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            kind TEXT, title TEXT, body TEXT, link TEXT,
            read INTEGER NOT NULL DEFAULT 0,
            created_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS evidence (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER,
            filename TEXT, mime TEXT, size INTEGER,
            data BLOB, uploaded_by INTEGER, created_at TEXT,
            FOREIGN KEY(finding_id) REFERENCES findings(id)
        );
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT, hostname TEXT, description TEXT, owner TEXT,
            criticality TEXT, asset_type TEXT, scan_policy TEXT,
            scan_eligible INTEGER DEFAULT 1, classify_reason TEXT,
            authorized_by TEXT, authorized_at TEXT,
            source TEXT, created_at TEXT, updated_at TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT
        );
        CREATE TABLE IF NOT EXISTS threat_feed (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cve TEXT, title TEXT, products TEXT, severity TEXT, source TEXT,
            kev INTEGER, date TEXT, summary TEXT, imported_at TEXT
        );
        CREATE TABLE IF NOT EXISTS threat_source (
            id TEXT PRIMARY KEY, name TEXT, url TEXT, kind TEXT,
            enabled INTEGER DEFAULT 1, added_by TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS threat_source_health (
            source_id TEXT PRIMARY KEY, status TEXT, detail TEXT,
            records INTEGER DEFAULT 0, checked_at TEXT
        );
        CREATE TABLE IF NOT EXISTS scan_schedule (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, targets TEXT, profile TEXT DEFAULT 'standard', ports TEXT,
            interval_hours INTEGER DEFAULT 168,
            do_tls INTEGER DEFAULT 1, do_http INTEGER DEFAULT 1, assume_up INTEGER DEFAULT 0,
            default_owner TEXT, default_classification TEXT,
            enabled INTEGER DEFAULT 1,
            next_run TEXT, last_run TEXT, last_result TEXT,
            created_by TEXT, created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS phish_campaign (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT, template_key TEXT, sender TEXT, subject TEXT,
            body TEXT, landing_note TEXT,
            channel TEXT DEFAULT 'email',
            authorized INTEGER DEFAULT 0, authorized_by TEXT, authorized_at TEXT,
            status TEXT DEFAULT 'Draft',
            created_by INTEGER, created_at TEXT,
            launched_at TEXT, closed_at TEXT
        );
        CREATE TABLE IF NOT EXISTS phish_recipient (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER,
            name TEXT, email TEXT, department TEXT,
            phone TEXT, handle TEXT, grp TEXT,
            token TEXT UNIQUE,
            clicked_at TEXT, reported_at TEXT, click_count INTEGER DEFAULT 0,
            sent_at TEXT, delivery_status TEXT, delivery_error TEXT,
            FOREIGN KEY(campaign_id) REFERENCES phish_campaign(id)
        );
        CREATE TABLE IF NOT EXISTS phish_event (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_id INTEGER, campaign_id INTEGER,
            kind TEXT, at TEXT, user_agent TEXT,
            FOREIGN KEY(recipient_id) REFERENCES phish_recipient(id)
        );
        CREATE TABLE IF NOT EXISTS shared_snapshot (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT, source TEXT, generated_at TEXT, generated_by TEXT,
            app_version TEXT, integrity_ok INTEGER, payload TEXT,
            imported_by TEXT, imported_at TEXT
        );
        CREATE TABLE IF NOT EXISTS phish_send_job (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            campaign_id INTEGER, channel TEXT, status TEXT,
            total INTEGER, processed INTEGER DEFAULT 0,
            ok_count INTEGER DEFAULT 0, fail_count INTEGER DEFAULT 0,
            rate_per_min INTEGER DEFAULT 30, scheduled_at TEXT,
            include_sent INTEGER DEFAULT 0, base_url TEXT, groups TEXT,
            created_by TEXT, created_at TEXT,
            started_at TEXT, finished_at TEXT, last_error TEXT,
            FOREIGN KEY(campaign_id) REFERENCES phish_campaign(id)
        );
        """
    )
    # WAL lets the background send worker write progress while web requests
    # read, without 'database is locked' contention.
    try:
        db.execute("PRAGMA journal_mode=WAL")
    except sqlite3.Error:
        pass
    # lightweight migrations: add columns that newer versions introduced to
    # tables that already exist in an older deployment's database.
    def _ensure_cols(table, cols):
        have = {r[1] for r in db.execute(f"PRAGMA table_info({table})")}
        for name, ddl in cols.items():
            if name not in have:
                db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
    _ensure_cols("phish_campaign", {
        "channel": "channel TEXT DEFAULT 'email'",
        "authorized": "authorized INTEGER DEFAULT 0",
        "authorized_by": "authorized_by TEXT",
        "authorized_at": "authorized_at TEXT",
    })
    _ensure_cols("phish_recipient", {
        "phone": "phone TEXT", "handle": "handle TEXT",
        "sent_at": "sent_at TEXT", "delivery_status": "delivery_status TEXT",
        "delivery_error": "delivery_error TEXT", "grp": "grp TEXT",
    })
    _ensure_cols("phish_send_job", {"groups": "groups TEXT"})
    _ensure_cols("findings", {
        "cvss_score": "cvss_score REAL",
        "cvss_vector": "cvss_vector TEXT",
    })
    # Owners become either a user-backed owner or a team with members.
    _ensure_cols("asset_owners", {
        "kind": "kind TEXT DEFAULT 'team'",
        "user_id": "user_id INTEGER",
        "email": "email TEXT",
    })
    # seed a few default owners if empty
    cur = db.execute("SELECT COUNT(*) FROM asset_owners")
    if cur.fetchone()[0] == 0:
        for n in ["Network Team", "Systems Team", "Security Team", "Unassigned"]:
            db.execute("INSERT OR IGNORE INTO asset_owners(name) VALUES (?)", (n,))
    db.commit()
    # auth tables — the first administrator is created via first-run web setup
    auth.init_auth_schema(db)
    setup_needed = auth.needs_setup(db)
    db.close()
    return setup_needed  # True on a brand-new install (no accounts yet)


@app.context_processor
def inject_user():
    """Make the current user and permission helpers available in every template."""
    try:
        u = auth.current_user(get_db())
    except Exception:
        u = None
    notif_items, notif_unread = [], 0
    if u:
        try:
            db = get_db()
            notif_items = notifications.recent(db, u["id"], limit=12)
            notif_unread = notifications.unread_count(db, u["id"])
        except Exception:
            notif_items, notif_unread = [], 0
    return {
        "current_user": u,
        "is_admin": auth.is_admin(u),
        "can_import_or_scan": auth.can_import_or_scan(u),
        "role_labels": auth.ROLE_LABELS,
        "notif_items": notif_items,
        "notif_unread": notif_unread,
    }


# ---------------------------------------------------------------------------
# Helpers: date parsing, row enrichment
# ---------------------------------------------------------------------------
def parse_date(s):
    if not s:
        return None
    if isinstance(s, (date, datetime)):
        return s.date() if isinstance(s, datetime) else s
    s = str(s).strip()
    for fmt in ("%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%b %d, %Y", "%d-%b-%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            continue
    return None


def iso(d):
    return d.isoformat() if d else None


def fmt_display(d):
    return d.strftime("%b %d, %Y") if d else ""


def enrich(row):
    """Row (sqlite Row) -> dict with derived fields computed by the engine."""
    r = dict(row)
    inp = {
        "asset_classification": r.get("asset_classification"),
        "reported_risk": r.get("reported_risk"),
        "exploit_available": r.get("exploit_available"),
        "detection_date": parse_date(r.get("detection_date")),
        "remediation_status": r.get("remediation_status"),
        "actual_fix_date": parse_date(r.get("actual_fix_date")),
        "revised_target_fix_date": parse_date(r.get("revised_target_fix_date")),
    }
    derived = engine.compute_row(inp)
    r["actual_risk_classification"] = derived["actual_risk_classification"] or ""
    r["target_fix_date"] = fmt_display(derived["target_fix_date"])
    r["target_fix_date_iso"] = iso(derived["target_fix_date"])
    r["time_to_fix_days"] = derived["time_to_fix_days"] if derived["time_to_fix_days"] is not None else ""
    r["risk_tolerance_objective"] = derived["risk_tolerance_objective"] or ""
    # display versions of stored dates
    r["detection_date_disp"] = fmt_display(parse_date(r.get("detection_date")))
    r["actual_fix_date_disp"] = fmt_display(parse_date(r.get("actual_fix_date")))
    r["revised_target_fix_date_disp"] = fmt_display(parse_date(r.get("revised_target_fix_date")))
    # CVSS display helpers (score may be absent for non-CVE findings)
    score = cvss_mod.clamp_score(r.get("cvss_score"))
    r["cvss_score"] = score
    r["cvss_score_disp"] = ("%.1f" % score) if score is not None else ""
    r["cvss_severity"] = cvss_mod.severity_band(score)
    r["cvss_breakdown"] = cvss_mod.parse_vector(r.get("cvss_vector") or "")
    return r


def owner_list():
    db = get_db()
    return [row["name"] for row in db.execute("SELECT name FROM asset_owners ORDER BY name")]


def owner_directory():
    """Owners with their kind and (for user-owners) the linked user, and member
    counts for teams — for the owners management page and pickers."""
    db = get_db()
    rows = db.execute(
        "SELECT o.*, u.display_name AS u_name, u.username AS u_username, u.email AS u_email, "
        "(SELECT COUNT(*) FROM team_members tm WHERE tm.owner_id=o.id) AS members "
        "FROM asset_owners o LEFT JOIN users u ON u.id=o.user_id ORDER BY o.name"
    ).fetchall()
    return rows


def _flash_assignment(r, owner_name):
    """Surface the outcome of an assignment notification to the person who did it."""
    if not r or not r.get("in_app"):
        return
    bits = [f"Notified {owner_name}"]
    if r.get("emailed"):
        bits.append(f"{r['emailed']} email{'' if r['emailed'] == 1 else 's'} sent")
    if r.get("errors"):
        bits.append(f"{len(r['errors'])} email(s) couldn't send — check mail settings")
    flash(" · ".join(bits) + ".")


# ---------------------------------------------------------------------------
# Routes: authentication
# ---------------------------------------------------------------------------
# Simple in-memory login throttle: lock an IP for a spell after repeated misses.
_LOGIN_FAILS = {}  # ip -> [count, first_ts]
_LOGIN_MAX = 8
_LOGIN_WINDOW = 300  # seconds


def _safe_next(target):
    """Allow only same-site relative paths, never absolute/scheme-relative URLs."""
    if not target:
        return None
    if target.startswith("//") or "://" in target or "\\" in target:
        return None
    if not target.startswith("/"):
        return None
    return target


@app.route("/setup", methods=["GET", "POST"])
def setup():
    db = get_db()
    # Setup is only available before the first account exists.
    if not auth.needs_setup(db):
        return redirect(url_for("login"))
    if request.method == "POST":
        display = request.form.get("display_name", "").strip()
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        pw = request.form.get("password", "")
        pw2 = request.form.get("confirm", "")
        err = None
        if not display or not username:
            err = "Please provide your name and a username."
        elif " " in username:
            err = "Username can't contain spaces."
        elif len(pw) < 8:
            err = "Password must be at least 8 characters."
        elif pw != pw2:
            err = "The two passwords don't match."
        if err:
            flash(err)
            return render_template("setup.html", form=request.form)
        uid = auth.create_user(db, username, display, email, pw, "admin", must_change=False)
        u = auth.get_user(db, uid)
        auth.login_user(u)
        auth.log_activity(db, uid, None, "setup", "First-run administrator account created")
        flash("Welcome to Argus — your administrator account is ready.")
        return redirect(url_for("index"))
    return render_template("setup.html", form={})


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    if request.method == "POST":
        import time as _t
        ip = request.remote_addr or "?"
        rec = _LOGIN_FAILS.get(ip)
        if rec and rec[0] >= _LOGIN_MAX and (_t.time() - rec[1]) < _LOGIN_WINDOW:
            flash("Too many failed attempts. Wait a few minutes and try again.")
            return render_template("login.html", username="")
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        u = auth.verify_login(db, username, password)
        if not u:
            r = _LOGIN_FAILS.get(ip)
            if not r or (_t.time() - r[1]) >= _LOGIN_WINDOW:
                _LOGIN_FAILS[ip] = [1, _t.time()]
            else:
                r[0] += 1
            flash("Incorrect username or password, or the account is inactive.")
            return render_template("login.html", username=username)
        _LOGIN_FAILS.pop(ip, None)
        auth.login_user(u)
        auth.log_activity(db, u["id"], None, "login", "")
        if u["must_change_pw"]:
            return redirect(url_for("change_password"))
        nxt = _safe_next(request.args.get("next")) or url_for("index")
        return redirect(nxt)
    if auth.current_user(db):
        return redirect(url_for("index"))
    return render_template("login.html", username="")


@app.route("/logout")
def logout():
    auth.logout_user()
    return redirect(url_for("login"))


@app.route("/account/password", methods=["GET", "POST"])
@auth.login_required
def change_password():
    db = get_db()
    u = auth.current_user(db)
    if request.method == "POST":
        cur = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        if not auth.verify_login(db, u["username"], cur):
            flash("Your current password is incorrect.")
        elif len(new) < 8:
            flash("New password must be at least 8 characters.")
        elif new != confirm:
            flash("New passwords don't match.")
        else:
            was_forced = bool(u["must_change_pw"])
            auth.set_password(db, u["id"], new)
            if was_forced:
                # First-login password change: sign them out so they sign back
                # in with the new password themselves.
                auth.logout_user()
                flash("Password set. Please sign in with your new password.")
                return redirect(url_for("login"))
            flash("Password updated.")
            return redirect(url_for("index"))
    return render_template("change_password.html", must_change=bool(u["must_change_pw"]))


# ---------------------------------------------------------------------------
# Routes: user management (admin only)
# ---------------------------------------------------------------------------
@app.route("/users")
@auth.role_required("admin")
def users():
    db = get_db()
    rows = db.execute(
        "SELECT u.*, ("
        "  SELECT MAX(created_at) FROM activity a WHERE a.user_id = u.id"
        ") AS last_active FROM users u ORDER BY "
        "CASE role WHEN 'admin' THEN 0 WHEN 'editor' THEN 1 ELSE 2 END, username").fetchall()
    me = auth.current_user(db)
    stats = {
        "total": len(rows),
        "admins": sum(1 for r in rows if r["role"] == "admin"),
        "active": sum(1 for r in rows if r["active"]),
        "inactive": sum(1 for r in rows if not r["active"]),
    }
    return render_template("users.html", users=rows, roles=auth.ROLES,
                           role_labels=auth.ROLE_LABELS, stats=stats,
                           permissions=auth.PERMISSION_MATRIX, me_id=me["id"] if me else None)


@app.route("/users/<int:uid>/delete", methods=["POST"])
@auth.role_required("admin")
def users_delete(uid):
    db = get_db()
    me = auth.current_user(db)
    if me and me["id"] == uid:
        flash("You can't delete your own account.")
        return redirect(url_for("users"))
    target = db.execute("SELECT username, role FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        abort(404)
    # never remove the last admin — the system must keep at least one
    if target["role"] == "admin":
        n_admin = db.execute("SELECT COUNT(*) n FROM users WHERE role='admin' AND active=1").fetchone()["n"]
        if n_admin <= 1:
            flash("Can't delete the only admin account. Make another user an admin first.")
            return redirect(url_for("users"))
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    auth.log_activity(db, me["id"], None, "users", f"deleted account '{target['username']}'")
    flash(f"Account '{target['username']}' deleted.")
    return redirect(url_for("users"))


@app.route("/users/add", methods=["POST"])
@auth.role_required("admin")
def users_add():
    db = get_db()
    username = request.form.get("username", "").strip()
    display = request.form.get("display_name", "").strip()
    email = request.form.get("email", "").strip()
    role = request.form.get("role", "viewer")
    password = request.form.get("password", "")
    if not username or not password:
        flash("Username and an initial password are required.")
        return redirect(url_for("users"))
    if role not in auth.ROLES:
        role = "viewer"
    if auth.get_user_by_username(db, username):
        flash("That username already exists.")
        return redirect(url_for("users"))
    auth.create_user(db, username, display or username, email, password, role)
    flash(f"Account created for {username}. Share the initial password securely; they can change it after signing in.")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/role", methods=["POST"])
@auth.role_required("admin")
def users_role(uid):
    db = get_db()
    role = request.form.get("role", "viewer")
    if role in auth.ROLES:
        db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
        db.commit()
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/active", methods=["POST"])
@auth.role_required("admin")
def users_active(uid):
    db = get_db()
    me = auth.current_user(db)
    if me and me["id"] == uid:
        flash("You can't deactivate your own account.")
        return redirect(url_for("users"))
    cur = db.execute("SELECT active FROM users WHERE id=?", (uid,)).fetchone()
    if cur is not None:
        db.execute("UPDATE users SET active=? WHERE id=?", (0 if cur["active"] else 1, uid))
        db.commit()
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/reset", methods=["POST"])
@auth.role_required("admin")
def users_reset(uid):
    db = get_db()
    newpw = request.form.get("password", "").strip()
    if len(newpw) < 8:
        flash("Reset password must be at least 8 characters.")
        return redirect(url_for("users"))
    auth.set_password(db, uid, newpw, clear_must_change=False)
    db.execute("UPDATE users SET must_change_pw=1 WHERE id=?", (uid,))
    db.commit()
    flash("Password reset. The user will be asked to set a new one at next sign-in.")
    return redirect(url_for("users"))


# ---------------------------------------------------------------------------
# Routes: dashboard & findings table
# ---------------------------------------------------------------------------
@app.route("/")
@auth.login_required
def index():
    db = get_db()
    q = request.args.get("q", "").strip()
    status = request.args.get("status", "").strip()
    risk = request.args.get("risk", "").strip()
    breach = request.args.get("breach", "").strip()
    sql = "SELECT * FROM findings WHERE 1=1"
    params = []
    if q:
        sql += " AND (ip_hostname LIKE ? OR vulnerability LIKE ? OR cve LIKE ?)"
        params += [f"%{q}%", f"%{q}%", f"%{q}%"]
    if status:
        sql += " AND remediation_status = ?"
        params.append(status)
    sql += " ORDER BY id DESC"
    me = auth.current_user(db)
    raw_rows = db.execute(sql, params).fetchall()
    rows = []
    for raw in raw_rows:
        er = enrich(raw)
        er["can_edit"] = auth.can_edit_finding(me, raw, db)
        rows.append(er)
    if risk:
        rows = [r for r in rows if r["actual_risk_classification"] == risk]
    if breach:
        rows = [r for r in rows if r["risk_tolerance_objective"] == "Breached"]

    # stats
    all_rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    stats = {
        "total": len(all_rows),
        "critical": sum(1 for r in all_rows if r["actual_risk_classification"] == "Critical"),
        "high": sum(1 for r in all_rows if r["actual_risk_classification"] == "High"),
        "medium": sum(1 for r in all_rows if r["actual_risk_classification"] == "Medium"),
        "low": sum(1 for r in all_rows if r["actual_risk_classification"] == "Low"),
        "information": sum(1 for r in all_rows if r["actual_risk_classification"] == "Information"),
        "open": sum(1 for r in all_rows if r["remediation_status"] not in ("Fixed", "Not Applicable")),
        "breached": sum(1 for r in all_rows if r["risk_tolerance_objective"] == "Breached"),
        "overdue": sum(1 for r in all_rows if _is_overdue(r)),
    }
    return render_template(
        "index.html", rows=rows, stats=stats, owners=owner_list(),
        statuses=engine.REMEDIATION_STATUSES, severities=engine.SEVERITIES,
        exploits=engine.EXPLOIT_OPTIONS, q=q, status=status, risk=risk, breach=breach,
        today_iso=date.today().isoformat(),
    )


def _is_overdue(r):
    if r["remediation_status"] in ("Fixed", "Not Applicable", "Risk Accepted", "Exception Approved"):
        return False
    tfd = r.get("revised_target_fix_date_iso") or r.get("target_fix_date_iso")
    if not tfd:
        return False
    return parse_date(tfd) < date.today()


# ---------------------------------------------------------------------------
# Routes: dashboard (charts & summary for presentation)
# ---------------------------------------------------------------------------
@app.route("/dashboard")
@auth.login_required
def dashboard():
    return render_template("dashboard.html")


@app.route("/dashboard/data")
@auth.login_required
def dashboard_data():
    return jsonify(_dashboard_aggregates(get_db()))


# --- Shareable dashboard snapshots (export + import) -----------------------
@app.route("/dashboard/share")
@auth.login_required
def dashboard_share():
    """Export the current dashboard as a read-only snapshot file. Air-gap safe:
    plain data, no connection back, opens in another Argus or (later) a viewer."""
    db = get_db()
    me = auth.current_user(db)
    source = get_setting(db, "instance_label", "") or "Argus instance"
    title = (request.args.get("title") or f"{source} — dashboard").strip()[:160]
    js = snapshots.build(_dashboard_aggregates(db), title, source,
                         me["username"], APP_VERSION,
                         datetime.now().isoformat(timespec="seconds"))
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", source)[:40] or "argus"
    fname = f"argus-dashboard-{safe}-{date.today().isoformat()}.json"
    return send_file(io.BytesIO(js.encode("utf-8")), mimetype="application/json",
                     as_attachment=True, download_name=fname)


@app.route("/dashboard/shared")
@auth.login_required
def shared_list():
    db = get_db()
    rows = db.execute(
        "SELECT id, title, source, generated_at, generated_by, integrity_ok, "
        "imported_by, imported_at FROM shared_snapshot ORDER BY id DESC").fetchall()
    return render_template("shared_list.html", snapshots=rows,
                           can_manage=auth.can_import_or_scan(auth.current_user(db)))


@app.route("/dashboard/shared/import", methods=["POST"])
@auth.role_required("admin", "editor")
def shared_import():
    db = get_db()
    me = auth.current_user(db)
    f = request.files.get("snapshot")
    if not f or not f.filename:
        flash("Choose a snapshot file to open.")
        return redirect(url_for("shared_list"))
    raw = f.read(snapshots.MAX_BYTES + 1)   # bounded read
    try:
        snap = snapshots.parse(raw)
    except snapshots.SnapshotError as e:
        flash(f"Couldn't open that snapshot — {e}")
        return redirect(url_for("shared_list"))
    cur = db.execute(
        "INSERT INTO shared_snapshot(title, source, generated_at, generated_by, "
        "app_version, integrity_ok, payload, imported_by, imported_at) "
        "VALUES (?,?,?,?,?,?,?,?,?)",
        (snap["title"], snap["source"], snap["generated_at"], snap["generated_by"],
         snap["app_version"], 1 if snap["integrity_ok"] else 0,
         _json.dumps(snap["data"]), me["username"],
         datetime.now().isoformat(timespec="seconds")))
    db.commit()
    auth.log_activity(db, me["id"], None, "shared",
                      f"opened shared snapshot '{snap['title']}'")
    flash("Snapshot opened." + ("" if snap["integrity_ok"] else
          " Note: its checksum didn't match, so the numbers may have been changed in transit."))
    return redirect(url_for("shared_view", sid=cur.lastrowid))


@app.route("/dashboard/shared/<int:sid>")
@auth.login_required
def shared_view(sid):
    db = get_db()
    row = db.execute("SELECT * FROM shared_snapshot WHERE id=?", (sid,)).fetchone()
    if not row:
        abort(404)
    data = _json.loads(row["payload"])
    return render_template("shared_view.html", snap=row, data=data,
                           can_manage=auth.can_import_or_scan(auth.current_user(db)))


@app.route("/dashboard/shared/<int:sid>/delete", methods=["POST"])
@auth.role_required("admin", "editor")
def shared_delete(sid):
    db = get_db()
    me = auth.current_user(db)
    if not db.execute("SELECT 1 FROM shared_snapshot WHERE id=?", (sid,)).fetchone():
        abort(404)
    db.execute("DELETE FROM shared_snapshot WHERE id=?", (sid,))
    db.commit()
    auth.log_activity(db, me["id"], None, "shared", f"removed shared snapshot #{sid}")
    flash("Snapshot removed.")
    return redirect(url_for("shared_list"))


@app.route("/settings/instance", methods=["POST"])
@auth.role_required("admin")
def settings_instance():
    db = get_db()
    me = auth.current_user(db)
    set_setting(db, "instance_label", (request.form.get("instance_label") or "").strip()[:160])
    db.commit()
    auth.log_activity(db, me["id"], None, "settings", "updated instance label")
    flash("Instance label saved.")
    return redirect(url_for("settings_page"))


def _dashboard_aggregates(db):
    """Aggregations for the dashboard charts, computed from live findings."""
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    today = date.today()

    def counter(order):
        return {k: 0 for k in order}

    sev_order = ["Critical", "High", "Medium", "Low", "Information"]
    status_order = engine.REMEDIATION_STATUSES
    rto_order = ["Met", "Breached", "Not Applicable", "Open"]

    by_actual_risk = counter(sev_order)
    by_reported = counter(sev_order)
    by_status = counter(status_order)
    by_rto = counter(rto_order)
    by_exploit = {"Yes": 0, "No": 0, "Unknown": 0}
    owners = {}
    open_vs_closed = {"Open": 0, "Fixed": 0, "Not Applicable": 0}
    overdue = 0

    for r in rows:
        ar = r["actual_risk_classification"]
        if ar in by_actual_risk:
            by_actual_risk[ar] += 1
        rr = r["reported_risk"]
        if rr in by_reported:
            by_reported[rr] += 1
        st = r["remediation_status"] or "Pending"
        # count every status, even one outside the canonical list, so the
        # remediation chart always reconciles with the total finding count
        by_status[st] = by_status.get(st, 0) + 1
        rto = r["risk_tolerance_objective"]
        if rto in ("Met", "Breached", "Not Applicable"):
            by_rto[rto] += 1
        else:
            by_rto["Open"] += 1
        ex = r["exploit_available"] or "Unknown"
        by_exploit[ex] = by_exploit.get(ex, 0) + 1
        owner = r["asset_owner"] or "Unassigned"
        owners[owner] = owners.get(owner, 0) + 1
        if st == "Fixed":
            open_vs_closed["Fixed"] += 1
        elif st == "Not Applicable":
            open_vs_closed["Not Applicable"] += 1
        else:
            open_vs_closed["Open"] += 1
        if _is_overdue(r):
            overdue += 1

    # top owners by finding count (max 8)
    top_owners = sorted(owners.items(), key=lambda kv: kv[1], reverse=True)[:8]

    total = len(rows)
    crit = by_actual_risk["Critical"]
    high = by_actual_risk["High"]
    open_count = open_vs_closed["Open"]
    fixed = open_vs_closed["Fixed"]
    breached = by_rto["Breached"]
    # remediation rate = resolved / total
    resolved = fixed + open_vs_closed["Not Applicable"]
    rem_rate = round(100 * resolved / total) if total else 0

    return {
        "totals": {
            "total": total, "critical": crit, "high": high,
            "open": open_count, "fixed": fixed, "breached": breached,
            "overdue": overdue, "remediation_rate": rem_rate,
        },
        "by_actual_risk": by_actual_risk,
        "by_reported": by_reported,
        "by_status": {k: v for k, v in by_status.items() if v > 0},
        "by_rto": by_rto,
        "by_exploit": by_exploit,
        "top_owners": top_owners,
        "open_vs_closed": open_vs_closed,
    }


@app.route("/finding/new", methods=["GET", "POST"])
@auth.role_required("admin", "editor")
def finding_new():
    db = get_db()
    me = auth.current_user(db)
    if request.method == "POST":
        rec = _form_to_dict(request.form)
        rec.setdefault("source_tool", "Manual")
        _insert_finding(rec, scan_id=None)
        fid = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        auth.log_activity(db, me["id"], fid, "created",
                          request.form.get("vulnerability", "")[:120])
        owner = (rec.get("asset_owner") or "").strip()
        if owner:
            fresh = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
            r = notifications.notify_assignment(
                db, owner, fresh, me["display_name"] or me["username"],
                base_url=request.url_root, exclude_user_id=me["id"])
            _flash_assignment(r, owner)
        flash("Finding added.")
        return redirect(url_for("index"))
    return render_template(
        "finding_form.html", finding={}, owners=owner_list(),
        statuses=engine.REMEDIATION_STATUSES, severities=engine.SEVERITIES,
        exploits=engine.EXPLOIT_OPTIONS, is_new=True, comments=[], can_edit=True,
    )


@app.route("/finding/<int:fid>/edit", methods=["GET", "POST"])
@auth.login_required
def finding_edit(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    editable = auth.can_edit_finding(me, row, db)
    if request.method == "POST":
        if not editable:
            flash("You can view and comment on this finding, but only the security team or the asset owner can edit it.")
            return redirect(url_for("finding_edit", fid=fid))
        prev_status = row["remediation_status"]
        prev_owner = (row["asset_owner"] or "").strip()
        form_data = _form_to_dict(request.form)
        # A non-editor asset owner may update remediation progress only — not the
        # finding's classification, ownership, or the vulnerability details.
        if me["role"] not in ("admin", "editor"):
            allowed = {"remediation_status", "actual_fix_date", "exception_requested",
                       "exception_approved_by", "revised_target_fix_date",
                       "asset_owners_comment", "comment"}
            form_data = {k: v for k, v in form_data.items() if k in allowed}
        _update_finding(fid, form_data)
        fresh = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        if fresh["remediation_status"] != prev_status:
            auth.log_activity(db, me["id"], fid, "status",
                              f'{prev_status} → {fresh["remediation_status"]} on {row["ip_hostname"]}')
        else:
            auth.log_activity(db, me["id"], fid, "edited", row["ip_hostname"])
        # Notify the owner if ownership was just (re)assigned.
        new_owner = (fresh["asset_owner"] or "").strip()
        if new_owner and new_owner.lower() != prev_owner.lower():
            r = notifications.notify_assignment(
                db, new_owner, fresh, me["display_name"] or me["username"],
                base_url=request.url_root, exclude_user_id=me["id"])
            _flash_assignment(r, new_owner)
        flash("Finding updated.")
        return redirect(url_for("index"))
    comments = db.execute(
        "SELECT c.*, u.display_name, u.username, u.role FROM comments c "
        "JOIN users u ON u.id=c.user_id WHERE c.finding_id=? ORDER BY c.created_at", (fid,)
    ).fetchall()
    return render_template(
        "finding_form.html", finding=enrich(row), owners=owner_list(),
        statuses=engine.REMEDIATION_STATUSES, severities=engine.SEVERITIES,
        exploits=engine.EXPLOIT_OPTIONS, is_new=False, comments=comments, can_edit=editable,
    )


def _owner_names_for_user(db, user):
    """Lowercased owner labels that belong to this user: their own name/username,
    any user-owner linked to them, and teams they are a member of."""
    names = set()
    for k in ("display_name", "username"):
        v = (user[k] or "").strip().lower()
        if v:
            names.add(v)
    rows = db.execute(
        "SELECT o.name FROM asset_owners o WHERE (o.kind='user' AND o.user_id=?) "
        "OR o.id IN (SELECT owner_id FROM team_members WHERE user_id=?)",
        (user["id"], user["id"])).fetchall()
    for r in rows:
        if r["name"]:
            names.add(r["name"].strip().lower())
    return names


@app.route("/assigned")
@auth.login_required
def assigned_to_me():
    db = get_db()
    me = auth.current_user(db)
    names = _owner_names_for_user(db, me)
    rows = []
    if names:
        placeholders = ",".join("?" for _ in names)
        rows = db.execute(
            f"SELECT * FROM findings WHERE LOWER(TRIM(asset_owner)) IN ({placeholders}) "
            "ORDER BY detection_date DESC, id DESC", list(names)).fetchall()
    findings = [enrich(r) for r in rows]
    open_n = sum(1 for f in findings if f.get("remediation_status") not in engine.CLOSING_STATUSES)
    return render_template("assigned.html", findings=findings, open_n=open_n)


@app.route("/notifications/open/<int:nid>")
@auth.login_required
def notification_open(nid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM notifications WHERE id=? AND user_id=?", (nid, me["id"])).fetchone()
    notifications.mark_read(db, me["id"], nid)
    if row and row["link"]:
        from urllib.parse import urlparse
        path = urlparse(row["link"]).path or url_for("assigned_to_me")
        return redirect(path)
    return redirect(url_for("assigned_to_me"))


@app.route("/notifications/read-all", methods=["POST"])
@auth.login_required
def notifications_read_all():
    db = get_db()
    me = auth.current_user(db)
    notifications.mark_all_read(db, me["id"])
    return redirect(_safe_next(request.form.get("next")) or url_for("assigned_to_me"))


@app.route("/finding/<int:fid>/delete", methods=["POST"])
@auth.role_required("admin", "editor")
def finding_delete(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT ip_hostname, vulnerability FROM findings WHERE id=?", (fid,)).fetchone()
    db.execute("DELETE FROM findings WHERE id=?", (fid,))
    db.execute("DELETE FROM comments WHERE finding_id=?", (fid,))
    db.commit()
    if row:
        auth.log_activity(db, me["id"], None, "deleted", f'{row["ip_hostname"]}: {row["vulnerability"][:80]}')
    flash("Finding deleted.")
    return redirect(url_for("index"))


@app.route("/findings/recheck-exploitation", methods=["POST"])
@auth.role_required("admin", "editor")
def findings_recheck_kev():
    """Re-cross-reference every finding's CVE against the current threat feed.

    Run this after refreshing feeds: a CVE that has since been added to the KEV
    catalogue gets flagged as actively exploited, which escalates its actual
    risk through the existing risk matrix. Existing findings aren't downgraded
    here — this only promotes newly-exploited ones."""
    db = get_db()
    me = auth.current_user(db)
    feed_count = db.execute("SELECT COUNT(*) FROM threat_feed").fetchone()[0]
    if not feed_count:
        flash("No threat feed is loaded yet, so there's nothing to cross-reference. "
              "Update your threat sources first, then re-check.")
        return redirect(url_for("index"))
    rows = db.execute(
        "SELECT id, cve, definition, exploit_available FROM findings "
        "WHERE cve IS NOT NULL AND cve != ''"
    ).fetchall()
    now = datetime.now().isoformat(timespec="seconds")
    promoted = annotated = 0
    for r in rows:
        d = {"cve": r["cve"], "definition": r["definition"] or "",
             "exploit_available": r["exploit_available"] or ""}
        before_exploit, before_def = d["exploit_available"], d["definition"]
        _kev_crossref(db, d)
        if d["exploit_available"] == before_exploit and d["definition"] == before_def:
            continue
        if d["exploit_available"] == "Yes" and before_exploit != "Yes":
            promoted += 1
        else:
            annotated += 1
        db.execute(
            "UPDATE findings SET exploit_available=?, definition=?, updated_at=? WHERE id=?",
            (d["exploit_available"], d["definition"], now, r["id"]),
        )
    db.commit()
    auth.log_activity(db, me["id"], None, "rechecked exploitation",
                      f"{promoted} promoted to actively-exploited, {annotated} annotated")
    if promoted or annotated:
        flash(f"Exploitation re-check complete: {promoted} finding(s) flagged as actively "
              f"exploited (risk escalated), {annotated} annotated from the feed.")
    else:
        flash("Exploitation re-check complete: no findings matched the current threat feed.")
    return redirect(url_for("index"))


# Inline status update (AJAX) — auto-stamps actual_fix_date when closing.
@app.route("/finding/<int:fid>/status", methods=["POST"])
@auth.login_required
def finding_status(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    if not auth.can_edit_finding(me, row, db):
        return jsonify({"ok": False, "error": "no_permission"}), 403
    new_status = request.json.get("status")
    updates = {"remediation_status": new_status,
               "updated_at": datetime.now().isoformat(timespec="seconds")}
    # Auto-stamp Actual Fix Date the moment status becomes Fixed/Not Applicable,
    # but only if it isn't already set (stays editable afterward).
    if new_status in engine.CLOSING_STATUSES and not row["actual_fix_date"]:
        updates["actual_fix_date"] = date.today().isoformat()
    sets = ", ".join(f"{k}=?" for k in updates)
    db.execute(f"UPDATE findings SET {sets} WHERE id=?", (*updates.values(), fid))
    db.commit()
    auth.log_activity(db, me["id"], fid, "status",
                      f'{row["remediation_status"]} → {new_status} on {row["ip_hostname"]}')
    fresh = enrich(db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
    return jsonify({
        "ok": True,
        "actual_fix_date": fresh["actual_fix_date_disp"],
        "risk_tolerance_objective": fresh["risk_tolerance_objective"],
        "actual_risk_classification": fresh["actual_risk_classification"],
        "target_fix_date": fresh["target_fix_date"],
    })


# ---------------------------------------------------------------------------
# Routes: threaded comments + activity feed
# ---------------------------------------------------------------------------
@app.route("/finding/<int:fid>/comment", methods=["POST"])
@auth.login_required
def finding_comment(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT ip_hostname FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    body = request.form.get("body", "").strip()
    if body:
        db.execute("INSERT INTO comments(finding_id, user_id, body, created_at) VALUES (?,?,?,?)",
                   (fid, me["id"], body, datetime.now().isoformat(timespec="seconds")))
        db.commit()
        auth.log_activity(db, me["id"], fid, "comment", f'on {row["ip_hostname"]}: {body[:80]}')
    return redirect(url_for("finding_edit", fid=fid) + "#discussion")


@app.route("/activity")
@auth.login_required
def activity_feed():
    db = get_db()
    rows = db.execute(
        "SELECT a.*, u.display_name, u.username, u.role, f.ip_hostname, f.vulnerability "
        "FROM activity a LEFT JOIN users u ON u.id=a.user_id "
        "LEFT JOIN findings f ON f.id=a.finding_id "
        "ORDER BY a.id DESC LIMIT 300"
    ).fetchall()
    return render_template("activity.html", rows=rows)


def _finding_key(row):
    """Stable identity for a finding across scans: host + CVE (or normalised vuln)."""
    vuln = (row["vulnerability"] or "").lower()
    vuln = re.sub(r"\s*\(\d+/tcp\)\s*$", "", vuln).strip()
    ip = (row["ip_hostname"] or "").lower().strip()
    cve = (row["cve"] or "").lower().strip()
    return (ip, cve or vuln)


@app.route("/finding/<int:fid>")
@auth.login_required
def finding_detail(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    f = enrich(row)
    f["can_edit"] = auth.can_edit_finding(me, row, db)
    comments = db.execute(
        "SELECT c.*, u.display_name, u.username, u.role FROM comments c "
        "JOIN users u ON u.id=c.user_id WHERE c.finding_id=? ORDER BY c.created_at", (fid,)
    ).fetchall()
    acts = db.execute(
        "SELECT a.*, u.display_name, u.username, u.role FROM activity a "
        "LEFT JOIN users u ON u.id=a.user_id WHERE a.finding_id=? ORDER BY a.id DESC", (fid,)
    ).fetchall()
    evidence = db.execute(
        "SELECT e.id, e.filename, e.mime, e.size, e.created_at, u.display_name, u.username "
        "FROM evidence e LEFT JOIN users u ON u.id=e.uploaded_by "
        "WHERE e.finding_id=? ORDER BY e.id DESC", (fid,)
    ).fetchall()
    controls = compliance.map_finding(f, _enabled_frameworks(db))
    return render_template("finding_detail.html", f=f, comments=comments, activity=acts,
                           evidence=evidence, controls=controls,
                           statuses=engine.REMEDIATION_STATUSES)


MAX_EVIDENCE = 5 * 1024 * 1024  # 5 MB per file


@app.route("/finding/<int:fid>/evidence", methods=["POST"])
@auth.login_required
def evidence_upload(fid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    if not row:
        abort(404)
    if not auth.can_edit_finding(me, row, db):
        flash("Only the security team or the asset owner can add evidence to this finding.")
        return redirect(url_for("finding_detail", fid=fid))
    file = request.files.get("evidence")
    if not file or not file.filename:
        flash("No file selected.")
        return redirect(url_for("finding_detail", fid=fid) + "#evidence")
    data = file.read(MAX_EVIDENCE + 1)
    if len(data) > MAX_EVIDENCE:
        flash("File too large (max 5 MB).")
        return redirect(url_for("finding_detail", fid=fid) + "#evidence")
    fname = os.path.basename(file.filename)[:200]
    db.execute("INSERT INTO evidence(finding_id, filename, mime, size, data, uploaded_by, created_at)"
               " VALUES (?,?,?,?,?,?,?)",
               (fid, fname, file.mimetype or "application/octet-stream", len(data), data,
                me["id"], datetime.now().isoformat(timespec="seconds")))
    db.commit()
    auth.log_activity(db, me["id"], fid, "evidence", f'attached {fname} to {row["ip_hostname"]}')
    flash("Evidence attached.")
    return redirect(url_for("finding_detail", fid=fid) + "#evidence")


@app.route("/evidence/<int:eid>")
@auth.login_required
def evidence_download(eid):
    db = get_db()
    row = db.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    if not row:
        abort(404)
    return send_file(io.BytesIO(row["data"]), mimetype=row["mime"] or "application/octet-stream",
                     as_attachment=True, download_name=row["filename"] or f"evidence-{eid}")


@app.route("/evidence/<int:eid>/delete", methods=["POST"])
@auth.login_required
def evidence_delete(eid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM evidence WHERE id=?", (eid,)).fetchone()
    if not row:
        abort(404)
    finding = db.execute("SELECT * FROM findings WHERE id=?", (row["finding_id"],)).fetchone()
    if not (finding and auth.can_edit_finding(me, finding, db)):
        abort(403)
    db.execute("DELETE FROM evidence WHERE id=?", (eid,))
    db.commit()
    auth.log_activity(db, me["id"], row["finding_id"], "evidence", f'removed {row["filename"]}')
    flash("Evidence removed.")
    return redirect(url_for("finding_detail", fid=row["finding_id"]) + "#evidence")


# ---------------------------------------------------------------------------
# Scan-to-scan diff (New / Resolved / Recurring between two scans)
# ---------------------------------------------------------------------------
@app.route("/diff")
@auth.login_required
def scan_diff():
    db = get_db()
    scans_sorted = db.execute(
        "SELECT * FROM scans ORDER BY COALESCE(scan_date, imported_at) DESC, id DESC"
    ).fetchall()
    latest = scans_sorted[0] if scans_sorted else None
    prev = scans_sorted[1] if len(scans_sorted) > 1 else None
    a = request.args.get("base", type=int)
    b = request.args.get("target", type=int)
    if a and b:
        prev = db.execute("SELECT * FROM scans WHERE id=?", (a,)).fetchone()
        latest = db.execute("SELECT * FROM scans WHERE id=?", (b,)).fetchone()

    result = None
    if latest and prev and latest["id"] != prev["id"]:
        latest_rows = db.execute("SELECT * FROM findings WHERE scan_id=?", (latest["id"],)).fetchall()
        prev_rows = db.execute("SELECT * FROM findings WHERE scan_id=?", (prev["id"],)).fetchall()
        latest_map, prev_map = {}, {}
        for r in latest_rows:
            latest_map.setdefault(_finding_key(r), r)
        for r in prev_rows:
            prev_map.setdefault(_finding_key(r), r)
        new = [enrich(latest_map[k]) for k in latest_map if k not in prev_map]
        resolved = [enrich(prev_map[k]) for k in prev_map if k not in latest_map]
        recurring = [enrich(latest_map[k]) for k in latest_map if k in prev_map]
        sev_sort = lambda L: sorted(L, key=lambda r: -compliance.SEV_RANK.get(r["actual_risk_classification"], 0))
        result = {"new": sev_sort(new), "resolved": sev_sort(resolved),
                  "recurring": sev_sort(recurring)}
    return render_template("diff.html", scans=scans_sorted, latest=latest, prev=prev, result=result)


# ---------------------------------------------------------------------------
# Asset inventory (findings grouped by host)
# ---------------------------------------------------------------------------
@app.route("/assets")
@auth.login_required
def assets():
    db = get_db()
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    rank = compliance.SEV_RANK
    hosts = {}
    for r in rows:
        key = r["ip_hostname"] or "—"
        h = hosts.setdefault(key, {
            "ip": key, "device": r.get("device") or "", "owners": set(),
            "total": 0, "open": 0, "exposed": 0, "breached": 0,
            "sev": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Information": 0},
            "max_sev": "", "max_rank": -1,
        })
        if r.get("device"):
            h["device"] = r["device"]
        if r.get("asset_owner"):
            h["owners"].add(r["asset_owner"])
        h["total"] += 1
        ar = r["actual_risk_classification"] or "Information"
        if ar in h["sev"]:
            h["sev"][ar] += 1
        if rank.get(ar, 0) > h["max_rank"]:
            h["max_rank"] = rank.get(ar, 0)
            h["max_sev"] = ar
        if r["remediation_status"] not in ("Fixed", "Not Applicable"):
            h["open"] += 1
        vl = (r["vulnerability"] or "").lower()
        if "exposed" in vl or "open service" in vl:
            h["exposed"] += 1
        if r["risk_tolerance_objective"] == "Breached":
            h["breached"] += 1
    host_list = sorted(hosts.values(), key=lambda h: (-h["max_rank"], -h["open"], h["ip"]))
    for h in host_list:
        h["owners"] = sorted(h["owners"])
    return render_template("assets.html", hosts=host_list, total_hosts=len(host_list))


# ---------------------------------------------------------------------------
# Compliance coverage (ISO 27001 / PCI DSS control areas touched by findings)
# ---------------------------------------------------------------------------
@app.route("/compliance")
@auth.login_required
def compliance_view():
    db = get_db()
    enabled = set(_enabled_frameworks(db))
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    cov = compliance.coverage(rows, enabled)
    all_frameworks = [{**f, "checked": f["id"] in enabled} for f in compliance.FRAMEWORKS]
    return render_template("compliance.html", coverage=cov, frameworks=list(cov.keys()),
                           all_frameworks=all_frameworks, total=len(rows))


# ===========================================================================
# Settings + threat intelligence (offline-first, fetch-only)
# ===========================================================================
def get_setting(db, key, default=None):
    r = db.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(db, key, value):
    db.execute("INSERT INTO settings(key, value) VALUES (?, ?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))


def _enabled_sources(db):
    raw = get_setting(db, "ti_sources")
    if raw is None:
        return [s["id"] for s in threatintel.SOURCES]  # all checked by default
    try:
        return _json.loads(raw)
    except Exception:
        return []


def _custom_sources(db):
    return [dict(r) for r in db.execute(
        "SELECT * FROM threat_source ORDER BY created_at")]


def _all_sources(db):
    """Built-in + admin-added sources, each annotated with enabled state and
    last-fetch health, for the Settings list and the fetch loop."""
    enabled_builtin = set(_enabled_sources(db))
    health = {r["source_id"]: dict(r)
              for r in db.execute("SELECT * FROM threat_source_health")}
    out = []
    for s in threatintel.SOURCES:
        out.append({**s, "custom": False, "checked": s["id"] in enabled_builtin,
                    "health": health.get(s["id"])})
    for s in _custom_sources(db):
        out.append({"id": s["id"], "name": s["name"], "url": s["url"],
                    "kind": s["kind"], "custom": True, "checked": bool(s["enabled"]),
                    "desc": "Custom source" + (f" · added by {s['added_by']}" if s["added_by"] else ""),
                    "health": health.get(s["id"])})
    return out


def _effective_sources(db):
    """Only the enabled sources — what the update loop actually fetches."""
    return [s for s in _all_sources(db) if s["checked"]]


def _record_source_health(db, sid, status, detail="", records=0):
    db.execute(
        "INSERT INTO threat_source_health(source_id, status, detail, records, checked_at) "
        "VALUES (?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET "
        "status=excluded.status, detail=excluded.detail, records=excluded.records, "
        "checked_at=excluded.checked_at",
        (sid, status, (detail or "")[:300], records,
         datetime.now().isoformat(timespec="seconds")))


def _unhealthy_sources(db):
    """Enabled sources whose last fetch failed — surfaced as notifications."""
    return [{"name": s["name"], "detail": (s["health"] or {}).get("detail", ""),
             "checked_at": (s["health"] or {}).get("checked_at", "")}
            for s in _effective_sources(db)
            if s.get("health") and s["health"]["status"] == "error"]


def _enabled_frameworks(db):
    raw = get_setting(db, "comp_frameworks")
    if raw is None:
        return compliance.DEFAULT_ENABLED
    try:
        ids = _json.loads(raw)
        return [i for i in ids if i in compliance.FRAMEWORK_BY_ID]
    except Exception:
        return compliance.DEFAULT_ENABLED


@app.route("/settings")
@auth.login_required
@auth.role_required("admin")
def settings_page():
    db = get_db()
    section = request.args.get("section", "")
    if section not in ("", "feeds", "frameworks", "delivery", "instance", "zoho"):
        section = ""
    sources = _all_sources(db)
    enabled_fw = set(_enabled_frameworks(db))
    frameworks = [{**f, "checked": f["id"] in enabled_fw} for f in compliance.FRAMEWORKS]
    return render_template(
        "settings.html", sources=sources, source_kinds=threatintel.SOURCE_KINDS,
        unhealthy=_unhealthy_sources(db), frameworks=frameworks, section=section,
        instance_label=get_setting(db, "instance_label", ""),
        zoho_conn=_zoho_conn(db), zoho_mapping=_zoho_mapping(db),
        zoho_fields=zoho.MAP_FIELDS, zoho_dcs=zoho.DATA_CENTERS,
        zoho_secrets_ok=zoho.secrets_configured(),
        zoho_status={"status": get_setting(db, "zoho_last_status", ""),
                     "detail": get_setting(db, "zoho_last_detail", ""),
                     "at": get_setting(db, "zoho_last_at", "")},
        ti_enabled=(get_setting(db, "ti_enabled", "0") == "1"),
        ti_proxy=get_setting(db, "ti_proxy", "") or "",
        last_update=get_setting(db, "ti_last_update", ""),
        feed_count=db.execute("SELECT COUNT(*) c FROM threat_feed").fetchone()["c"],
        delivery_status=delivery.provider_status(),
    )


@app.route("/settings/threatintel", methods=["POST"])
@auth.login_required
@auth.role_required("admin")
def settings_threatintel():
    db = get_db()
    me = auth.current_user(db)
    set_setting(db, "ti_enabled", "1" if request.form.get("ti_enabled") else "0")
    # only ids that actually exist in the hardcoded registry can be enabled
    chosen = [s["id"] for s in threatintel.SOURCES
              if request.form.get("src_" + s["id"])]
    set_setting(db, "ti_sources", _json.dumps(chosen))
    # enable/disable each admin-added source from its checkbox
    for s in _custom_sources(db):
        on = 1 if request.form.get("src_" + s["id"]) else 0
        db.execute("UPDATE threat_source SET enabled=? WHERE id=?", (on, s["id"]))
    set_setting(db, "ti_proxy", request.form.get("ti_proxy", "").strip())
    db.commit()
    auth.log_activity(db, me["id"], None, "settings", "updated threat-feed settings")
    flash("Threat-feed settings saved.")
    return redirect(url_for("settings_page"))


@app.route("/settings/sources/add", methods=["POST"])
@auth.role_required("admin")
def settings_source_add():
    db = get_db()
    me = auth.current_user(db)
    name = (request.form.get("name") or "").strip()[:120]
    url = (request.form.get("url") or "").strip()[:500]
    kind = (request.form.get("kind") or "").strip()
    if not name:
        flash("Give the source a name.")
        return redirect(url_for("settings_page"))
    if kind not in {k["id"] for k in threatintel.SOURCE_KINDS}:
        flash("Pick a feed format for the source.")
        return redirect(url_for("settings_page"))
    ok, reason = threatintel.validate_source_url(url)
    if not ok:
        flash(f"Source not added — {reason}")
        return redirect(url_for("settings_page"))
    # don't duplicate a URL already present (built-in or custom)
    existing_urls = {s["url"] for s in _all_sources(db)}
    if url in existing_urls:
        flash("That URL is already a source.")
        return redirect(url_for("settings_page"))
    sid = "custom_" + _secrets.token_hex(5)
    db.execute("INSERT INTO threat_source(id, name, url, kind, enabled, added_by, created_at) "
               "VALUES (?,?,?,?,1,?,?)",
               (sid, name, url, kind, me["username"],
                datetime.now().isoformat(timespec="seconds")))
    db.commit()
    auth.log_activity(db, me["id"], None, "settings", f"added threat source '{name}'")
    # test-fetch now (if online) so the admin learns immediately whether it works
    note = ""
    if get_setting(db, "ti_enabled", "0") == "1":
        proxy = get_setting(db, "ti_proxy", "") or None
        try:
            recs = threatintel.fetch_custom({"url": url, "kind": kind, "name": name}, proxy=proxy)
            _record_source_health(db, sid, "ok", f"{len(recs)} records", len(recs))
            note = f" Reachable — {len(recs)} records on a test fetch."
        except Exception as e:
            _record_source_health(db, sid, "error", str(e))
            note = f" ⚠ Added, but the test fetch failed: {e}"
        db.commit()
    flash(f"Source '{name}' added." + note)
    return redirect(url_for("settings_page"))


@app.route("/settings/sources/<sid>/delete", methods=["POST"])
@auth.role_required("admin")
def settings_source_delete(sid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT name FROM threat_source WHERE id=?", (sid,)).fetchone()
    if not row:
        abort(404)
    db.execute("DELETE FROM threat_source WHERE id=?", (sid,))
    db.execute("DELETE FROM threat_source_health WHERE source_id=?", (sid,))
    db.commit()
    auth.log_activity(db, me["id"], None, "settings", f"removed threat source '{row['name']}'")
    flash(f"Source '{row['name']}' removed.")
    return redirect(url_for("settings_page"))


@app.route("/settings/frameworks", methods=["POST"])
@auth.login_required
@auth.role_required("admin")
def settings_frameworks():
    db = get_db()
    me = auth.current_user(db)
    chosen = [f["id"] for f in compliance.FRAMEWORKS if request.form.get("fw_" + f["id"])]
    set_setting(db, "comp_frameworks", _json.dumps(chosen))
    db.commit()
    auth.log_activity(db, me["id"], None, "settings", "updated compliance frameworks")
    flash("Compliance frameworks updated.")
    # return to wherever the change was made from (Compliance page or Settings)
    if request.form.get("next") == "compliance":
        return redirect(url_for("compliance_view"))
    return redirect(url_for("settings_page"))


@app.route("/threatintel/update", methods=["POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def threatintel_update():
    db = get_db()
    me = auth.current_user(db)
    if get_setting(db, "ti_enabled", "0") != "1":
        flash("Online threat-feed updates are turned off. Enable them in Settings first, "
              "or import a feed file for air-gapped use.")
        return redirect(url_for("settings_page"))
    proxy = get_setting(db, "ti_proxy", "") or None
    sources = _effective_sources(db)
    records, errors = [], []
    for s in sources:
        try:
            recs = (threatintel.fetch_custom(s, proxy=proxy) if s["custom"]
                    else threatintel.fetch_source(s["id"], proxy=proxy))
            records.extend(recs)
            _record_source_health(db, s["id"], "ok", f"{len(recs)} records", len(recs))
        except Exception as e:
            _record_source_health(db, s["id"], "error", str(e))
            errors.append(f"{s['name']}: {e}")
            auth.log_activity(db, me["id"], None, "threatintel",
                              f"source '{s['name']}' failed: {str(e)[:120]}")
    if records:
        _store_feed(db, records)
        set_setting(db, "ti_last_update", datetime.now().isoformat(timespec="seconds"))
        auth.log_activity(db, me["id"], None, "threatintel", f"updated feed ({len(records)} records)")
    db.commit()
    msg = f"Fetched {len(records)} feed records from {len(sources)} source(s)."
    if errors:
        msg += f" ⚠ {len(errors)} source(s) had problems — see the alert on this page."
    flash(msg)
    return redirect(url_for("threatintel_view"))


@app.route("/threatintel/import", methods=["POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def threatintel_import():
    db = get_db()
    me = auth.current_user(db)
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose a feed file (produced by feedsync.py) to import.")
        return redirect(url_for("settings_page"))
    MAX_FEED = 128 * 1024 * 1024  # 128 MB
    blob = file.read(MAX_FEED + 1)
    if len(blob) > MAX_FEED:
        flash("Feed file too large (max 128 MB).")
        return redirect(url_for("settings_page"))
    try:
        payload = _json.loads(blob.decode("utf-8", "ignore"))
        records = payload.get("records") if isinstance(payload, dict) else payload
        assert isinstance(records, list)
    except Exception as e:
        flash(f"Could not read that feed file: {e}")
        return redirect(url_for("settings_page"))
    _store_feed(db, records)
    set_setting(db, "ti_last_update", datetime.now().isoformat(timespec="seconds") + " (imported)")
    db.commit()
    auth.log_activity(db, me["id"], None, "threatintel", f"imported feed ({len(records)} records)")
    flash(f"Imported {len(records)} feed records.")
    return redirect(url_for("threatintel_view"))


def _store_feed(db, records):
    db.execute("DELETE FROM threat_feed")
    now = datetime.now().isoformat(timespec="seconds")
    for r in records:
        db.execute(
            "INSERT INTO threat_feed(cve, title, products, severity, source, kev, date, summary, imported_at)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            ((r.get("cve") or "").upper(), r.get("title") or "",
             _json.dumps(r.get("products") or []), r.get("severity") or "",
             r.get("source") or "", 1 if r.get("kev") else 0,
             r.get("date") or "", r.get("summary") or "", now))


@app.route("/threatintel")
@auth.login_required
def threatintel_view():
    db = get_db()
    feed = []
    for r in db.execute("SELECT * FROM threat_feed"):
        d = dict(r)
        try:
            d["products"] = _json.loads(d["products"] or "[]")
        except Exception:
            d["products"] = []
        d["kev"] = bool(d["kev"])
        feed.append(d)
    findings = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    assets = [dict(r) for r in db.execute("SELECT * FROM assets")]
    alerts = threatintel.match(feed, findings, assets) if feed else []
    kev_count = sum(1 for a in alerts if a["kev"])
    return render_template("threat_alerts.html", alerts=alerts, feed_count=len(feed),
                           kev_count=kev_count, last_update=get_setting(db, "ti_last_update", ""),
                           unhealthy=_unhealthy_sources(db),
                           enabled=(get_setting(db, "ti_enabled", "0") == "1"))


# ===========================================================================
# Phishing-awareness simulation (responsible scope)
#   * No credential capture anywhere — the link leads to a teachable page.
#   * Argus does not send mail; it mints per-recipient tracking links and the
#     team sends them through their own authorised relay.
#   * Tracking tokens are opaque; no PII is encoded in the URL.
# ===========================================================================
def _new_token():
    return _secrets.token_urlsafe(24)


def _csv_safe(v):
    """Neutralise spreadsheet formula-injection in exported cells."""
    s = "" if v is None else str(v)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + s
    return s


_PHONE_RE = re.compile(r"^\+?[\d][\d\s()\-]{5,}$")


def _classify_recipient_fields(parts):
    """Sort free-form comma fields into name/email/phone/handle/dept.
    Accepts, in any order: an email (has @ and a dot), a phone (+ / digits),
    a social handle (@name), and plain words (first = name, next = dept)."""
    out = {"name": "", "email": "", "phone": "", "handle": "", "dept": ""}
    plain = []
    for p in parts:
        if not p:
            continue
        if p.startswith("@"):                       # social handle, e.g. @ama.b
            if not out["handle"]:
                out["handle"] = p
        elif "@" in p and "." in p.split("@", 1)[1]:
            if not out["email"]:
                out["email"] = p
        elif _PHONE_RE.match(p):
            if not out["phone"]:
                out["phone"] = p
        else:
            plain.append(p)
    if plain:
        out["name"] = plain[0]
    if len(plain) > 1:
        out["dept"] = plain[1]
    return out


def _delivery_providers():
    """Build the send providers from environment config. A seam tests can
    monkeypatch to inject fakes — real sending only happens on the operator's
    own deployment with their own credentials."""
    return {"email": delivery.EmailProvider(), "twilio": delivery.TwilioProvider()}


def _ensure_send_worker():
    """Start the background send worker on first use (idempotent)."""
    sending.start_worker(DB_PATH, _delivery_providers)


# --- Zoho Creator inventory sync -------------------------------------------
def _zoho_conn(db):
    return {
        "dc": get_setting(db, "zoho_dc", "com") or "com",
        "owner": get_setting(db, "zoho_owner", ""),
        "app": get_setting(db, "zoho_app", ""),
        "report": get_setting(db, "zoho_report", ""),
    }


def _zoho_mapping(db):
    raw = get_setting(db, "zoho_mapping", "")
    try:
        m = _json.loads(raw) if raw else {}
    except Exception:
        m = {}
    return {k: (m.get(k) or "") for k, _ in zoho.MAP_FIELDS}


def _upsert_assets(db, assets, source):
    """Insert new assets, update existing ones (matched by IP then hostname).
    Classification (type / scan policy / eligibility) is always refreshed, but a
    manually-set criticality, owner or description is kept when the incoming
    value is empty, so a sync never wipes hand-entered context."""
    added = updated = 0
    now = datetime.now().isoformat(timespec="seconds")
    for a in assets:
        existing = None
        if a["ip"]:
            existing = db.execute("SELECT * FROM assets WHERE ip=? AND ip!=''",
                                  (a["ip"],)).fetchone()
        if not existing and a["hostname"]:
            existing = db.execute("SELECT * FROM assets WHERE hostname=? AND hostname!=''",
                                  (a["hostname"],)).fetchone()
        if existing:
            db.execute(
                "UPDATE assets SET ip=?, hostname=?, description=?, owner=?, "
                "criticality=?, asset_type=?, scan_policy=?, scan_eligible=?, "
                "classify_reason=?, source=?, updated_at=? WHERE id=?",
                (a["ip"] or existing["ip"], a["hostname"] or existing["hostname"],
                 a["description"] or existing["description"],
                 a["owner"] or existing["owner"],
                 a["criticality"] or existing["criticality"],
                 a["asset_type"], a["scan_policy"], a["scan_eligible"],
                 a["classify_reason"], source, now, existing["id"]))
            updated += 1
        else:
            db.execute(
                "INSERT INTO assets(ip, hostname, description, owner, criticality, "
                "asset_type, scan_policy, scan_eligible, classify_reason, source, "
                "created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (a["ip"], a["hostname"], a["description"], a["owner"], a["criticality"],
                 a["asset_type"], a["scan_policy"], a["scan_eligible"],
                 a["classify_reason"], source, now, now))
            added += 1
    db.commit()
    return added, updated


@app.route("/inventory/sync", methods=["POST"])
@auth.role_required("admin", "editor")
def inventory_sync():
    db = get_db()
    me = auth.current_user(db)
    if not zoho.secrets_configured():
        flash("Zoho credentials aren't set in the server environment — see Settings → Zoho sync.")
        return redirect(url_for("inventory"))
    conn = _zoho_conn(db)
    mapping = _zoho_mapping(db)
    if not (conn["owner"] and conn["app"] and conn["report"]):
        flash("Set the Zoho app owner, app and report in Settings → Zoho sync first.")
        return redirect(url_for("inventory"))
    if not (mapping.get("ip") or mapping.get("hostname")):
        flash("Map at least the IP or hostname field in Settings → Zoho sync.")
        return redirect(url_for("inventory"))
    try:
        records = zoho.fetch_records(conn)
        assets = zoho.map_records(records, mapping)
    except zoho.ZohoError as e:
        set_setting(db, "zoho_last_status", "error")
        set_setting(db, "zoho_last_detail", str(e)[:300])
        set_setting(db, "zoho_last_at", datetime.now().isoformat(timespec="seconds"))
        db.commit()
        auth.log_activity(db, me["id"], None, "inventory", f"Zoho sync failed: {str(e)[:120]}")
        flash(f"Zoho sync failed — {e}")
        return redirect(url_for("inventory"))
    added, upd = _upsert_assets(db, assets, "zoho")
    set_setting(db, "zoho_last_status", "ok")
    set_setting(db, "zoho_last_detail", f"{len(assets)} pulled · {added} new, {upd} updated")
    set_setting(db, "zoho_last_at", datetime.now().isoformat(timespec="seconds"))
    db.commit()
    auth.log_activity(db, me["id"], None, "inventory",
                      f"Zoho sync: {len(assets)} assets ({added} new, {upd} updated)")
    flash(f"Synced {len(assets)} asset(s) from Zoho — {added} new, {upd} updated.")
    return redirect(url_for("inventory"))


@app.route("/settings/zoho", methods=["POST"])
@auth.role_required("admin")
def settings_zoho():
    db = get_db()
    me = auth.current_user(db)
    dc = (request.form.get("zoho_dc") or "com").strip()
    if dc not in zoho.DATA_CENTERS:
        dc = "com"
    set_setting(db, "zoho_dc", dc)
    set_setting(db, "zoho_owner", (request.form.get("zoho_owner") or "").strip()[:120])
    set_setting(db, "zoho_app", (request.form.get("zoho_app") or "").strip()[:120])
    set_setting(db, "zoho_report", (request.form.get("zoho_report") or "").strip()[:120])
    mapping = {k: (request.form.get("map_" + k) or "").strip()[:120]
               for k, _ in zoho.MAP_FIELDS}
    set_setting(db, "zoho_mapping", _json.dumps(mapping))
    db.commit()
    auth.log_activity(db, me["id"], None, "settings", "updated Zoho sync settings")
    flash("Zoho sync settings saved.")
    return redirect(url_for("settings_page", section="zoho"))


def _recipients_for(db, campaign_id):
    return db.execute(
        "SELECT * FROM phish_recipient WHERE campaign_id=? ORDER BY id",
        (campaign_id,)).fetchall()


def _campaign_stats(recips):
    n = len(recips)
    clicked = sum(1 for r in recips if r["clicked_at"])
    reported = sum(1 for r in recips if r["reported_at"])
    return {
        "recipients": n,
        "clicked": clicked,
        "reported": reported,
        "not_clicked": n - clicked,
        "click_rate": round(clicked / n * 100) if n else 0,
        "report_rate": round(reported / n * 100) if n else 0,
    }


@app.route("/phishing")
@auth.login_required
def phishing_view():
    db = get_db()
    campaigns = db.execute(
        "SELECT * FROM phish_campaign ORDER BY id DESC").fetchall()
    rbyc, enriched = {}, []
    for c in campaigns:
        rs = _recipients_for(db, c["id"])
        rbyc[c["id"]] = rs
        d = dict(c)
        d["stats"] = _campaign_stats(rs)
        enriched.append(d)
    prog = phishing.program_stats(campaigns, rbyc)
    return render_template("phishing.html", campaigns=enriched, prog=prog)


@app.route("/phishing/new", methods=["GET", "POST"])
@auth.role_required("admin", "editor")
def phishing_new():
    db = get_db()
    me = auth.current_user(db)
    if request.method == "POST":
        key = request.form.get("template_key", "")
        tpl = phishing.TEMPLATE_BY_KEY.get(key)
        if not tpl:
            flash("Pick a template to start from.")
            return redirect(url_for("phishing_new"))
        name = (request.form.get("name") or tpl["name"]).strip()[:160]
        sender = (request.form.get("sender") or tpl["sender"]).strip()[:200]
        subject = (request.form.get("subject") or tpl["subject"]).strip()[:200]
        body = (request.form.get("body") or tpl["body"])[:8000]
        landing = (request.form.get("landing_note") or "").strip()[:2000]
        channel = request.form.get("channel", "email")
        if channel not in (delivery.CHANNELS + delivery.MANUAL_CHANNELS):
            channel = "email"
        now = datetime.now().isoformat(timespec="seconds")
        cur = db.execute(
            "INSERT INTO phish_campaign(name, template_key, sender, subject, "
            "body, landing_note, channel, status, created_by, created_at) "
            "VALUES (?,?,?,?,?,?,?,'Draft',?,?)",
            (name, key, sender, subject, body, landing, channel, me["id"], now))
        db.commit()
        auth.log_activity(db, me["id"], None, "phishing",
                          f"created simulation campaign '{name}'")
        return redirect(url_for("phishing_campaign", cid=cur.lastrowid))
    return render_template("phishing_new.html", templates=phishing.TEMPLATES)


@app.route("/phishing/<int:cid>")
@auth.login_required
def phishing_campaign(cid):
    db = get_db()
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    recips = _recipients_for(db, cid)
    tpl = phishing.TEMPLATE_BY_KEY.get(c["template_key"], {})
    # a sample rendered email for the first recipient (or a placeholder)
    sample_link = url_for("phish_land", token="SAMPLE-TOKEN", _external=True)
    sample = phishing.render_body(c["body"],
                                  recips[0]["name"] if recips else "Alex Mensah",
                                  sample_link)
    pstatus = delivery.provider_status()
    channel = c["channel"] or "email"
    job = sending.active_job(db, cid)
    return render_template(
        "phishing_campaign.html", c=c, recips=recips,
        stats=_campaign_stats(recips), flags=tpl.get("flags", []),
        sample=sample, can_manage=auth.can_import_or_scan(auth.current_user(db)),
        channel=channel, provider_ready=pstatus.get(channel, False),
        is_manual=(channel in delivery.MANUAL_CHANNELS),
        job=job, pending=sending.pending_count(db, cid),
        groups=sending.campaign_groups(db, cid),
        ext_base=url_for("phish_land", token="", _external=True))


@app.route("/phishing/<int:cid>/recipients", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_recipients(cid):
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    if c["status"] == "Closed":
        flash("This campaign is closed — reopen a new one to add recipients.")
        return redirect(url_for("phishing_campaign", cid=cid))
    raw = request.form.get("recipients", "")
    grp = (request.form.get("group") or "").strip()[:60]
    added, skipped = 0, 0
    existing = set()
    for r in _recipients_for(db, cid):
        for v in (r["email"], r["phone"], r["handle"]):
            if v:
                existing.add(v.lower())
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        rec = _classify_recipient_fields([p.strip() for p in line.split(",")])
        # a recipient needs at least one contactable address
        key = (rec["email"] or rec["phone"] or rec["handle"]).lower()
        if not key:
            skipped += 1
            continue
        if key in existing:
            skipped += 1
            continue
        existing.add(key)
        db.execute(
            "INSERT INTO phish_recipient(campaign_id, name, email, department, "
            "phone, handle, grp, token, click_count) VALUES (?,?,?,?,?,?,?,?,0)",
            (cid, rec["name"][:120], rec["email"][:254], rec["dept"][:120],
             rec["phone"][:40], rec["handle"][:120], grp, _new_token()))
        added += 1
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing",
                      f"added {added} recipients to campaign #{cid}")
    flash(f"Added {added} recipient(s)." + (f" Skipped {skipped}." if skipped else ""))
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/launch", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_launch(cid):
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    n = db.execute("SELECT COUNT(*) n FROM phish_recipient WHERE campaign_id=?",
                   (cid,)).fetchone()["n"]
    if not n:
        flash("Add at least one recipient before launching.")
        return redirect(url_for("phishing_campaign", cid=cid))
    db.execute("UPDATE phish_campaign SET status='Active', launched_at=? WHERE id=?",
               (datetime.now().isoformat(timespec="seconds"), cid))
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing",
                      f"launched campaign #{cid} ({n} recipients)")
    flash("Campaign marked Active. Export the links and send them from your "
          "authorised mail relay.")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/close", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_close(cid):
    db = get_db()
    me = auth.current_user(db)
    if not db.execute("SELECT 1 FROM phish_campaign WHERE id=?", (cid,)).fetchone():
        abort(404)
    db.execute("UPDATE phish_campaign SET status='Closed', closed_at=? WHERE id=?",
               (datetime.now().isoformat(timespec="seconds"), cid))
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing", f"closed campaign #{cid}")
    flash("Campaign closed. Tracking links no longer record new clicks.")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/delete", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_delete(cid):
    db = get_db()
    me = auth.current_user(db)
    if not db.execute("SELECT 1 FROM phish_campaign WHERE id=?", (cid,)).fetchone():
        abort(404)
    db.execute("DELETE FROM phish_event WHERE campaign_id=?", (cid,))
    db.execute("DELETE FROM phish_recipient WHERE campaign_id=?", (cid,))
    db.execute("DELETE FROM phish_campaign WHERE id=?", (cid,))
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing", f"deleted campaign #{cid}")
    flash("Campaign deleted.")
    return redirect(url_for("phishing_view"))


@app.route("/phishing/<int:cid>/export")
@auth.role_required("admin", "editor")
def phishing_export(cid):
    db = get_db()
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    out = io.StringIO()
    w = _csv.writer(out)
    w.writerow(["name", "email", "department", "tracking_link"])
    for r in _recipients_for(db, cid):
        link = url_for("phish_land", token=r["token"], _external=True)
        w.writerow([_csv_safe(r["name"]), _csv_safe(r["email"]),
                    _csv_safe(r["department"]), link])
    data = out.getvalue().encode("utf-8")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "_", c["name"] or f"campaign_{cid}")[:60]
    return send_file(io.BytesIO(data), mimetype="text/csv", as_attachment=True,
                     download_name=f"phish_{safe}_links.csv")


@app.route("/phishing/<int:cid>/authorize", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_authorize(cid):
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    # the gate that keeps this an awareness tool: an explicit human attestation
    # that the recipients are people/systems the operator is allowed to test.
    if not request.form.get("confirm"):
        flash("Tick the authorisation box to confirm you may test these recipients.")
        return redirect(url_for("phishing_campaign", cid=cid))
    db.execute("UPDATE phish_campaign SET authorized=1, authorized_by=?, "
               "authorized_at=? WHERE id=?",
               (me["username"], datetime.now().isoformat(timespec="seconds"), cid))
    db.commit()
    auth.log_activity(db, me["id"], None, "phishing",
                      f"authorised sending for campaign #{cid}")
    flash("Authorisation recorded. You can now send to this campaign.")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/testsend", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_testsend(cid):
    """Send a single message to an address the operator controls, so they can
    preview the real thing before any recipient is touched. Uses a SAMPLE link
    that records nothing."""
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    channel = c["channel"] or "email"
    if channel in delivery.MANUAL_CHANNELS:
        flash("This channel is manual — use the copy buttons, there is nothing to test-send.")
        return redirect(url_for("phishing_campaign", cid=cid))
    target = (request.form.get("target") or "").strip()
    if not target:
        flash("Enter your own email or phone to send the test to.")
        return redirect(url_for("phishing_campaign", cid=cid))
    link = url_for("phish_land", token="SAMPLE-TOKEN", _external=True)
    recip = {"name": me["display_name"] or "",
             "email": target if channel == "email" else "",
             "phone": "" if channel == "email" else target}
    ok, err = delivery.dispatch(channel, recip, dict(c), link,
                                providers=_delivery_providers())
    if ok:
        flash(f"Test {channel} sent to {target}.")
    else:
        flash(f"Test send failed: {err}")
    auth.log_activity(db, me["id"], None, "phishing",
                      f"test-send ({channel}) for campaign #{cid}: {'ok' if ok else err}")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/send", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_send(cid):
    """Queue a paced, background send for this campaign. Gated: the campaign
    must be Active, explicitly authorised, and the channel's provider ready.
    Only recipients attached to THIS campaign are ever contacted."""
    db = get_db()
    me = auth.current_user(db)
    c = db.execute("SELECT * FROM phish_campaign WHERE id=?", (cid,)).fetchone()
    if not c:
        abort(404)
    channel = c["channel"] or "email"
    if channel in delivery.MANUAL_CHANNELS:
        flash("This is a manual channel — copy each person's message and link by hand.")
        return redirect(url_for("phishing_campaign", cid=cid))
    if c["status"] != "Active":
        flash("Launch the campaign before sending.")
        return redirect(url_for("phishing_campaign", cid=cid))
    if not c["authorized"]:
        flash("Record your authorisation to test these recipients first.")
        return redirect(url_for("phishing_campaign", cid=cid))
    if not delivery.provider_status().get(channel):
        flash(f"The {channel} provider isn't configured on this server. "
              f"Set its credentials in the environment (see Settings) and retry.")
        return redirect(url_for("phishing_campaign", cid=cid))
    if sending.has_live_job(db, cid):
        flash("A send is already queued or running for this campaign.")
        return redirect(url_for("phishing_campaign", cid=cid))

    include_sent = request.form.get("resend") == "1"
    # optional group filter: which recipient groups this send targets. The form
    # sends one value per selected group (ungrouped is the empty-string value).
    all_groups = [g["name"] for g in sending.campaign_groups(db, cid)]
    picked_groups = request.form.getlist("group")
    groups = [g for g in picked_groups if g in all_groups] or None
    # treat "all groups selected" as no filter
    if groups and set(groups) == set(all_groups):
        groups = None
    if not include_sent and sending.pending_count(db, cid, groups) == 0:
        flash("No one pending in the selected group(s). Tick 're-send' or widen the selection.")
        return redirect(url_for("phishing_campaign", cid=cid))
    try:
        rate = int(request.form.get("rate") or 30)
    except ValueError:
        rate = 30
    scheduled_at = (request.form.get("scheduled_at") or "").strip() or None
    if scheduled_at:
        scheduled_at = scheduled_at.replace("T", " ")[:19]
    # Prefer a pinned base URL over the client-controlled Host header, so the
    # tracked links in sent messages can't be bent by a spoofed Host.
    base_url = os.environ.get("ARGUS_BASE_URL") or request.host_url
    jid = sending.create_job(db, cid, channel, base_url, me["username"],
                             rate_per_min=rate, scheduled_at=scheduled_at,
                             include_sent=include_sent, groups=groups)
    _ensure_send_worker()
    auth.log_activity(db, me["id"], None, "phishing",
                      f"queued send job #{jid} for campaign #{cid} via {channel}")
    flash("Send queued." if not scheduled_at else f"Send scheduled for {scheduled_at}.")
    return redirect(url_for("phishing_campaign", cid=cid))


@app.route("/phishing/<int:cid>/job")
@auth.login_required
def phishing_job(cid):
    """Live progress for the campaign's latest send job (polled by the UI)."""
    db = get_db()
    j = sending.active_job(db, cid)
    if not j:
        return jsonify({"exists": False})
    d = dict(j)
    d["exists"] = True
    d["pct"] = round(d["processed"] / d["total"] * 100) if d["total"] else 0
    return jsonify(d)


@app.route("/phishing/<int:cid>/job/cancel", methods=["POST"])
@auth.role_required("admin", "editor")
def phishing_job_cancel(cid):
    db = get_db()
    me = auth.current_user(db)
    j = sending.active_job(db, cid)
    if j and j["status"] in ("scheduled", "queued", "running"):
        sending.cancel_job(db, j["id"])
        auth.log_activity(db, me["id"], None, "phishing",
                          f"cancelled send job #{j['id']} for campaign #{cid}")
        flash("Send cancelled.")
    return redirect(url_for("phishing_campaign", cid=cid))


# --- PUBLIC tracking + teachable landing (no login, NO credential capture) ---
@app.route("/p/<token>")
def phish_land(token):
    """A simulated-phish click lands here. We record the click and teach.
    There is deliberately no form, no password field, nothing to submit."""
    db = get_db()
    r = db.execute("SELECT * FROM phish_recipient WHERE token=?",
                   (token,)).fetchone()
    campaign = None
    if r:
        campaign = db.execute("SELECT * FROM phish_campaign WHERE id=?",
                              (r["campaign_id"],)).fetchone()
        # only Active campaigns record clicks; SAMPLE-TOKEN never matches a row
        if campaign and campaign["status"] == "Active":
            ua = (request.headers.get("User-Agent", "") or "")[:300]
            now = datetime.now().isoformat(timespec="seconds")
            if not r["clicked_at"]:
                db.execute("UPDATE phish_recipient SET clicked_at=?, "
                           "click_count=click_count+1 WHERE id=?", (now, r["id"]))
            else:
                db.execute("UPDATE phish_recipient SET click_count=click_count+1 "
                           "WHERE id=?", (r["id"],))
            db.execute("INSERT INTO phish_event(recipient_id, campaign_id, kind, "
                       "at, user_agent) VALUES (?,?,'click',?,?)",
                       (r["id"], r["campaign_id"], now, ua))
            db.commit()
    tpl = phishing.TEMPLATE_BY_KEY.get(campaign["template_key"], {}) if campaign else {}
    note = campaign["landing_note"] if campaign else ""
    reported = bool(r["reported_at"]) if r else False
    return render_template("phishing_landing.html",
                           flags=tpl.get("flags", []), note=note,
                           token=token, known=bool(r), reported=reported,
                           active=bool(campaign and campaign["status"] == "Active"))


@app.route("/p/<token>/reported")
def phish_reported(token):
    """The teachable 'I would report this' acknowledgement. Idempotent,
    records no credentials — just that the person recognised the simulation."""
    db = get_db()
    r = db.execute("SELECT * FROM phish_recipient WHERE token=?",
                   (token,)).fetchone()
    if r and not r["reported_at"]:
        now = datetime.now().isoformat(timespec="seconds")
        db.execute("UPDATE phish_recipient SET reported_at=? WHERE id=?",
                   (now, r["id"]))
        db.execute("INSERT INTO phish_event(recipient_id, campaign_id, kind, at, "
                   "user_agent) VALUES (?,?,'report',?,?)",
                   (r["id"], r["campaign_id"], now,
                    (request.headers.get("User-Agent", "") or "")[:300]))
        db.commit()
    return redirect(url_for("phish_land", token=token))


# ===========================================================================
# Asset inventory register — import, classify, govern scanning
# ===========================================================================
def _read_asset_rows(file):
    """Return (headers, list-of-row-lists) from an uploaded .xlsx or .csv."""
    name = (file.filename or "").lower()
    MAX_IMPORT = 12 * 1024 * 1024  # 12 MB — asset sheets are small
    raw = file.read(MAX_IMPORT + 1)
    if len(raw) > MAX_IMPORT:
        raise ValueError("file too large (max 12 MB)")
    if name.endswith(".csv") or name.endswith(".tsv"):
        text = raw.decode("utf-8-sig", "ignore")
        delim = "\t" if name.endswith(".tsv") else ","
        reader = _csv.reader(io.StringIO(text), delimiter=delim)
        rows = [r for r in reader if any(str(c).strip() for c in r)]
        if not rows:
            return [], []
        return rows[0], rows[1:]
    # default: xlsx
    import openpyxl
    wb = openpyxl.load_workbook(io.BytesIO(raw), read_only=True, data_only=True)
    ws = wb.active
    data = [list(row) for row in ws.iter_rows(values_only=True)]
    data = [r for r in data if any(c is not None and str(c).strip() for c in r)]
    if not data:
        return [], []
    return data[0], data[1:]


def _assessed_keys(db):
    """IPs/hostnames that already appear in findings (proxy for 'assessed')."""
    keys = set()
    for r in db.execute("SELECT DISTINCT ip_hostname FROM findings"):
        v = (r["ip_hostname"] or "").strip().lower()
        if v:
            keys.add(v)
    return keys


@app.route("/inventory")
@auth.login_required
def inventory():
    db = get_db()
    rows = db.execute("SELECT * FROM assets ORDER BY "
                      "CASE criticality WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
                      "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, hostname, ip").fetchall()
    assessed = _assessed_keys(db)
    assets = []
    counts = {"total": 0, "ot": 0, "do_not_scan": 0, "never_assessed": 0, "unclassified": 0}
    for r in rows:
        a = dict(r)
        ipk = (a.get("ip") or "").strip().lower()
        hnk = (a.get("hostname") or "").strip().lower()
        a["assessed"] = (ipk in assessed) or (hnk in assessed)
        assets.append(a)
        counts["total"] += 1
        if a["asset_type"] == "OT":
            counts["ot"] += 1
        if not a["scan_eligible"]:
            counts["do_not_scan"] += 1
        if not a["assessed"]:
            counts["never_assessed"] += 1
        if not a["criticality"] or a["asset_type"] == "Unknown":
            counts["unclassified"] += 1
    conn = _zoho_conn(db)
    zoho_ready = (zoho.secrets_configured() and conn["owner"] and conn["app"]
                  and conn["report"])
    return render_template("inventory.html", assets=assets, counts=counts,
                           types=asset_classify.TYPES, crits=asset_classify.CRITICALITY,
                           policies=sorted(set(asset_classify.SCAN_POLICY.values())),
                           zoho_ready=zoho_ready,
                           zoho_status={"status": get_setting(db, "zoho_last_status", ""),
                                        "detail": get_setting(db, "zoho_last_detail", ""),
                                        "at": get_setting(db, "zoho_last_at", "")},
                           can_manage=auth.can_import_or_scan(auth.current_user(db)))


@app.route("/inventory/import", methods=["GET", "POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def inventory_import():
    if request.method == "GET":
        return render_template("inventory_import.html")
    db = get_db()
    me = auth.current_user(db)
    file = request.files.get("file")
    if not file or not file.filename:
        flash("Choose an Excel (.xlsx) or CSV file to import.")
        return redirect(url_for("inventory_import"))
    try:
        headers, data_rows = _read_asset_rows(file)
    except Exception as e:
        flash(f"Could not read that file: {e}")
        return redirect(url_for("inventory_import"))
    if not headers:
        flash("That file appears to be empty.")
        return redirect(url_for("inventory_import"))
    mapping = asset_classify.map_headers(headers)
    if "ip" not in mapping and "hostname" not in mapping:
        flash("Couldn't find an IP or hostname column. Expected a header like "
              "'IP Address' or 'Hostname'. You can download the template for the layout.")
        return redirect(url_for("inventory_import"))
    now = datetime.now().isoformat(timespec="seconds")
    added = 0
    for raw in data_rows:
        rowdict = {}
        for canon, idx in mapping.items():
            if idx < len(raw):
                rowdict[canon] = raw[idx]
        if not (str(rowdict.get("ip") or "").strip() or str(rowdict.get("hostname") or "").strip()):
            continue
        a = asset_classify.classify(rowdict)
        db.execute(
            "INSERT INTO assets(ip, hostname, description, owner, criticality, asset_type,"
            " scan_policy, scan_eligible, classify_reason, source, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (a["ip"], a["hostname"], a["description"], a["owner"], a["criticality"],
             a["asset_type"], a["scan_policy"], a["scan_eligible"], a["classify_reason"],
             f"import:{os.path.basename(file.filename)[:80]}", now, now))
        added += 1
    db.commit()
    auth.log_activity(db, me["id"], None, "inventory", f"imported {added} assets")
    flash(f"Imported {added} assets. Review the classifications below — OT is marked do-not-scan.")
    return redirect(url_for("inventory"))


@app.route("/inventory/template")
@auth.login_required
def inventory_template():
    import openpyxl
    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = "Assets"
    ws.append(["IP Address", "Hostname", "Description", "Criticality", "Type", "Owner"])
    ws.append(["10.20.4.11", "core-sw-01", "Core switch", "Critical", "Network", "Network Team"])
    ws.append(["10.20.8.23", "db-prod-02", "Production database", "Critical", "IT", "Database Team"])
    ws.append(["10.30.1.5", "plc-line3", "Siemens S7 PLC (do not scan)", "High", "OT", "Plant"])
    ws.append(["10.40.2.7", "jdoe-laptop", "Employee laptop", "Low", "BYOD", "IT"])
    buf = io.BytesIO()
    wb.save(buf)
    buf.seek(0)
    return send_file(buf, mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                     as_attachment=True, download_name="asset_inventory_template.xlsx")


@app.route("/inventory/<int:aid>/edit", methods=["POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def inventory_edit(aid):
    db = get_db()
    me = auth.current_user(db)
    row = db.execute("SELECT * FROM assets WHERE id=?", (aid,)).fetchone()
    if not row:
        abort(404)
    crit = request.form.get("criticality", "").strip()
    atype = request.form.get("asset_type", "").strip() or row["asset_type"]
    policy = asset_classify.SCAN_POLICY.get(atype, "Review before scanning")
    scan_eligible = 0 if policy == "Do not actively scan" else 1
    authorized_by = request.form.get("authorized_by", "").strip()
    now = datetime.now().isoformat(timespec="seconds")
    authorized_at = row["authorized_at"]
    if authorized_by and not authorized_at:
        authorized_at = now
    if not authorized_by:
        authorized_at = None
    db.execute("UPDATE assets SET criticality=?, asset_type=?, scan_policy=?, scan_eligible=?,"
               " authorized_by=?, authorized_at=?, classify_reason=?, updated_at=? WHERE id=?",
               (crit, atype, policy, scan_eligible, authorized_by or None, authorized_at,
                "edited by " + (me["display_name"] or me["username"]), now, aid))
    db.commit()
    auth.log_activity(db, me["id"], None, "inventory", f'updated asset {row["hostname"] or row["ip"]}')
    flash("Asset updated.")
    return redirect(url_for("inventory"))


@app.route("/inventory/<int:aid>/delete", methods=["POST"])
@auth.login_required
@auth.role_required("editor", "admin")
def inventory_delete(aid):
    db = get_db()
    me = auth.current_user(db)
    db.execute("DELETE FROM assets WHERE id=?", (aid,))
    db.commit()
    auth.log_activity(db, me["id"], None, "inventory", "removed an asset")
    flash("Asset removed.")
    return redirect(url_for("inventory"))


def _form_to_dict(form):
    d = {}
    for col in INPUT_COLUMNS:
        if col == "source_tool":
            continue
        d[col] = form.get(col, "").strip()
    # normalise dates to ISO for storage
    for dc in DATE_COLUMNS:
        pd = parse_date(d.get(dc))
        d[dc] = iso(pd)
    # Only set source_tool when the form actually carries it (the edit form does
    # not), so editing a finding never clobbers its real origin (Nessus, etc.).
    if form.get("source_tool"):
        d["source_tool"] = form.get("source_tool")
    # CVSS: capture only when the field is present on the form, so unrelated
    # posts never blank a stored score. Normalised so score and vector are valid.
    if "cvss_score" in form or "cvss_vector" in form:
        score, vector, _band = cvss_mod.normalize(
            form.get("cvss_score", "").strip(), form.get("cvss_vector", "").strip())
        d["cvss_score"] = score
        d["cvss_vector"] = vector
    return d


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
_KEV_NOTE = ("Actively exploited in the wild — this CVE is listed in the loaded threat feed's "
             "Known Exploited Vulnerabilities (KEV) catalogue. Treat as an urgent priority.")
_FEED_NOTE = "This CVE appears in the loaded threat feed."


def _kev_crossref(db, d):
    """Cross-reference a finding's CVE(s) against the threat_feed table.

    If any referenced CVE is flagged KEV (actively exploited), set
    exploit_available='Yes' so the risk engine auto-escalates the actual risk,
    and annotate the finding. If a CVE is merely present in the feed, add a
    lighter note. Mutates d in place. No-op when the feed is empty or the
    finding carries no CVE id (so it never invents exploitation).
    """
    ids = [m.upper() for m in _CVE_RE.findall(d.get("cve") or "")]
    if not ids:
        return
    seen = set()
    uniq = [i for i in ids if not (i in seen or seen.add(i))]
    rows = db.execute(
        "SELECT cve, kev FROM threat_feed WHERE UPPER(cve) IN (%s)"
        % ",".join("?" for _ in uniq),
        uniq,
    ).fetchall()
    if not rows:
        return
    kev = any(r["kev"] for r in rows)
    note = _KEV_NOTE if kev else _FEED_NOTE
    if kev:
        d["exploit_available"] = "Yes"
    existing = (d.get("definition") or "").strip()
    if note not in existing:
        d["definition"] = (existing + " " + note).strip()


def _insert_finding_db(db, d, scan_id=None):
    """Insert one finding using an explicit db connection. Shared by the request
    path and the background scan scheduler (which has no request context)."""
    now = datetime.now().isoformat(timespec="seconds")
    # Normalise any CVSS the finding carries, then cross-reference exploitation
    # against the threat feed before storing (so stored exploit_available feeds
    # the risk engine on every read).
    score, vector, _band = cvss_mod.normalize(d.get("cvss_score"), d.get("cvss_vector") or "")
    _kev_crossref(db, d)
    cols = INPUT_COLUMNS + ["cvss_score", "cvss_vector", "scan_id", "created_at", "updated_at"]
    vals = [d.get(c, "") for c in INPUT_COLUMNS] + [score, vector, scan_id, now, now]
    placeholders = ", ".join("?" for _ in cols)
    db.execute(f"INSERT INTO findings ({', '.join(cols)}) VALUES ({placeholders})", vals)
    db.commit()


def _insert_finding(d, scan_id=None):
    _insert_finding_db(get_db(), d, scan_id)


def _update_finding(fid, d):
    db = get_db()
    row = db.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
    # If status is being set to closing and no actual fix date provided, stamp today.
    if (d.get("remediation_status") in engine.CLOSING_STATUSES
            and not d.get("actual_fix_date") and not row["actual_fix_date"]):
        d["actual_fix_date"] = date.today().isoformat()
    d["updated_at"] = datetime.now().isoformat(timespec="seconds")
    sets = ", ".join(f"{k}=?" for k in d)
    db.execute(f"UPDATE findings SET {sets} WHERE id=?", (*d.values(), fid))
    db.commit()


# ---------------------------------------------------------------------------
# Routes: import scans
# ---------------------------------------------------------------------------
@app.route("/import", methods=["GET", "POST"])
@auth.role_required("admin", "editor")
def import_scan():
    if request.method == "POST":
        files = request.files.getlist("scanfile")
        detection = request.form.get("detection_date", "").strip()
        detection_iso = iso(parse_date(detection)) or date.today().isoformat()
        default_owner = request.form.get("default_owner", "").strip()
        default_class = request.form.get("default_classification", "").strip()
        total = 0
        errors = []
        for f in files:
            if not f or not f.filename:
                continue
            raw = f.read()
            try:
                label, findings = detect_and_parse(raw, f.filename)
            except ValueError as e:
                errors.append(f"{f.filename}: {e}")
                continue
            db = get_db()
            db.execute(
                "INSERT INTO scans(name, scan_date, source_tool, imported_at) VALUES (?,?,?,?)",
                (f.filename, detection_iso, label, datetime.now().isoformat(timespec="seconds")),
            )
            scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
            for fx in findings:
                rec = {c: "" for c in INPUT_COLUMNS}
                rec.update({
                    "ip_hostname": fx.get("ip_hostname", ""),
                    "device": fx.get("device", ""),
                    "asset_classification": default_class,  # analyst sets per-asset criticality
                    "vulnerability": fx.get("vulnerability", ""),
                    "synopsis": fx.get("synopsis", ""),
                    "definition": fx.get("definition", ""),
                    "cve": fx.get("cve", ""),
                    "reported_risk": fx.get("reported_risk", ""),
                    "exploit_available": fx.get("exploit_available", "Unknown"),
                    "exploit_reference": fx.get("exploit_reference", ""),
                    "solution": fx.get("solution", ""),
                    "asset_owner": default_owner,
                    "detection_date": detection_iso,
                    "remediation_status": "Pending",
                    "exception_requested": "No",
                    "source_tool": fx.get("source_tool", label),
                    "cvss_score": fx.get("cvss_score"),
                    "cvss_vector": fx.get("cvss_vector", ""),
                })
                _insert_finding(rec, scan_id=scan_id)
                total += 1
        if errors:
            flash("Some files could not be read: " + "; ".join(errors))
        me = auth.current_user(get_db())
        auth.log_activity(get_db(), me["id"], None, "import", f"Imported {total} findings")
        flash(f"Imported {total} findings.")
        return redirect(url_for("index"))
    return render_template(
        "import.html", owners=owner_list(), severities=engine.SEVERITIES,
        today=date.today().isoformat(),
    )


# ---------------------------------------------------------------------------
# Routes: built-in scanner
# ---------------------------------------------------------------------------
# In-memory registry of running scans. Keyed by job id. Each job holds progress
# lines, status, and (when done) the findings awaiting review.
SCAN_JOBS = {}


@app.route("/scan", methods=["GET"])
@auth.role_required("admin", "editor")
def scan_page():
    db = get_db()
    # scan-eligible assets from the register (OT / protected assets are excluded
    # by scan_eligible=0, so they can never be ticked here)
    eligible = db.execute(
        "SELECT ip, hostname, criticality, asset_type FROM assets "
        "WHERE scan_eligible=1 AND ip IS NOT NULL AND ip != '' "
        "ORDER BY CASE criticality WHEN 'Critical' THEN 0 WHEN 'High' THEN 1 "
        "WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END, hostname, ip").fetchall()
    protected = db.execute(
        "SELECT COUNT(*) n FROM assets WHERE scan_eligible=0").fetchone()["n"]
    return render_template(
        "scan.html", owners=owner_list(), severities=engine.SEVERITIES,
        today=date.today().isoformat(), eligible=[dict(r) for r in eligible],
        protected_count=protected,
        default_ports=",".join(str(p) for p in scanner_mod.DEFAULT_PORTS),
        scan_profiles=scanner_mod.SCAN_PROFILES,
    )


def _safe_port(raw, default=22):
    try:
        p = int(str(raw).strip())
        return p if 1 <= p <= 65535 else default
    except (TypeError, ValueError):
        return default


@app.route("/scan/start", methods=["POST"])
@auth.role_required("admin", "editor")
def scan_start():
    # targets come from two places: assets ticked from the register, plus any
    # free-text IPs/ranges typed in. We union them.
    picked = request.form.getlist("asset_ip")
    typed = request.form.get("targets", "").strip()
    parts = [p for p in picked if p.strip()]
    if typed:
        parts.append(typed)
    targets = "\n".join(parts).strip()
    if not targets:
        flash("Tick at least one asset to scan, or type a target IP, range or CIDR.")
        return redirect(url_for("scan_page"))
    # Port scope: a named profile, or a custom typed list that overrides it.
    profile = request.form.get("profile", "standard").strip().lower()
    ports_raw = request.form.get("ports", "").strip()
    ports = None
    if profile == "custom" and ports_raw:
        try:
            ports = [int(p) for p in ports_raw.replace(",", " ").split()]
        except ValueError:
            ports = None
    elif profile != "custom":
        ports = scanner_mod.profile_ports(profile)  # None -> scanner default
        # a custom list typed alongside a profile still refines it, if valid
        if ports_raw:
            try:
                ports = [int(p) for p in ports_raw.replace(",", " ").split()]
            except ValueError:
                pass
    # Governance: assets the register marks do-not-actively-scan (OT/protected)
    db = get_db()
    blocklist = [r["ip"] for r in db.execute(
        "SELECT ip FROM assets WHERE scan_eligible=0 AND ip IS NOT NULL AND ip != ''")]
    job_id = uuid.uuid4().hex[:12]
    job = {
        "id": job_id,
        "status": "running",
        "progress": (["Scan queued…"] +
                     ([f"Governance: {len(blocklist)} protected (do-not-scan) asset(s) "
                       "will be skipped."] if blocklist else [])),
        "findings": [],
        "targets": targets,
        "detection_date": request.form.get("detection_date", "").strip() or date.today().isoformat(),
        "default_owner": request.form.get("default_owner", "").strip(),
        "default_classification": request.form.get("default_classification", "").strip(),
        "assume_up": request.form.get("assume_up") == "on",
        "do_tls": request.form.get("do_tls", "on") == "on",
        "do_http": request.form.get("do_http", "on") == "on",
        "ips": [],
        "committed": False,
        "authenticated": request.form.get("auth_enable") == "on",
    }
    SCAN_JOBS[job_id] = job

    # Credentials for the optional authenticated audit live ONLY in this local
    # variable for the lifetime of the run — never stored on the job dict that
    # the status endpoint reads, never written to the database or disk.
    creds = None
    if job["authenticated"]:
        creds = {
            "username": request.form.get("ssh_username", "").strip(),
            "password": request.form.get("ssh_password", ""),
            "key_data": request.form.get("ssh_key", ""),
            "port": _safe_port(request.form.get("ssh_port", "22")),
        }

    def run():
        def progress(msg):
            job["progress"].append(msg)
            # keep last 200 lines
            if len(job["progress"]) > 200:
                job["progress"] = job["progress"][-200:]
        try:
            ips, findings = scanner_mod.scan_targets(
                targets, ports=ports, do_tls=job["do_tls"], do_http=job["do_http"],
                progress=progress, assume_up=job["assume_up"], blocklist=blocklist,
            )
            job["ips"] = ips
            job["findings"] = findings
            job["progress"].append(f"Network scan done. {len(ips)} host(s) probed, {len(findings)} finding(s).")
            # ---- optional read-only credentialed audit (SSH) ----
            if creds and ips:
                if not cred_audit.paramiko_available():
                    job["progress"].append(
                        "Authenticated audit skipped: the 'paramiko' package isn't installed on "
                        "this Argus host. Install it (pip install paramiko) to enable SSH audits.")
                elif not creds["username"] or not (creds["password"] or creds["key_data"]):
                    job["progress"].append(
                        "Authenticated audit skipped: an SSH username and a password or key are required.")
                else:
                    job["progress"].append(f"Starting read-only credentialed audit on {len(ips)} host(s)…")
                    ok = fail = 0
                    for ip in ips:
                        try:
                            run_cmd, close = cred_audit.make_ssh_runner(
                                ip, port=creds["port"], username=creds["username"],
                                password=creds["password"], key_data=creds["key_data"])
                        except cred_audit.CredAuditUnavailable as e:
                            fail += 1
                            progress(f"{ip}: credentialed audit unavailable — {e}")
                            continue
                        try:
                            hf = cred_audit.audit_host(ip, run_cmd)
                            job["findings"].extend(hf)
                            ok += 1
                            progress(f"{ip}: credentialed audit added {len(hf)} finding(s).")
                        finally:
                            close()
                    job["progress"].append(
                        f"Credentialed audit done: {ok} host(s) audited, {fail} unreachable/auth-failed.")
            job["progress"].append(f"Done. {len(job['findings'])} finding(s) total.")
            job["status"] = "done"
        except Exception as e:
            job["progress"].append(f"Scan error: {e}")
            job["status"] = "error"
        finally:
            # scrub credentials from memory as soon as the run ends
            if creds is not None:
                for k in list(creds):
                    creds[k] = None

    threading.Thread(target=run, daemon=True).start()
    return redirect(url_for("scan_progress", job_id=job_id))


@app.route("/scan/<job_id>")
@auth.role_required("admin", "editor")
def scan_progress(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        abort(404)
    return render_template("scan_progress.html", job=job)


@app.route("/scan/<job_id>/status")
@auth.role_required("admin", "editor")
def scan_status(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        return jsonify({"status": "missing"}), 404
    return jsonify({
        "status": job["status"],
        "progress": job["progress"][-40:],
        "finding_count": len(job["findings"]),
        "host_count": len(job["ips"]),
    })


@app.route("/scan/<job_id>/commit", methods=["POST"])
@auth.role_required("admin", "editor")
def scan_commit(job_id):
    job = SCAN_JOBS.get(job_id)
    if not job:
        abort(404)
    if job["committed"]:
        flash("These results were already added.")
        return redirect(url_for("index"))
    db = get_db()
    me = auth.current_user(db)
    db.execute(
        "INSERT INTO scans(name, scan_date, source_tool, imported_at) VALUES (?,?,?,?)",
        (f"Built-in scan: {job['targets'][:60]}", job["detection_date"],
         "Built-in scanner", datetime.now().isoformat(timespec="seconds")),
    )
    scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    for fx in job["findings"]:
        rec = {c: "" for c in INPUT_COLUMNS}
        rec.update({
            "ip_hostname": fx.get("ip_hostname", ""),
            "device": fx.get("device", ""),
            "asset_classification": job["default_classification"],
            "vulnerability": fx.get("vulnerability", ""),
            "synopsis": fx.get("synopsis", ""),
            "definition": fx.get("definition", ""),
            "cve": fx.get("cve", ""),
            "reported_risk": fx.get("reported_risk", ""),
            "exploit_available": fx.get("exploit_available", "Unknown"),
            "exploit_reference": fx.get("exploit_reference", ""),
            "solution": fx.get("solution", ""),
            "asset_owner": job["default_owner"],
            "detection_date": job["detection_date"],
            "remediation_status": "Pending",
            "exception_requested": "No",
            "source_tool": fx.get("source_tool", "Built-in scanner"),
            "cvss_score": fx.get("cvss_score"),
            "cvss_vector": fx.get("cvss_vector", ""),
        })
        _insert_finding(rec, scan_id=scan_id)
    job["committed"] = True
    auth.log_activity(db, me["id"], None, "scan",
                      f"Added {len(job['findings'])} findings from scan of {job['targets'][:60]}")
    flash(f"Added {len(job['findings'])} findings from the scan.")
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Scheduled scans — recurring, unattended, NETWORK-ONLY.
#
# Scheduled runs are deliberately network-only: credentialed audits need
# credentials, which Argus never stores, so they are run interactively only.
# A single daemon thread wakes once a minute, runs any due schedule and
# auto-commits its findings as a new scan. It uses its own sqlite connection
# (no request/g context) and the shared _insert_finding_db core.
# ---------------------------------------------------------------------------
INTERVAL_PRESETS = [
    (6, "Every 6 hours"), (12, "Every 12 hours"), (24, "Daily"),
    (72, "Every 3 days"), (168, "Weekly"), (336, "Every 2 weeks"), (720, "Monthly"),
]


def _schedule_ports(s):
    prof = (s["profile"] or "standard").strip().lower()
    raw = (s["ports"] or "").strip()
    if prof == "custom" and raw:
        try:
            return [int(p) for p in raw.replace(",", " ").split()]
        except ValueError:
            return None
    if prof != "custom":
        return scanner_mod.profile_ports(prof)
    return None


def _run_one_schedule(db, s):
    """Execute one schedule row against its targets and auto-commit findings.
    Returns a short human-readable result string."""
    blocklist = [r["ip"] for r in db.execute(
        "SELECT ip FROM assets WHERE scan_eligible=0 AND ip IS NOT NULL AND ip != ''")]
    ips, findings = scanner_mod.scan_targets(
        s["targets"], ports=_schedule_ports(s),
        do_tls=bool(s["do_tls"]), do_http=bool(s["do_http"]),
        assume_up=bool(s["assume_up"]), blocklist=blocklist,
    )
    today = date.today().isoformat()
    db.execute(
        "INSERT INTO scans(name, scan_date, source_tool, imported_at) VALUES (?,?,?,?)",
        (f"Scheduled: {s['name']}", today, "Built-in scanner (scheduled)",
         datetime.now().isoformat(timespec="seconds")),
    )
    scan_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
    for fx in findings:
        rec = {c: "" for c in INPUT_COLUMNS}
        rec.update({
            "ip_hostname": fx.get("ip_hostname", ""), "device": fx.get("device", ""),
            "asset_classification": s["default_classification"] or "",
            "vulnerability": fx.get("vulnerability", ""), "synopsis": fx.get("synopsis", ""),
            "definition": fx.get("definition", ""), "cve": fx.get("cve", ""),
            "reported_risk": fx.get("reported_risk", ""),
            "exploit_available": fx.get("exploit_available", "Unknown"),
            "exploit_reference": fx.get("exploit_reference", ""),
            "solution": fx.get("solution", ""),
            "asset_owner": s["default_owner"] or "", "detection_date": today,
            "remediation_status": "Pending", "exception_requested": "No",
            "source_tool": fx.get("source_tool", "Built-in scanner (scheduled)"),
            "cvss_score": fx.get("cvss_score"), "cvss_vector": fx.get("cvss_vector", ""),
        })
        _insert_finding_db(db, rec, scan_id=scan_id)
    return f"{len(ips)} host(s) probed, {len(findings)} finding(s) added"


def _scheduler_tick():
    """Run all schedules that are due. Separate connection; safe to call from a
    thread. Each schedule's failure is isolated so one bad row can't stall others."""
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    try:
        now = datetime.now()
        now_iso = now.isoformat(timespec="seconds")
        due = db.execute(
            "SELECT * FROM scan_schedule WHERE enabled=1 AND (next_run IS NULL OR next_run<=?)",
            (now_iso,)).fetchall()
        for s in due:
            try:
                res = _run_one_schedule(db, s)
                stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                result = f"{stamp}: {res}"
            except Exception as e:
                stamp = datetime.now().strftime("%Y-%m-%d %H:%M")
                result = f"{stamp}: error — {e}"
            hrs = max(1, int(s["interval_hours"] or 168))
            nxt = (datetime.now() + timedelta(hours=hrs)).isoformat(timespec="seconds")
            db.execute(
                "UPDATE scan_schedule SET last_run=?, next_run=?, last_result=? WHERE id=?",
                (now_iso, nxt, result, s["id"]))
            db.commit()
    finally:
        db.close()


_SCHEDULER_STARTED = False
_SCHEDULER_LOCK = threading.Lock()


def _scheduler_loop():
    while True:
        try:
            _scheduler_tick()
        except Exception:
            pass
        time.sleep(60)


def _ensure_scan_scheduler():
    """Start the scan scheduler thread once (idempotent). Single-process servers
    only, like the send worker."""
    global _SCHEDULER_STARTED
    with _SCHEDULER_LOCK:
        if _SCHEDULER_STARTED:
            return
        _SCHEDULER_STARTED = True
        threading.Thread(target=_scheduler_loop, daemon=True).start()


def _next_run_for(hours):
    return (datetime.now() + timedelta(hours=max(1, int(hours or 168)))).isoformat(timespec="seconds")


@app.route("/schedules")
@auth.role_required("admin", "editor")
def schedules():
    db = get_db()
    rows = [dict(r) for r in db.execute("SELECT * FROM scan_schedule ORDER BY name")]
    eligible = db.execute(
        "SELECT COUNT(*) n FROM assets WHERE scan_eligible=1 AND ip IS NOT NULL AND ip != ''"
    ).fetchone()["n"]
    return render_template(
        "schedules.html", schedules=rows, owners=owner_list(),
        severities=engine.SEVERITIES, scan_profiles=scanner_mod.SCAN_PROFILES,
        intervals=INTERVAL_PRESETS, eligible_count=eligible,
    )


@app.route("/schedules/add", methods=["POST"])
@auth.role_required("admin", "editor")
def schedule_add():
    db = get_db()
    me = auth.current_user(db)
    name = request.form.get("name", "").strip()
    targets = request.form.get("targets", "").strip()
    if not name or not targets:
        flash("A schedule needs a name and at least one target.")
        return redirect(url_for("schedules"))
    hrs = _safe_port(request.form.get("interval_hours", "168"), default=168)
    db.execute(
        "INSERT INTO scan_schedule(name, targets, profile, ports, interval_hours, "
        "do_tls, do_http, assume_up, default_owner, default_classification, enabled, "
        "next_run, created_by, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,1,?,?,?)",
        (name, targets, request.form.get("profile", "standard").strip().lower(),
         request.form.get("ports", "").strip(), hrs,
         1 if request.form.get("do_tls", "on") == "on" else 0,
         1 if request.form.get("do_http", "on") == "on" else 0,
         1 if request.form.get("assume_up") == "on" else 0,
         request.form.get("default_owner", "").strip(),
         request.form.get("default_classification", "").strip(),
         _next_run_for(hrs), me["username"], datetime.now().isoformat(timespec="seconds")),
    )
    db.commit()
    _ensure_scan_scheduler()
    flash(f"Schedule '{name}' created. First run is due {_next_run_for(hrs)[:16].replace('T',' ')}.")
    return redirect(url_for("schedules"))


@app.route("/schedules/<int:sid>/toggle", methods=["POST"])
@auth.role_required("admin", "editor")
def schedule_toggle(sid):
    db = get_db()
    row = db.execute("SELECT enabled FROM scan_schedule WHERE id=?", (sid,)).fetchone()
    if row:
        db.execute("UPDATE scan_schedule SET enabled=? WHERE id=?",
                   (0 if row["enabled"] else 1, sid))
        db.commit()
    return redirect(url_for("schedules"))


@app.route("/schedules/<int:sid>/run", methods=["POST"])
@auth.role_required("admin", "editor")
def schedule_run_now(sid):
    db = get_db()
    s = db.execute("SELECT * FROM scan_schedule WHERE id=?", (sid,)).fetchone()
    if not s:
        abort(404)

    def runner():
        rdb = sqlite3.connect(DB_PATH)
        rdb.row_factory = sqlite3.Row
        try:
            try:
                res = _run_one_schedule(rdb, s)
                result = f"{datetime.now().strftime('%Y-%m-%d %H:%M')}: {res} (manual run)"
            except Exception as e:
                result = f"{datetime.now().strftime('%Y-%m-%d %H:%M')}: error — {e}"
            rdb.execute("UPDATE scan_schedule SET last_run=?, last_result=? WHERE id=?",
                        (datetime.now().isoformat(timespec="seconds"), result, sid))
            rdb.commit()
        finally:
            rdb.close()

    threading.Thread(target=runner, daemon=True).start()
    flash("Running that schedule now — its findings will appear in the register shortly.")
    return redirect(url_for("schedules"))


@app.route("/schedules/<int:sid>/delete", methods=["POST"])
@auth.role_required("admin", "editor")
def schedule_delete(sid):
    db = get_db()
    db.execute("DELETE FROM scan_schedule WHERE id=?", (sid,))
    db.commit()
    flash("Schedule removed.")
    return redirect(url_for("schedules"))


# ---------------------------------------------------------------------------
# Remediation report — group open findings by the fix that resolves them.
# ---------------------------------------------------------------------------
@app.route("/remediation")
@auth.login_required
def remediation():
    db = get_db()
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings")]
    open_rows = [r for r in rows
                 if r.get("remediation_status") not in engine.CLOSING_STATUSES]
    groups = {}
    for r in open_rows:
        key = (r.get("solution") or "").strip() or "(no remediation step recorded)"
        g = groups.setdefault(key, {
            "solution": key, "count": 0, "hosts": set(), "cves": set(),
            "vulns": set(), "max_rank": -1, "max_sev": ""})
        g["count"] += 1
        if r.get("ip_hostname"):
            g["hosts"].add(r["ip_hostname"])
        for c in re.findall(r"CVE-\d{4}-\d{4,7}", r.get("cve") or "", re.I):
            g["cves"].add(c.upper())
        if r.get("vulnerability"):
            g["vulns"].add(r["vulnerability"])
        rank = compliance.SEV_RANK.get(r.get("actual_risk_classification"), 0)
        if rank > g["max_rank"]:
            g["max_rank"] = rank
            g["max_sev"] = r.get("actual_risk_classification") or ""
    group_list = []
    for g in groups.values():
        g["host_count"] = len(g["hosts"])
        g["hosts"] = sorted(g["hosts"])
        g["cves"] = sorted(g["cves"])
        g["vulns"] = sorted(g["vulns"])
        group_list.append(g)
    group_list.sort(key=lambda g: (-g["max_rank"], -g["count"]))
    return render_template(
        "remediation.html", groups=group_list,
        total_open=len(open_rows), action_count=len(group_list),
    )


# ---------------------------------------------------------------------------
# Routes: asset owners management
# ---------------------------------------------------------------------------
@app.route("/owners", methods=["GET", "POST"])
@auth.role_required("admin", "editor")
def owners():
    db = get_db()
    if request.method == "POST":
        # Create a team owner (a plain name). User-owners are created from the
        # "link a user" form below, which carries kind=user.
        name = request.form.get("name", "").strip()
        if name:
            db.execute("INSERT OR IGNORE INTO asset_owners(name, kind) VALUES (?, 'team')", (name,))
            db.commit()
        return redirect(url_for("owners"))
    owners_rows = owner_directory()
    # users not yet linked as a user-owner, offered in the "add a person" picker
    linked = {r["user_id"] for r in owners_rows if r["user_id"]}
    users = db.execute("SELECT id, display_name, username, email FROM users WHERE active=1 "
                       "ORDER BY display_name, username").fetchall()
    free_users = [u for u in users if u["id"] not in linked]
    # members for each team, for the expandable rows
    members = {}
    for o in owners_rows:
        if (o["kind"] or "team") == "team":
            members[o["id"]] = db.execute(
                "SELECT u.id, u.display_name, u.username FROM team_members tm "
                "JOIN users u ON u.id=tm.user_id WHERE tm.owner_id=? ORDER BY u.display_name",
                (o["id"],)).fetchall()
    return render_template("owners.html", owners=owners_rows, all_users=users,
                           free_users=free_users, members=members)


@app.route("/owners/add_person", methods=["POST"])
@auth.role_required("admin", "editor")
def owners_add_person():
    db = get_db()
    uid = request.form.get("user_id", "")
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None
    if not u:
        flash("Pick a user to add as an owner.")
        return redirect(url_for("owners"))
    name = (u["display_name"] or u["username"]).strip()
    # avoid a name clash with an existing owner
    existing = db.execute("SELECT id FROM asset_owners WHERE name=? COLLATE NOCASE", (name,)).fetchone()
    if existing:
        db.execute("UPDATE asset_owners SET kind='user', user_id=?, email=? WHERE id=?",
                   (u["id"], u["email"], existing["id"]))
    else:
        db.execute("INSERT INTO asset_owners(name, kind, user_id, email) VALUES (?, 'user', ?, ?)",
                   (name, u["id"], u["email"]))
    db.commit()
    flash(f"{name} can now be assigned assets and will be notified.")
    return redirect(url_for("owners"))


@app.route("/owners/<int:oid>/members/add", methods=["POST"])
@auth.role_required("admin", "editor")
def owners_member_add(oid):
    db = get_db()
    uid = request.form.get("user_id", "")
    owner = db.execute("SELECT * FROM asset_owners WHERE id=?", (oid,)).fetchone()
    if owner and (owner["kind"] or "team") == "team" and uid:
        db.execute("INSERT OR IGNORE INTO team_members(owner_id, user_id) VALUES (?, ?)", (oid, uid))
        db.commit()
    return redirect(url_for("owners"))


@app.route("/owners/<int:oid>/members/<int:uid>/remove", methods=["POST"])
@auth.role_required("admin", "editor")
def owners_member_remove(oid, uid):
    db = get_db()
    db.execute("DELETE FROM team_members WHERE owner_id=? AND user_id=?", (oid, uid))
    db.commit()
    return redirect(url_for("owners"))


@app.route("/owners/add_ajax", methods=["POST"])
@auth.role_required("admin", "editor")
def owners_add_ajax():
    db = get_db()
    name = request.json.get("name", "").strip()
    if name:
        db.execute("INSERT OR IGNORE INTO asset_owners(name, kind) VALUES (?, 'team')", (name,))
        db.commit()
    return jsonify({"ok": True, "owners": owner_list()})


@app.route("/owners/<int:oid>/delete", methods=["POST"])
@auth.role_required("admin", "editor")
def owners_delete(oid):
    db = get_db()
    db.execute("DELETE FROM asset_owners WHERE id=?", (oid,))
    db.execute("DELETE FROM team_members WHERE owner_id=?", (oid,))
    db.commit()
    return redirect(url_for("owners"))


# ---------------------------------------------------------------------------
# Routes: exports
# ---------------------------------------------------------------------------
@app.route("/export/excel")
@auth.login_required
def export_excel():
    from export_excel import build_excel
    db = get_db()
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings ORDER BY id")]
    bio = build_excel(rows)
    fname = f"VAPT_Report_{date.today().isoformat()}.xlsx"
    return send_file(bio, as_attachment=True, download_name=fname,
                     mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/export/pdf")
@auth.login_required
def export_pdf():
    from export_pdf import build_pdf
    db = get_db()
    rows = [enrich(r) for r in db.execute("SELECT * FROM findings ORDER BY id")]
    stats = {
        "total": len(rows),
        "critical": sum(1 for r in rows if r["actual_risk_classification"] == "Critical"),
        "high": sum(1 for r in rows if r["actual_risk_classification"] == "High"),
        "breached": sum(1 for r in rows if r["risk_tolerance_objective"] == "Breached"),
    }
    bio = build_pdf(rows, stats)
    fname = f"VAPT_Report_{date.today().isoformat()}.pdf"
    return send_file(bio, as_attachment=True, download_name=fname, mimetype="application/pdf")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    setup_needed = init_db()
    _ensure_send_worker()   # resume scheduled / interrupted send jobs
    _ensure_scan_scheduler()  # recurring network-only scans
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()
    if setup_needed:
        print("\n" + "=" * 64)
        print("  FIRST RUN — no accounts exist yet.")
        print(f"  Open  http://{args.host}:{args.port}/  in your browser and")
        print("  create your administrator account to get started.")
        print("  After that, add your team under 'Users' — each teammate sets")
        print("  their own password at first sign-in.")
        print("=" * 64 + "\n")
    print(f"Argus running at http://{args.host}:{args.port}  (DB: {DB_PATH})")
    app.run(host=args.host, port=args.port, debug=args.debug)
