"""
auth.py, local user accounts, roles, sessions and permissions.

All local, offline. Passwords are hashed with werkzeug's PBKDF2 (ships with
Flask, no extra dependency). Sessions are signed with a secret key that is
generated once and stored on disk so logins survive restarts.

Roles:
  admin , manage users + everything an editor can do
  editor, the security team: edit findings, change status, import, scan
  viewer, bosses, colleagues, asset owners: view everything and comment;
            may also change the status of a finding whose Asset Owner matches
            their account (owners self-report progress on their own assets)
"""
import functools
import os
import secrets
import sqlite3
from datetime import datetime

from flask import session, redirect, url_for, flash, g, request
from werkzeug.security import generate_password_hash, check_password_hash

ROLES = ["admin", "editor", "viewer"]
ROLE_LABELS = {
    "admin": "Admin",
    "editor": "Editor (security team)",
    "viewer": "Viewer / commenter",
}
ROLE_SUMMARY = {
    "admin": "Full control, plus managing accounts and settings.",
    "editor": "The security team: scan, import, and edit the register, findings, phishing and feeds.",
    "viewer": "Read-only across the app, with the ability to comment.",
}

# What each access level can do, drives the matrix on the admin console and
# documents the role_required() gates enforced on the routes.
PERMISSION_MATRIX = [
    ("View dashboards, findings & reports", {"admin": True, "editor": True, "viewer": True}),
    ("Comment on findings", {"admin": True, "editor": True, "viewer": True}),
    ("Edit findings & change remediation status", {"admin": True, "editor": True, "viewer": False}),
    ("Run / import scans & manage the asset register", {"admin": True, "editor": True, "viewer": False}),
    ("Run phishing campaigns & threat-feed updates", {"admin": True, "editor": True, "viewer": False}),
    ("Change settings & compliance frameworks", {"admin": True, "editor": False, "viewer": False}),
    ("Manage user accounts & access levels", {"admin": True, "editor": False, "viewer": False}),
]


# ---------------------------------------------------------------------------
# Secret key: generate once, persist, so sessions survive restarts.
# ---------------------------------------------------------------------------
def load_or_create_secret(app_dir):
    path = os.path.join(app_dir, ".secret_key")
    try:
        with open(path, "r") as f:
            k = f.read().strip()
            if k:
                return k
    except FileNotFoundError:
        pass
    k = secrets.token_hex(32)
    try:
        with open(path, "w") as f:
            f.write(k)
        os.chmod(path, 0o600)
    except OSError:
        pass
    return k


# ---------------------------------------------------------------------------
# Schema + first-run admin bootstrap
# ---------------------------------------------------------------------------
def init_auth_schema(db):
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            display_name TEXT,
            email TEXT,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'viewer',
            active INTEGER NOT NULL DEFAULT 1,
            must_change_pw INTEGER NOT NULL DEFAULT 0,
            created_at TEXT
        );
        CREATE TABLE IF NOT EXISTS comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            finding_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            body TEXT NOT NULL,
            created_at TEXT,
            FOREIGN KEY(finding_id) REFERENCES findings(id),
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        CREATE TABLE IF NOT EXISTS activity (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            finding_id INTEGER,
            action TEXT,
            detail TEXT,
            created_at TEXT
        );
        """
    )
    db.commit()


def needs_setup(db):
    """True when no accounts exist yet, the app should run first-run setup so
    the first administrator creates their own profile (rather than being handed
    a generated password)."""
    return db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


# ---------------------------------------------------------------------------
# User helpers
# ---------------------------------------------------------------------------
def get_user_by_username(db, username):
    return db.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE", (username,)).fetchone()


def get_user(db, user_id):
    return db.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()


def verify_login(db, username, password):
    u = get_user_by_username(db, username)
    if not u or not u["active"]:
        return None
    if check_password_hash(u["password_hash"], password):
        return u
    return None


def create_user(db, username, display_name, email, password, role, must_change=True):
    """Create an account. By default the user must change their password at
    first sign-in (must_change=True), used for admin-created teammate accounts.
    First-run setup passes must_change=False, since the admin just chose it."""
    cur = db.execute(
        "INSERT INTO users(username, display_name, email, password_hash, role, active, must_change_pw, created_at) "
        "VALUES (?,?,?,?,?,1,?,?)",
        (username, display_name, email, generate_password_hash(password), role,
         1 if must_change else 0, datetime.now().isoformat(timespec="seconds")),
    )
    db.commit()
    return cur.lastrowid


def set_password(db, user_id, password, clear_must_change=True):
    db.execute(
        "UPDATE users SET password_hash=?, must_change_pw=? WHERE id=?",
        (generate_password_hash(password), 0 if clear_must_change else 1, user_id),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Session / current user
# ---------------------------------------------------------------------------
def current_user(db):
    uid = session.get("uid")
    if not uid:
        return None
    u = get_user(db, uid)
    if u and u["active"]:
        return u
    return None


def login_user(user):
    session.clear()
    session["uid"] = user["id"]
    session.permanent = True


def logout_user():
    session.clear()


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------
def can_edit_finding(user, finding_row=None, db=None):
    """
    admin/editor can always edit. Any other user can change a finding when they
    own it: either the owner label matches their name/username, or (when db is
    given) the owner is a user-owner linked to them or a team they belong to.
    """
    if not user:
        return False
    if user["role"] in ("admin", "editor"):
        return True
    if finding_row is None:
        return False
    owner = (finding_row["asset_owner"] or "").strip()
    if not owner:
        return False
    if owner.lower() in ((user["display_name"] or "").strip().lower(),
                         (user["username"] or "").strip().lower()):
        return True
    if db is not None:
        row = db.execute("SELECT id, kind, user_id FROM asset_owners WHERE name=? COLLATE NOCASE",
                         (owner,)).fetchone()
        if row:
            if (row["kind"] or "team") == "user" and row["user_id"] == user["id"]:
                return True
            if db.execute("SELECT 1 FROM team_members WHERE owner_id=? AND user_id=?",
                          (row["id"], user["id"])).fetchone():
                return True
    return False


def can_import_or_scan(user):
    return bool(user) and user["role"] in ("admin", "editor")


def is_admin(user):
    return bool(user) and user["role"] == "admin"


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------
def login_required(view):
    @functools.wraps(view)
    def wrapped(*a, **kw):
        if not session.get("uid"):
            return redirect(url_for("login", next=request.path))
        return view(*a, **kw)
    return wrapped


def role_required(*roles):
    def deco(view):
        @functools.wraps(view)
        def wrapped(*a, **kw):
            if not session.get("uid"):
                return redirect(url_for("login", next=request.path))
            u = get_user(get_db_proxy(), session["uid"])
            if not u or u["role"] not in roles:
                flash("You don't have permission to do that.")
                return redirect(url_for("index"))
            return view(*a, **kw)
        return wrapped
    return deco


# the app injects its get_db here so the decorator can use it
_get_db = None
def register_db_getter(fn):
    global _get_db
    _get_db = fn
def get_db_proxy():
    return _get_db()


# ---------------------------------------------------------------------------
# Activity log
# ---------------------------------------------------------------------------
def log_activity(db, user_id, finding_id, action, detail=""):
    db.execute(
        "INSERT INTO activity(user_id, finding_id, action, detail, created_at) VALUES (?,?,?,?,?)",
        (user_id, finding_id, action, detail, datetime.now().isoformat(timespec="seconds")),
    )
    db.commit()
