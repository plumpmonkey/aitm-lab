"""
CorpSSO Identity Provider — Mock Corporate Single Sign-On Portal
=================================================================
A deliberately simple Flask application for the AitM lab exercise.
Implements username/password authentication with TOTP MFA and session
cookie issuance. Includes an admin log viewer for Phase 2 analysis.

THIS APPLICATION IS INTENTIONALLY INSECURE IN SPECIFIC WAYS TO SUPPORT
THE LAB EXERCISE. DO NOT DEPLOY IN ANY PRODUCTION CONTEXT.
"""

import os
import io
import json
import base64
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps

import pyotp
import qrcode
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, make_response, jsonify, g
)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "lab-secret-key-do-not-use")
app.config["SESSION_COOKIE_NAME"] = "_corpsso_sess"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(minutes=30)

DATABASE = "/app/data/corpsso.db"

# ---------------------------------------------------------------------------
# Deterministic TOTP secrets (so QR codes are identical across rebuilds)
# ---------------------------------------------------------------------------
USERS = [
    {
        "email": "alice.smith@corpsso.local",
        "password": "LabPassword123!",
        "name": "Alice Smith",
        "department": "Engineering",
        "totp_secret": "JBSWY3DPEHPK3PXP",  # Deterministic for lab reproducibility
    },
    {
        "email": "bob.jones@corpsso.local",
        "password": "LabPassword456!",
        "name": "Bob Jones",
        "department": "Marketing",
        "totp_secret": "KRSXG5CTMVRXEZLU",
    },
    {
        "email": "admin@corpsso.local",
        "password": "AdminLab789!",
        "name": "Admin User",
        "department": "IT Security",
        "totp_secret": "GEZDGNBVGY3TQOJQ",
    },
]


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Initialise the database schema and seed user accounts."""
    db = sqlite3.connect(DATABASE)
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            department TEXT,
            totp_secret TEXT NOT NULL,
            mfa_enrolled INTEGER DEFAULT 0
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            email TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            user_agent TEXT,
            event_type TEXT NOT NULL,
            outcome TEXT NOT NULL,
            details TEXT
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            source_ip TEXT NOT NULL,
            user_agent TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    """)

    for user in USERS:
        pw_hash = hashlib.sha256(user["password"].encode()).hexdigest()
        try:
            db.execute(
                "INSERT INTO users (email, password_hash, name, department, totp_secret) "
                "VALUES (?, ?, ?, ?, ?)",
                (user["email"], pw_hash, user["name"], user["department"], user["totp_secret"]),
            )
        except sqlite3.IntegrityError:
            pass  # User already exists

    db.commit()
    db.close()


def log_auth_event(email, event_type, outcome, details=None):
    """Record an authentication event for Phase 2 analysis."""
    db = get_db()
    db.execute(
        "INSERT INTO auth_logs (timestamp, email, source_ip, user_agent, event_type, outcome, details) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            datetime.now(timezone.utc).isoformat(),
            email,
            request.remote_addr,
            request.headers.get("User-Agent", "Unknown"),
            event_type,
            outcome,
            details,
        ),
    )
    db.commit()


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------
def get_current_user():
    """Retrieve the current authenticated user from the session token cookie."""
    token = request.cookies.get("session_token")
    if not token:
        return None
    db = get_db()
    sess = db.execute("SELECT * FROM sessions WHERE token = ?", (token,)).fetchone()
    if not sess:
        return None
    # Check expiry (30 minutes)
    created = datetime.fromisoformat(sess["created_at"])
    if datetime.now(timezone.utc) - created > timedelta(minutes=30):
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
        return None
    user = db.execute("SELECT * FROM users WHERE id = ?", (sess["user_id"],)).fetchone()
    return user


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return redirect(url_for("login"))
        g.user = user
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user or user["email"] != "admin@corpsso.local":
            return redirect(url_for("login"))
        g.user = user
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    user = get_current_user()
    if user:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        pw_hash = hashlib.sha256(password.encode()).hexdigest()

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE email = ? AND password_hash = ?",
            (email, pw_hash),
        ).fetchone()

        if user:
            log_auth_event(email, "login_attempt", "success", "Credentials valid")
            # Store user ID in session for MFA step
            session["pending_user_id"] = user["id"]
            session["pending_email"] = email

            if user["mfa_enrolled"]:
                return redirect(url_for("mfa_verify"))
            else:
                return redirect(url_for("mfa_setup"))
        else:
            log_auth_event(email, "login_attempt", "failure", "Invalid credentials")
            flash("Invalid email or password.", "error")

    return render_template("login.html")


@app.route("/mfa-setup", methods=["GET", "POST"])
def mfa_setup():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return redirect(url_for("login"))

    totp = pyotp.TOTP(user["totp_secret"])
    provisioning_uri = totp.provisioning_uri(
        name=user["email"], issuer_name="CorpSSO"
    )

    # Generate QR code as base64 image
    qr = qrcode.make(provisioning_uri)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    if request.method == "POST":
        token = request.form.get("totp_code", "").strip()
        if totp.verify(token, valid_window=1):
            db.execute("UPDATE users SET mfa_enrolled = 1 WHERE id = ?", (user_id,))
            db.commit()
            log_auth_event(user["email"], "mfa_enrol", "success", "TOTP enrolled")
            # Complete authentication
            return _create_session(user)
        else:
            log_auth_event(user["email"], "mfa_enrol", "failure", "Invalid TOTP code")
            flash("Invalid code. Please try again.", "error")

    return render_template(
        "mfa_setup.html",
        qr_code=qr_b64,
        secret=user["totp_secret"],
        email=user["email"],
    )


@app.route("/mfa-verify", methods=["GET", "POST"])
def mfa_verify():
    user_id = session.get("pending_user_id")
    if not user_id:
        return redirect(url_for("login"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        token = request.form.get("totp_code", "").strip()
        totp = pyotp.TOTP(user["totp_secret"])

        log_auth_event(user["email"], "mfa_challenge", "presented", "TOTP challenge sent")

        if totp.verify(token, valid_window=1):
            log_auth_event(user["email"], "mfa_verify", "success", "TOTP verified")
            return _create_session(user)
        else:
            log_auth_event(user["email"], "mfa_verify", "failure", "Invalid TOTP code")
            flash("Invalid code. Please try again.", "error")

    return render_template("mfa_verify.html", email=user["email"])


def _create_session(user):
    """Create an authenticated session and redirect to dashboard."""
    token = secrets.token_hex(32)
    db = get_db()
    db.execute(
        "INSERT INTO sessions (token, user_id, created_at, source_ip, user_agent) "
        "VALUES (?, ?, ?, ?, ?)",
        (
            token,
            user["id"],
            datetime.now(timezone.utc).isoformat(),
            request.remote_addr,
            request.headers.get("User-Agent", "Unknown"),
        ),
    )
    db.commit()

    log_auth_event(
        user["email"], "session_created", "success",
        f"Token: {token[:16]}... IP: {request.remote_addr}"
    )

    # Clear MFA flow state
    session.clear()

    response = make_response(redirect(url_for("dashboard")))
    response.set_cookie("session_token", token, httponly=True, samesite="Lax", path="/")
    return response


@app.route("/dashboard")
@login_required
def dashboard():
    user = g.user
    return render_template(
        "dashboard.html",
        user_name=user["name"],
        user_email=user["email"],
        user_department=user["department"],
    )


@app.route("/logout")
def logout():
    token = request.cookies.get("session_token")
    if token:
        db = get_db()
        user = get_current_user()
        if user:
            log_auth_event(user["email"], "logout", "success", "User logged out")
        db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        db.commit()
    session.clear()
    response = make_response(redirect(url_for("login")))
    response.delete_cookie("session_token")
    return response


# ---------------------------------------------------------------------------
# Admin routes (for Phase 2 analysis)
# ---------------------------------------------------------------------------
@app.route("/admin/logs")
@admin_required
def admin_logs():
    db = get_db()
    logs = db.execute(
        "SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()
    return render_template("admin_logs.html", logs=logs, user_name=g.user["name"])


@app.route("/admin/logs/json")
@admin_required
def admin_logs_json():
    db = get_db()
    logs = db.execute(
        "SELECT * FROM auth_logs ORDER BY timestamp DESC LIMIT 200"
    ).fetchall()
    return jsonify([dict(row) for row in logs])


# ---------------------------------------------------------------------------
# Stub for WebAuthn extension task
# ---------------------------------------------------------------------------
@app.route("/webauthn-setup")
@login_required
def webauthn_setup():
    return render_template("webauthn_stub.html", user_name=g.user["name"])


# ---------------------------------------------------------------------------
# Application entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    app.run(
        host="0.0.0.0",
        port=443,
        ssl_context=("/app/cert.pem", "/app/key.pem"),
        debug=False,
    )
