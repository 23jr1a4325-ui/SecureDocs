import os
import io
import csv
import sqlite3
import secrets
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, send_file, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("SECUREDOCS_DATA_DIR", BASE_DIR / "instance"))
UPLOAD_DIR = DATA_DIR / "private_uploads"
DB_PATH = Path(os.environ.get("DATABASE_PATH", DATA_DIR / "securedocs.sqlite3"))
ALLOWED_EXTENSIONS = {"pdf", "txt", "csv", "doc", "docx", "png", "jpg", "jpeg"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024

app = Flask(__name__, instance_path=str(DATA_DIR), instance_relative_config=True)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", "dev-only-change-this-secret-before-deployment"),
    MAX_CONTENT_LENGTH=MAX_UPLOAD_BYTES,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
)
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def audit(conn, actor_id, action, document_id=None, outcome="success", details=""):
    # Do not put passwords, session IDs, or document contents in audit details.
    conn.execute(
        "INSERT INTO audit_logs(actor_id, action, document_id, outcome, details, created_at) VALUES(?,?,?,?,?,?)",
        (actor_id, action, document_id, outcome, details[:300], now()),
    )

def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','user')),
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER NOT NULL REFERENCES users(id),
            title TEXT NOT NULL,
            stored_name TEXT NOT NULL UNIQUE,
            original_name TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS document_grants (
            document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            can_read INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY(document_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
            action TEXT NOT NULL,
            document_id INTEGER,
            outcome TEXT NOT NULL,
            details TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL
        );
        """)
        count = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        # Bootstrap an admin only when the database is empty. Change credentials immediately.
        if count == 0:
            username = os.environ.get("BOOTSTRAP_ADMIN_USER", "admin")
            password = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD", "ChangeMe-123!")
            conn.execute(
                "INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                (username, generate_password_hash(password), "admin", now()),
            )

def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    with db() as conn:
        user = conn.execute("SELECT id,username,role,active FROM users WHERE id=?", (uid,)).fetchone()
    if not user or not user["active"]:
        session.clear()
        return None
    return user

def login_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapped

def admin_required(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        user = current_user()
        if user is None:
            return redirect(url_for("login", next=request.path))
        if user["role"] != "admin":
            with db() as conn:
                audit(conn, user["id"], "admin_route_denied", outcome="denied", details=request.path)
            abort(403)
        return fn(*args, **kwargs)
    return wrapped

def allowed_document(conn, user, doc_id):
    doc = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
    if not doc:
        return None
    if user["role"] == "admin" or doc["owner_id"] == user["id"]:
        return doc
    grant = conn.execute(
        "SELECT can_read FROM document_grants WHERE document_id=? AND user_id=?",
        (doc_id, user["id"]),
    ).fetchone()
    return doc if grant and grant["can_read"] else None

def extension_ok(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
    return response

@app.errorhandler(403)
def forbidden(_error):
    return render_template("error.html", code=403, message="You do not have permission to do that."), 403

@app.errorhandler(404)
def not_found(_error):
    return render_template("error.html", code=404, message="The requested page or document was not found."), 404

@app.errorhandler(413)
def too_large(_error):
    return render_template("error.html", code=413, message="Upload is too large. The maximum size is 10 MB."), 413

@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("landing.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    # Public self-registration creates ordinary users only. No client can choose admin role.
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) > 40 or not username.replace("_", "").isalnum():
            flash("Username must be 3–40 characters and contain only letters, numbers, or underscores.", "error")
        elif len(password) < 12:
            flash("Use a password with at least 12 characters.", "error")
        else:
            try:
                with db() as conn:
                    conn.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                                 (username, generate_password_hash(password), "user", now()))
                    user = conn.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
                    audit(conn, user["id"], "account_registered", details="role=user")
                flash("Account created. You can now sign in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("That username is already in use.", "error")
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with db() as conn:
            user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and user["active"] and check_password_hash(user["password_hash"], password):
                session.clear()
                session["user_id"] = user["id"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                audit(conn, user["id"], "login_success")
                return redirect(url_for("dashboard"))
            audit(conn, user["id"] if user else None, "login_failed", outcome="denied", details="invalid credentials or inactive account")
        flash("Invalid username or password.", "error")
    return render_template("login.html")

@app.route("/logout", methods=["POST"])
@login_required
def logout():
    user = current_user()
    with db() as conn:
        audit(conn, user["id"], "logout")
    session.clear()
    flash("You have signed out.", "success")
    return redirect(url_for("index"))

@app.before_request
def csrf_protection():
    # CSRF protection for every state-changing browser form.
    if request.method in {"POST", "PUT", "PATCH", "DELETE"} and request.endpoint not in {"login", "register"}:
        if current_user() is not None:
            supplied = request.form.get("csrf_token", "")
            expected = session.get("csrf_token", "")
            if not supplied or not expected or not secrets.compare_digest(supplied, expected):
                abort(400, description="Invalid or missing CSRF token.")

@app.context_processor
def inject_user():
    return {"signed_in_user": current_user(), "csrf_token": session.get("csrf_token", "")}

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    with db() as conn:
        if user["role"] == "admin":
            docs = conn.execute("""SELECT d.*, u.username AS owner_name FROM documents d JOIN users u ON u.id=d.owner_id ORDER BY d.created_at DESC""").fetchall()
        else:
            docs = conn.execute("""SELECT DISTINCT d.*, u.username AS owner_name FROM documents d
                JOIN users u ON u.id=d.owner_id
                LEFT JOIN document_grants g ON g.document_id=d.id AND g.user_id=?
                WHERE d.owner_id=? OR (g.user_id=? AND g.can_read=1)
                ORDER BY d.created_at DESC""", (user["id"], user["id"], user["id"])).fetchall()
        count_users = conn.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] if user["role"] == "admin" else None
    return render_template("dashboard.html", documents=docs, count_users=count_users)

@app.route("/documents/upload", methods=["POST"])
@login_required
def upload_document():
    user = current_user()
    file = request.files.get("file")
    title = request.form.get("title", "").strip()
    if not file or not file.filename:
        flash("Choose a file first.", "error")
        return redirect(url_for("dashboard"))
    safe_original = secure_filename(file.filename)
    if not safe_original or not extension_ok(safe_original):
        flash("File type not allowed. Allowed: PDF, TXT, CSV, DOC, DOCX, PNG, JPG.", "error")
        return redirect(url_for("dashboard"))
    payload = file.read(MAX_UPLOAD_BYTES + 1)
    if len(payload) > MAX_UPLOAD_BYTES:
        abort(413)
    if not title:
        title = safe_original[:120]
    stored = secrets.token_hex(24) + "." + safe_original.rsplit(".", 1)[1].lower()
    path = UPLOAD_DIR / stored
    path.write_bytes(payload)
    try:
        with db() as conn:
            cur = conn.execute("""INSERT INTO documents(owner_id,title,stored_name,original_name,size_bytes,created_at)
                VALUES(?,?,?,?,?,?)""", (user["id"], title[:120], stored, safe_original, len(payload), now()))
            doc_id = cur.lastrowid
            audit(conn, user["id"], "document_uploaded", doc_id, details=f"name={safe_original};bytes={len(payload)}")
        flash("Document uploaded securely.", "success")
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return redirect(url_for("dashboard"))

@app.route("/documents/<int:doc_id>/download")
@login_required
def download_document(doc_id):
    user = current_user()
    with db() as conn:
        doc = allowed_document(conn, user, doc_id)
        if not doc:
            audit(conn, user["id"], "document_download_denied", doc_id, "denied", "missing or no permission")
            abort(404)  # Conceal whether a protected document exists.
        path = UPLOAD_DIR / doc["stored_name"]
        if not path.is_file():
            audit(conn, user["id"], "document_file_missing", doc_id, "error")
            abort(404)
        audit(conn, user["id"], "document_downloaded", doc_id)
        stored_path = str(path)
        original_name = doc["original_name"]
    return send_file(stored_path, as_attachment=True, download_name=original_name, conditional=True)

@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@login_required
def delete_document(doc_id):
    user = current_user()
    with db() as conn:
        doc = allowed_document(conn, user, doc_id)
        if not doc or (user["role"] != "admin" and doc["owner_id"] != user["id"]):
            audit(conn, user["id"], "document_delete_denied", doc_id, "denied", "missing or no permission")
            abort(404)
        path = UPLOAD_DIR / doc["stored_name"]
        conn.execute("DELETE FROM documents WHERE id=?", (doc_id,))
        audit(conn, user["id"], "document_deleted", doc_id, details=doc["original_name"])
        path.unlink(missing_ok=True)
    flash("Document deleted.", "success")
    return redirect(url_for("dashboard"))

@app.route("/documents/<int:doc_id>/permissions", methods=["GET", "POST"])
@login_required
def document_permissions(doc_id):
    user = current_user()
    with db() as conn:
        doc = conn.execute("SELECT * FROM documents WHERE id=?", (doc_id,)).fetchone()
        if not doc:
            abort(404)
        if user["role"] != "admin" and doc["owner_id"] != user["id"]:
            audit(conn, user["id"], "permissions_route_denied", doc_id, "denied")
            abort(404)
        users = conn.execute("SELECT id,username FROM users WHERE active=1 AND id != ? ORDER BY username", (doc["owner_id"],)).fetchall()
        if request.method == "POST":
            target_id = request.form.get("user_id", type=int)
            grant = request.form.get("grant") == "yes"
            target = conn.execute("SELECT id FROM users WHERE id=? AND active=1", (target_id,)).fetchone()
            if not target or target_id == doc["owner_id"]:
                flash("Choose a valid user.", "error")
            elif grant:
                conn.execute("INSERT OR REPLACE INTO document_grants(document_id,user_id,can_read) VALUES(?,?,1)", (doc_id, target_id))
                audit(conn, user["id"], "document_access_granted", doc_id, details=f"user_id={target_id}")
                flash("Read access granted.", "success")
            else:
                conn.execute("DELETE FROM document_grants WHERE document_id=? AND user_id=?", (doc_id, target_id))
                audit(conn, user["id"], "document_access_revoked", doc_id, details=f"user_id={target_id}")
                flash("Read access revoked.", "success")
            return redirect(url_for("document_permissions", doc_id=doc_id))
        grants = conn.execute("""SELECT g.user_id,u.username FROM document_grants g JOIN users u ON u.id=g.user_id
            WHERE g.document_id=? AND g.can_read=1 ORDER BY u.username""", (doc_id,)).fetchall()
    return render_template("permissions.html", document=doc, users=users, grants=grants)

@app.route("/admin/users", methods=["GET", "POST"])
@admin_required
def admin_users():
    actor = current_user()
    with db() as conn:
        if request.method == "POST":
            uid = request.form.get("user_id", type=int)
            action = request.form.get("action")
            target = conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
            if not target:
                flash("User not found.", "error")
            elif uid == actor["id"]:
                flash("You cannot deactivate your own account here.", "error")
            elif target["role"] == "admin":
                flash("Admin accounts cannot be deactivated from this screen.", "error")
            elif action == "deactivate":
                conn.execute("UPDATE users SET active=0 WHERE id=?", (uid,))
                audit(conn, actor["id"], "user_deactivated", details=f"user_id={uid}")
                flash("User deactivated.", "success")
            elif action == "activate":
                conn.execute("UPDATE users SET active=1 WHERE id=?", (uid,))
                audit(conn, actor["id"], "user_activated", details=f"user_id={uid}")
                flash("User activated.", "success")
            return redirect(url_for("admin_users"))
        users = conn.execute("SELECT id,username,role,active,created_at FROM users ORDER BY id").fetchall()
    return render_template("admin_users.html", users=users)

@app.route("/admin/audit")
@admin_required
def audit_logs():
    with db() as conn:
        logs = conn.execute("""SELECT a.*,u.username FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id
            ORDER BY a.id DESC LIMIT 500""").fetchall()
    return render_template("audit.html", logs=logs)

@app.route("/admin/audit.csv")
@admin_required
def export_audit():
    with db() as conn:
        logs = conn.execute("""SELECT a.id,u.username,a.action,a.document_id,a.outcome,a.details,a.created_at
            FROM audit_logs a LEFT JOIN users u ON u.id=a.actor_id ORDER BY a.id DESC LIMIT 5000""").fetchall()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id","username","action","document_id","outcome","details","created_at"])
    writer.writerows([tuple(row) for row in logs])
    response = make_response(output.getvalue())
    response.headers["Content-Type"] = "text/csv; charset=utf-8"
    response.headers["Content-Disposition"] = "attachment; filename=securedocs-audit.csv"
    return response

@app.route("/health")
def health():
    try:
        with db() as conn:
            conn.execute("SELECT 1")
        return {"status": "ok"}, 200
    except sqlite3.Error:
        return {"status": "error"}, 503

init_db()

if __name__ == "__main__":
    # Debug must remain off by default.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
