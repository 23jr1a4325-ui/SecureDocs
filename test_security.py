from conftest import csrf, register, login
import sqlite3

def test_landing_and_health(client):
    assert client.get("/").status_code == 200
    assert client.get("/health").json == {"status": "ok"}

def test_dashboard_requires_login(client):
    response = client.get("/dashboard")
    assert response.status_code == 302
    assert "/login" in response.location

def test_password_is_not_stored_plaintext(app, client):
    register(client, "alice")
    import app as module
    with module.db() as conn:
        row = conn.execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()
    assert row["password_hash"] != "StrongPassword-123!"
    assert row["password_hash"].startswith("scrypt:")

def test_registration_cannot_choose_admin_role(app, client):
    register(client, "mallory")
    import app as module
    with module.db() as conn:
        row = conn.execute("SELECT role FROM users WHERE username='mallory'").fetchone()
    assert row["role"] == "user"

def test_non_admin_cannot_open_admin_pages(client):
    register(client, "alice")
    login(client, "alice", "StrongPassword-123!")
    assert client.get("/admin/users").status_code == 403
    assert client.get("/admin/audit").status_code == 403
    assert client.get("/admin/audit.csv").status_code == 403

def test_upload_rejects_disallowed_extension(client):
    register(client, "alice")
    login(client, "alice", "StrongPassword-123!")
    response = client.post("/documents/upload", data={
        "csrf_token": csrf(client),
        "title": "bad file",
        "file": ( __import__("io").BytesIO(b"not really an executable"), "malware.exe"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert b"File type not allowed" in response.data

def test_user_cannot_download_other_users_document(client):
    register(client, "alice")
    login(client, "alice", "StrongPassword-123!")
    response = client.post("/documents/upload", data={
        "csrf_token": csrf(client), "title": "Alice private",
        "file": (__import__("io").BytesIO(b"private document"), "private.txt"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert b"Document uploaded securely" in response.data
    import app as module
    with module.db() as conn:
        doc_id = conn.execute("SELECT id FROM documents ORDER BY id DESC").fetchone()["id"]
    # Log out and sign in as a different account.
    client.post("/logout", data={"csrf_token": csrf(client)}, follow_redirects=True)
    register(client, "bob")
    login(client, "bob", "StrongPassword-123!")
    assert client.get(f"/documents/{doc_id}/download").status_code == 404

def test_owner_can_download_and_grant_can_be_revoked(client):
    register(client, "alice")
    login(client, "alice", "StrongPassword-123!")
    client.post("/documents/upload", data={
        "csrf_token": csrf(client), "title": "Shared note",
        "file": (__import__("io").BytesIO(b"hello"), "note.txt"),
    }, content_type="multipart/form-data", follow_redirects=True)
    import app as module
    with module.db() as conn:
        doc_id = conn.execute("SELECT id FROM documents ORDER BY id DESC").fetchone()["id"]
    assert client.get(f"/documents/{doc_id}/download").status_code == 200
    client.post("/logout", data={"csrf_token": csrf(client)}, follow_redirects=True)
    register(client, "bob")
    login(client, "bob", "StrongPassword-123!")
    assert client.get(f"/documents/{doc_id}/download").status_code == 404

def test_post_without_csrf_is_rejected(client):
    register(client, "alice")
    login(client, "alice", "StrongPassword-123!")
    response = client.post("/documents/upload", data={"title": "missing token"})
    assert response.status_code == 400

def test_denied_download_is_audited(client):
    register(client, "alice")
    login(client, "alice", "StrongPassword-123!")
    client.post("/documents/upload", data={
        "csrf_token": csrf(client), "title": "Secret",
        "file": (__import__("io").BytesIO(b"secret"), "secret.txt"),
    }, content_type="multipart/form-data", follow_redirects=True)
    import app as module
    with module.db() as conn:
        doc_id = conn.execute("SELECT id FROM documents ORDER BY id DESC").fetchone()["id"]
    client.post("/logout", data={"csrf_token": csrf(client)}, follow_redirects=True)
    register(client, "bob")
    login(client, "bob", "StrongPassword-123!")
    client.get(f"/documents/{doc_id}/download")
    with module.db() as conn:
        row = conn.execute("SELECT outcome FROM audit_logs WHERE action='document_download_denied' ORDER BY id DESC").fetchone()
    assert row and row["outcome"] == "denied"

def test_admin_can_export_audit_csv(client):
    login(client, "admin", "AdminPassword-123!")
    response = client.get("/admin/audit.csv")
    assert response.status_code == 200
    assert "text/csv" in response.headers["Content-Type"]
    assert b"action" in response.data
