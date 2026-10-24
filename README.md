# SecureDocs — Document Access Control System

A learning project built with Flask, SQLite, HTML, and CSS. It demonstrates authentication, server-side authorisation, private file storage, per-document read grants, audit logs, CSV export, and automated security tests.

> **Status:** This is a starter implementation. Run the tests and complete the deployment checks before submitting. Do not claim features you have not personally verified.

## Features
- Password hashing using Werkzeug.
- Public registration creates **ordinary users only**; role is never accepted from the registration form.
- Admin-only user management and audit log.
- Upload allowlist, filename sanitisation, random storage names, 10 MB limit, and private upload directory.
- Owners and admins can download documents; users with an explicit read grant can download them too.
- Server-side checks on every download/delete/permission operation.
- Access denials and sensitive document actions recorded in the audit trail.
- CSV export for administrators.
- CSRF token checks on authenticated state-changing forms and security response headers.
- Pytest tests for authentication, role escalation, IDOR-style download attempts, permissions, upload restrictions, and audit logs.

## Requirements
- Python 3.11 or 3.12
- Windows PowerShell (or macOS/Linux terminal)

## Local setup — Windows
Open PowerShell in the extracted `SecureDocs` folder.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:SECRET_KEY = "local-development-change-this"
$env:BOOTSTRAP_ADMIN_USER = "admin"
$env:BOOTSTRAP_ADMIN_PASSWORD = "ChangeMe-123!"
python app.py
```

Open `http://127.0.0.1:5000`. Change the bootstrap admin password before using the app for anything beyond a local demo. If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again.

## First login
- Username: `admin`
- Password: `ChangeMe-123!`

These defaults are for local demonstration only. Set `BOOTSTRAP_ADMIN_USER` and `BOOTSTRAP_ADMIN_PASSWORD` before the database is first created. If a database already exists, bootstrap credentials do not overwrite it. Do not publish a live deployment with a known default password.

Create a second account using **Register**. New accounts are ordinary users. Sign in as admin to view Users and Audit Log.

## Run tests
Stop the web server, activate `.venv`, then run:

```powershell
python -m pytest -q
```

Tests use a temporary test database and upload directory; they do not use your real local database.

## Main security decisions
1. **Deny by default:** a document is downloadable only by its owner, an admin, or a user with an explicit read grant.
2. **No direct public file URLs:** files are stored outside `static/` and sent only after an authorisation check.
3. **IDOR protection:** changing a document ID does not bypass `allowed_document`.
4. **No user-selected role:** registration always creates `role='user'`.
5. **Passwords:** hashes, not plaintext, are stored.
6. **Audit trail:** security-relevant actions are logged without storing passwords or document contents.
7. **Error concealment:** inaccessible and nonexistent document IDs both return 404.
8. **CSRF:** authenticated POST actions require a session token.
9. **Production secrets:** set a strong secret key using the host's environment settings. Never commit `.env`.

## Deploy on Render
The included `render.yaml` configures a persistent disk for SQLite and uploaded files. Create a Render account, connect your own GitHub repository, and deploy the Blueprint. When prompted, set `BOOTSTRAP_ADMIN_PASSWORD` to a strong unique password. Set `SECRET_KEY` to a long random secret (or use Render's generated value). Keep debug off. Confirm the persistent disk is available on your selected plan before relying on persistence; hosting plan features and prices can change.

After deployment:
1. Open `/health` and confirm it returns `{"status":"ok"}`.
2. Register a normal user and sign in.
3. Upload a harmless test document.
4. Test an unauthorised account cannot download it by changing the URL's document ID.
5. Verify audit records and CSV export as admin.
6. Test in a private/incognito browser window.
7. Check logs for errors and ensure no secrets are displayed.

A deployment cannot be created automatically from this ZIP alone; you must connect your own GitHub and hosting accounts and configure their secrets.

## GitHub workflow
Do not commit `.env`, database files, uploads, passwords, or real confidential documents.

```powershell
git init
git add .
git commit -m "Create Flask app and project documentation"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
git push -u origin main
```

Make small, genuine commits as you implement and test each part. Follow the challenge's conflicting repository-visibility instructions: it says the repo must be public but also says not to make it public before the deadline. Ask your placement cell which instruction takes precedence.

## Project structure
```text
SecureDocs/
├── app.py
├── requirements.txt
├── Procfile
├── render.yaml
├── tests/
│   ├── conftest.py
│   └── test_security.py
├── templates/
├── static/css/style.css
├── THREATS.md
├── PROMPTS.md
└── README.md
```

## Known limitations to disclose
- This is a challenge/demo implementation, not a certified production document vault.
- SQLite is suitable for a small demo; a multi-instance production service should use a managed database and object storage.
- Audit logs are application-level records, not tamper-proof against a database administrator.
- The application does not scan uploads for malware or inspect file contents.
- Rate limiting, email verification, password reset, MFA, and advanced session management are not implemented.
- Test the exact deployed environment before submission.
