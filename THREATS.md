# Threat model — SecureDocs

## Assets
- Private document contents and filenames
- User accounts and password hashes
- Role assignments and document grants
- Audit history
- Application secret and database

## Trust boundaries
- Browser to Flask server
- Authenticated user to admin-only routes
- User-controlled document IDs and upload metadata to database/storage
- Deployment environment variables and persistent disk

## Threats and mitigations

| Threat | Example | Mitigation | Test |
|---|---|---|---|
| Broken access control / IDOR | User A changes `/documents/1/download` to `/documents/2/download` | `allowed_document` checks owner, admin, or explicit grant on the server | `test_user_cannot_download_other_users_document` |
| Privilege escalation | Register with `role=admin` | Registration ignores role input and sets `user` server-side | `test_registration_cannot_choose_admin_role` |
| Unauthenticated access | Open dashboard without login | `login_required` | `test_dashboard_requires_login` |
| Admin-route access | Regular user opens `/admin/users` | `admin_required` | `test_non_admin_cannot_open_admin_pages` |
| Malicious filename/path | Upload `../../app.py` | `secure_filename`, random stored name, private directory | `test_upload_rejects_disallowed_extension` |
| Oversized upload | Upload a file larger than limit | Flask `MAX_CONTENT_LENGTH` and bounded read | Add/extend oversized-upload test |
| CSRF | Cross-site form submits delete action | Session CSRF token on authenticated state-changing routes | `test_post_without_csrf_is_rejected` |
| Password exposure | Database leak | Werkzeug password hash | `test_password_is_not_stored_plaintext` |
| Audit gaps | Denied download is not recorded | Denials logged before 404 | `test_denied_download_is_audited` |
| Secret leakage | Commit `.env` or production secret | `.gitignore`, environment variables | Manual repository scan before push |
| Session theft | Cookie intercepted | HTTPS in production; HttpOnly and SameSite cookies; Secure flag configurable | Verify HTTPS deployment and cookie flags |
| Malicious file contents | Executable disguised as document | Extension allowlist only; no malware scanning or content inspection | Known limitation; do not upload untrusted files |

## Residual risks
- Application-level audit logs can be changed by someone with database/file-system access.
- File extensions do not prove file contents are safe.
- No rate limiting, MFA, email verification, antivirus, or security monitoring.
- SQLite and local file storage need a persistent disk on hosting; ephemeral filesystems lose data on restart.
- The bootstrap admin password must be strong and unique in deployment.

## Test plan
Run `python -m pytest -q`. Also test manually with two normal users and one admin:
1. User A uploads a document.
2. User B cannot see or download it by guessing its numeric ID.
3. User A grants read access to B; B can download it.
4. User A revokes access; B is denied again.
5. A normal user cannot open admin pages or export audit CSV.
6. Admin can view and export audit logs.
7. Check the audit trail for successful and denied attempts.
