# AI usage log — SecureDocs

The challenge asks for at least five dated entries written while working, including at least two about authorisation/access control/audit logging. Keep this file truthful. Do not invent bugs, fixes, or commit links. Replace bracketed fields only after you have actually performed the work and committed the change.

## 2026-10-24 — Project skeleton and setup
- **Prompt/request:** Help me structure a beginner-friendly Flask document access control application with tests and deployment documentation.
- **Tool output:** A Flask starter with authentication, document routes, templates, test setup, and documentation.
- **Review performed:** Generated project files for local review; dependency installation and full runtime testing still need to be run in my environment.
- **Issue found:** [Record a real issue after running the project; do not invent one.]
- **My fix:** [Describe the change you actually made.]
- **Commit:** [Add the real commit URL after committing.]

## 2026-10-24 — Authorisation / IDOR review
- **Prompt/request:** Review document download and delete routes for insecure direct object reference (IDOR) and enforce server-side ownership/grant checks.
- **Tool output:** A shared `allowed_document` authorisation helper and protected document routes.
- **Review performed:** [Test with two separate accounts and record the exact result.]
- **Issue found:** [Record the actual failing behaviour, if any.]
- **My fix:** [Describe your actual change and test.]
- **Commit:** [Real commit URL.]

## 2026-10-24 — Role escalation review
- **Prompt/request:** Check whether a new user can submit `role=admin` during registration or access administrator routes.
- **Tool output:** Registration assigns `role='user'` server-side and admin routes check the current user's role.
- **Review performed:** [Run the relevant test and record the result.]
- **Issue found:** [Actual observation.]
- **My fix:** [Actual code change, or say no code change was needed and why.]
- **Commit:** [Real commit URL.]

## 2026-10-24 — Audit trail review
- **Prompt/request:** Check that successful and denied document actions are recorded without logging passwords or file contents.
- **Tool output:** Application-level audit logging for login, upload, download, deletion, permission changes, and denied access.
- **Review performed:** [Inspect the audit page/CSV after a real test.]
- **Issue found:** [Actual observation.]
- **My fix:** [Actual change.]
- **Commit:** [Real commit URL.]

## 2026-10-24 — Automated tests and deployment review
- **Prompt/request:** Create tests for authentication, authorisation, upload restrictions, CSRF, and audit logging; review deployment steps.
- **Tool output:** Pytest suite and README/Render configuration.
- **Review performed:** [Paste the actual test summary and deployment smoke-test result.]
- **Issue found:** [Actual test/deployment issue.]
- **My fix:** [Actual change.]
- **Commit:** [Real commit URL.]

## How to keep this log honest
- Add entries as work happens; do not backdate commits.
- Include a link to the real commit that contains the fix.
- A prompt alone is not evidence of a bug. Record the test, result, and correction you actually made.
