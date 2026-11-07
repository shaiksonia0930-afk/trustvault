# PROMPTS.md - TrustVault - How I Used AI

## 1. Date: 07 Nov 2026 - JWT + Redis Blacklist
- Asked: "Create secure FastAPI with JWT Redis blacklist"
- AI Gave: security.py with redis.from_url, no fallback
- Wrong: AI code assumed Redis always available. In VS Code Redis ledu, app crash ayyindi.
- I Did Instead: Added memory fallback if Redis fails.

## 2. Date: 07 Nov 2026 - IDOR Prevention
- Asked: "Write per-person permission logic to prevent IDOR"
- AI Gave: check_read() with owner check only
- Wrong: AI missed Permission table check, list API lo kuda filter cheyaledu.
- I Did Instead: Added Permission table check + list_docs filter owned + permitted_ids.
- Topic: Access Control

## 3. Date: 07 Nov 2026 - File Validation
- Asked: "Add file validation with python-magic"
- AI Gave: validate_file with python-magic
- Wrong: AI used python-magic which is for Linux, Windows lo work avvaledu. Also used pydantic 2.6.1 which fails on Python 3.13.
- I Did Instead: Changed to python-magic-bin for Windows, removed version pins.

## 4. Date: 07 Nov 2026 - Audit Logs
- Asked: "Add immutable audit logs"
- AI Gave: AuditLog table with GET API
- Wrong: AI also suggested PUT/DELETE for audit, which allows tampering.
- I Did Instead: Removed PUT/DELETE, only ADMIN can GET. Added READ_FAILED log on IDOR attempt.
- Topic: Audit Trail

## 5. Date: 07 Nov 2026 - Deployment Fix
- Asked: "Deploy on Render"
- AI Gave: requirements with python-magic-bin
- Wrong: Render is Linux, python-magic-bin is Windows only. Deploy failed.
- I Did Instead: Changed to python-magic for Render.

## 6. Date: 07 Nov 2026 - Password Hashing
- Asked: "Fix register 500 error"
- AI Gave: bcrypt
- Wrong: bcrypt fails on Python 3.13 - Register 500 error vachindi.
- I Did Instead: Changed to pbkdf2_sha256 in security.py.
- Topic: Authorisation