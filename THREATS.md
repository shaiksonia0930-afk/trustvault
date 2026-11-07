# THREATS.md - TrustVault

| Threat | Attack | Mitigation | Test |
| IDOR | GET /documents/2 with other user token | check_read() checks owner OR Permission table. List filtered. | test_idor.py - Viewer gets 403 |
| JWT Replay | Use old token after logout | Redis blacklist jti, check on every request | Logout -> /auth/me = 401 |
| Malicious Upload | Upload .exe renamed as .pdf | python-magic magic bytes, not extension. 10MB limit | Upload .exe = 400 |
| Privilege Escalation | VIEWER tries DELETE | check_delete() only OWNER or ADMIN | Viewer DELETE = 403 |
| Audit Tampering | Attacker deletes logs | No PUT/DELETE API for audit_logs. Only ADMIN GET | Viewer GET /audit = 403 |
| Search Leak | List all docs | list_docs filters owned + permitted only | Viewer sees only own + shared |