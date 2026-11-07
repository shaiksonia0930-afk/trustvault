# THREATS.md
| Threat | Mitigation |
| IDOR | check_read() checks owner or Permission table |
| JWT Replay | Redis blacklist with jti |
| Malicious Upload | python-magic mime check + 10MB limit |
| Privilege Escalation | check_delete() only OWNER or ADMIN |
| Audit Tampering | No DELETE API for audit_logs |