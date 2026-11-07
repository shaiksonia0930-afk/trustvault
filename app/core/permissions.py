from fastapi import HTTPException
from sqlalchemy.orm import Session

def audit_log(db: Session, user_id: int, doc_id: int, action: str, ip: str = "127.0.0.1", details: str = ""):
    from app.models import AuditLog
    log = AuditLog(user_id=user_id, document_id=doc_id, action=action, ip_address=ip, details=details)
    db.add(log)
    db.commit()

def check_read(user, doc, db: Session, ip: str = "127.0.0.1"):
    # ADMIN can read all
    if user.role == "ADMIN":
        return True
    # Owner can read
    if doc.owner_id == user.id:
        return True
    # Per-person permission check - IDOR prevention
    from app.models import Permission
    perm = db.query(Permission).filter(
        Permission.document_id == doc.id,
        Permission.user_id == user.id,
        Permission.can_read == True
    ).first()
    if not perm:
        audit_log(db, user.id, doc.id, "READ_FAILED", ip, f"Failed read by {user.email}")
        raise HTTPException(status_code=403, detail="Access Denied: No read permission (IDOR Blocked)")
    return True

def check_edit(user, doc, db: Session, ip: str = "127.0.0.1"):
    if user.role == "ADMIN":
        return True
    if doc.owner_id == user.id:
        return True
    from app.models import Permission
    perm = db.query(Permission).filter(
        Permission.document_id == doc.id,
        Permission.user_id == user.id,
        Permission.can_edit == True
    ).first()
    if not perm:
        audit_log(db, user.id, doc.id, "EDIT_FAILED", ip, f"Failed edit by {user.email}")
        raise HTTPException(status_code=403, detail="Access Denied: No edit permission")
    return True

def check_delete(user, doc):
    if user.role == "ADMIN":
        return True
    if doc.owner_id == user.id:
        return True
    raise HTTPException(status_code=403, detail="Only Owner or Admin can delete")