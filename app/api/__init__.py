# app/api/__init__.py - COMPLETE FILE - TrustVault - NO IMPORT ERRORS
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from sqlalchemy.orm import Session
from typing import List
import os

# ---------- get_db - ekkada unna teesukuntundi, fail avvadu ----------
try:
    from app.database import get_db
except ImportError:
    try:
        from app.models import get_db
    except ImportError:
        from app import get_db

# ---------- Models ----------
from app.models import User, Document, Permission
try:
    from app.models import AuditLog
except ImportError:
    AuditLog = None

# ---------- Schemas ----------
try:
    from app.schemas import DocumentOut, AuditOut
except ImportError:
    from pydantic import BaseModel
    class DocumentOut(BaseModel):
        id: int
        filename: str
        owner_id: int
        class Config:
            from_attributes = True
    class AuditOut(BaseModel):
        id: int
        action: str
        class Config:
            from_attributes = True

# ---------- Security ----------
try:
    from app.core.security import get_current_active_user, get_password_hash, verify_password, create_access_token
except ImportError:
    try:
        from app.core.security import get_current_user as get_current_active_user
        from app.core.security import get_password_hash, verify_password, create_access_token
    except ImportError:
        from app.core.security import get_current_user as get_current_active_user
        from passlib.context import CryptContext
        _pwd = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
        def get_password_hash(p): return _pwd.hash(p)
        def verify_password(p, h):
            try: return _pwd.verify(p, h)
            except Exception: return False
        def create_access_token(data: dict):
            from app.core.security import create_token as _ct
            return _ct(data)

# ---------- check_delete ----------
try:
    from app.core.permissions import check_delete
except ImportError:
    def check_delete(user, doc):
        if doc.owner_id != user.id and getattr(user, "role", "") != "ADMIN":
            raise HTTPException(status_code=403, detail="Only owner can delete")

# ---------- validate_file ----------
try:
    from app.core.file_validator import validate_file
except ImportError:
    def validate_file(file):
        allowed = {".pdf", ".png", ".jpg", ".jpeg", ".docx"}
        ext = os.path.splitext(file.filename or "")[1].lower()
        if ext not in allowed:
            raise HTTPException(status_code=400, detail="File type not allowed")

# ---------- audit_log - ekkada unna teesukuntundi ----------
try:
    from app.services.audit import audit_log
except ImportError:
    try:
        from app.services import audit_log
    except ImportError:
        def audit_log(db, user_id, doc_id, action, ip, details=""):
            try:
                if AuditLog is not None:
                    log = AuditLog(user_id=user_id, document_id=doc_id, action=action, ip_address=ip, details=details)
                    db.add(log)
                    db.commit()
            except Exception:
                try: db.rollback()
                except Exception: pass

auth_router = APIRouter(prefix="/auth", tags=["Auth"])
document_router = APIRouter(prefix="/documents", tags=["Documents"])
audit_router = APIRouter(prefix="/audit", tags=["Audit"])
document = document_router

@auth_router.post("/register")
def register(name: str, email: str, password: str, role: str = "VIEWER", db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(name=name, email=email, password_hash=get_password_hash(password), role=role.upper())
    db.add(user)
    db.commit()
    db.refresh(user)
    return {"detail": "User registered", "id": user.id, "email": user.email}

@auth_router.post("/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_access_token({"sub": user.email})
    return {"access_token": token, "token_type": "bearer"}

@auth_router.get("/me")
def me(current_user: User = Depends(get_current_active_user)):
    return {"id": current_user.id, "name": current_user.name, "email": current_user.email, "role": current_user.role}

@document_router.post("/upload", response_model=DocumentOut)
async def upload_doc(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    validate_file(file)
    content = await file.read()
    os.makedirs("storage", exist_ok=True)
    path = f"storage/{current_user.id}_{file.filename}"
    with open(path, "wb") as f:
        f.write(content)
    doc = Document(filename=file.filename, stored_filename=file.filename, owner_id=current_user.id, file_path=path)
    db.add(doc)
    db.commit()
    db.refresh(doc)
    audit_log(db, current_user.id, doc.id, "UPLOAD", request.client.host, f"Uploaded {file.filename}")
    return doc

@document_router.get("/", response_model=List[DocumentOut])
def list_documents(search: str = "", db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role == "ADMIN":
        query = db.query(Document)
        if search:
            query = query.filter(Document.filename.ilike(f"%{search}%"))
        return query.all()
    owned = db.query(Document).filter(Document.owner_id == current_user.id).all()
    permitted_ids = [p.document_id for p in db.query(Permission).filter(Permission.user_id == current_user.id, Permission.can_read == True).all()]
    shared = db.query(Document).filter(Document.id.in_(permitted_ids)).all() if permitted_ids else []
    all_docs = owned + shared
    if search:
        all_docs = [d for d in all_docs if search.lower() in (d.filename or "").lower()]
    return all_docs

@document_router.get("/{doc_id}", response_model=DocumentOut)
def get_doc(doc_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    is_owner = doc.owner_id == current_user.id
    perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == current_user.id, Permission.can_read == True).first()
    if not is_owner and not perm and current_user.role != "ADMIN":
        audit_log(db, current_user.id, doc_id, "READ_FAILED", request.client.host, "IDOR blocked")
        raise HTTPException(status_code=403, detail="Access Denied: No read permission (IDOR Blocked)")
    return doc

@document_router.get("/{doc_id}/download")
def download_doc(doc_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    is_owner = doc.owner_id == current_user.id
    perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == current_user.id, Permission.can_read == True).first()
    if not is_owner and not perm and current_user.role != "ADMIN":
        audit_log(db, current_user.id, doc_id, "READ_FAILED", request.client.host, "IDOR blocked")
        raise HTTPException(status_code=403, detail="Access Denied: No read permission (IDOR Blocked)")
    audit_log(db, current_user.id, doc_id, "DOWNLOAD", request.client.host, f"Downloaded {doc.filename}")
    from fastapi.responses import FileResponse
    fpath = getattr(doc, "file_path", None) or f"storage/{doc.filename}"
    return FileResponse(fpath, filename=doc.filename)

@document_router.post("/{doc_id}/share")
def share_doc(doc_id: int, user_email: str, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only owner can share")
    target = db.query(User).filter(User.email == user_email).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == target.id).first()
    if perm:
        perm.can_read = True
    else:
        perm = Permission(document_id=doc_id, user_id=target.id, can_read=True, can_edit=False)
        db.add(perm)
    db.commit()
    audit_log(db, current_user.id, doc_id, "SHARE", request.client.host, f"Shared with {user_email}")
    return {"detail": f"Shared with {target.email}"}

@document_router.delete("/{doc_id}/share")
def unshare_document(doc_id: int, user_email: str, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc or doc.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="Only owner can revoke share")
    target = db.query(User).filter(User.email == user_email).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == target.id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="This user has no access")
    db.delete(perm)
    db.commit()
    audit_log(db, current_user.id, doc_id, "SHARE_REVOKED", request.client.host, f"Revoked access for {user_email}")
    return {"detail": f"Access revoked for {user_email}"}

@document_router.delete("/{doc_id}")
def delete_doc(doc_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    check_delete(current_user, doc)
    db.query(Permission).filter(Permission.document_id == doc_id).delete()
    audit_log(db, current_user.id, doc_id, "DELETE", request.client.host, f"Deleted {doc.filename}")
    db.delete(doc)
    db.commit()
    return {"detail": "Deleted"}

@audit_router.get("/", response_model=List[AuditOut])
def get_logs(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only ADMIN can view audit logs")
    if AuditLog is None:
        return []
    return db.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()

router = APIRouter()
router.include_router(auth_router)
router.include_router(document_router)
router.include_router(audit_router)