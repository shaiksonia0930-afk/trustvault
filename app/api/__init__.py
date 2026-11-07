from fastapi.security import OAuth2PasswordRequestForm
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import List
from jose import jwt
import os
from datetime import datetime, timezone

from app.models import get_db, User, Document, Permission, AuditLog
from app.schemas import UserCreate, UserLogin, Token, UserOut, DocumentOut, PermissionCreate, AuditOut
from app.core.security import get_password_hash, verify_password, create_access_token, blacklist_token, get_current_active_user, oauth2_scheme, SECRET_KEY, ALGORITHM
from app.core.permissions import check_read, check_edit, check_delete, audit_log
from app.core.file_validator import validate_file
from app.services import save_file_service, get_file_path_service, delete_file_service

# --- AUTH ROUTER ---
auth_router = APIRouter(prefix="/auth", tags=["Auth"])

@auth_router.post("/register", response_model=UserOut)
def register(user_in: UserCreate, db: Session = Depends(get_db), request: Request = None):
    if db.query(User).filter(User.email == user_in.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    role = user_in.role if user_in.role in ["ADMIN", "OWNER", "VIEWER"] else "OWNER"
    user = User(email=user_in.email, hashed_password=get_password_hash(user_in.password), full_name=user_in.full_name, role=role)
    db.add(user)
    db.commit()
    db.refresh(user)
    audit_log(db, user.id, None, "REGISTER", request.client.host if request else "unknown")
    return user

@auth_router.post("/login", response_model=Token)
@auth_router.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db), request: Request = None):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token, jti, expire = create_access_token({"sub": user.email})
    audit_log(db, user.id, None, "LOGIN", request.client.host if request else "unknown")
    return {"access_token": token, "token_type": "bearer", "user": user}

@auth_router.post("/logout")
def logout(request: Request, token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        jti = payload.get("jti")
        exp = payload.get("exp")
        email = payload.get("sub")
        if jti and exp:
            expire_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
            blacklist_token(jti, expire_dt)
            user = db.query(User).filter(User.email == email).first()
            if user:
                audit_log(db, user.id, None, "LOGOUT", request.client.host)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {"detail": "Logged out, token revoked"}

@auth_router.get("/me", response_model=UserOut)
def me(current_user: User = Depends(get_current_active_user)):
    return current_user

# --- DOCUMENTS ROUTER ---
document_router = APIRouter(prefix="/documents", tags=["Documents"])

@document_router.post("/upload", response_model=DocumentOut)
async def upload_doc(request: Request, file: UploadFile = File(...), db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    file_bytes = await file.read()
    mime = validate_file(file_bytes, file.filename)
    stored_name, file_path = save_file_service(file_bytes, mime)
    doc = Document(owner_id=current_user.id, filename=file.filename, stored_filename=stored_name, file_path=file_path, mime_type=mime, file_size=len(file_bytes))
    db.add(doc)
    db.commit()
    db.refresh(doc)
    audit_log(db, current_user.id, doc.id, "UPLOAD", request.client.host, f"Uploaded {file.filename}")
    return doc

@document_router.get("/", response_model=List[DocumentOut])
def list_docs(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role == "ADMIN":
        return db.query(Document).all()
    owned = db.query(Document).filter(Document.owner_id == current_user.id).all()
    permitted_ids = [p[0] for p in db.query(Permission.document_id).filter(Permission.user_id == current_user.id, Permission.can_read == True).all()]
    shared = db.query(Document).filter(Document.id.in_(permitted_ids)).all() if permitted_ids else []
    return owned + shared

@document_router.get("/{doc_id}", response_model=DocumentOut)
def get_doc(doc_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    check_read(current_user, doc, db, request.client.host)
    return doc

@document_router.get("/{doc_id}/download")
def download_doc(doc_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    check_read(current_user, doc, db, request.client.host)
    path = get_file_path_service(doc.stored_filename)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail="File missing")
    audit_log(db, current_user.id, doc.id, "DOWNLOAD", request.client.host)
    return FileResponse(path, filename=doc.filename, media_type=doc.mime_type)

@document_router.post("/{doc_id}/share")
def share_doc(doc_id: int, perm_in: PermissionCreate, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    check_edit(current_user, doc, db, request.client.host)
    target = db.query(User).filter(User.email == perm_in.user_email).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")
    existing = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == target.id).first()
    if existing:
        existing.can_read = perm_in.can_read
        existing.can_edit = perm_in.can_edit
    else:
        db.add(Permission(document_id=doc_id, user_id=target.id, can_read=perm_in.can_read, can_edit=perm_in.can_edit, granted_by=current_user.id))
    db.commit()
    audit_log(db, current_user.id, doc_id, "PERMISSION_GRANT", request.client.host, f"Grant to {target.email}")
    return {"detail": f"Shared with {target.email}"}

@document_router.delete("/{doc_id}")
def delete_doc(doc_id: int, request: Request, db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Not found")
    check_delete(current_user, doc)
    delete_file_service(doc.stored_filename)
    db.query(Permission).filter(Permission.document_id == doc_id).delete()
    audit_log(db, current_user.id, doc_id, "DELETE", request.client.host, f"Deleted {doc.filename}")
    db.delete(doc)
    db.commit()
    return {"detail": "Deleted"}

# --- AUDIT ROUTER ---
audit_router = APIRouter(prefix="/audit", tags=["Audit"])

@audit_router.get("/", response_model=List[AuditOut])
def get_logs(db: Session = Depends(get_db), current_user: User = Depends(get_current_active_user)):
    if current_user.role != "ADMIN":
        raise HTTPException(status_code=403, detail="Only ADMIN can view audit logs")
    return db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()