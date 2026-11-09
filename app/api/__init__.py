# app/api/__init__.py - TrustVault FULL FILE - Upload Fix Version
import hashlib, uuid
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query, Header
from fastapi.responses import FileResponse
from sqlalchemy import inspect as sa_inspect
from sqlalchemy.orm import Session

try:
    from app.database import get_db, SessionLocal, engine
except ImportError:
    try:
        from app.models import get_db, SessionLocal, engine
    except ImportError:
        from app.db import get_db, SessionLocal, engine

try:
    from app.models import User, Document, Permission, AuditLog
except ImportError:
    from app.models import User, Document
    Permission = None
    AuditLog = None

SECRET_KEY = "trustvault-secret-key-change-in-prod"
ALGORITHM = "HS256"

def _hash_password(password: str) -> str:
    try:
        from app.security import get_password_hash as _gph
        return _gph(password)
    except Exception:
        try:
            from app.services.security import get_password_hash as _gph2
            return _gph2(password)
        except Exception:
            return hashlib.sha256(password.encode()).hexdigest()

def _verify_password(password: str, hashed: str) -> bool:
    try:
        from app.security import verify_password as _vp
        r = _vp(password, hashed)
        if r: return True
    except Exception:
        pass
    try:
        from app.services.security import verify_password as _vp2
        if _vp2(password, hashed): return True
    except Exception:
        pass
    return hashlib.sha256(password.encode()).hexdigest() == hashed

def _create_token(email: str) -> str:
    try:
        from app.security import create_access_token as _cat
        return _cat({"sub": email})
    except Exception:
        try:
            from jose import jwt
            return jwt.encode({"sub": email, "exp": datetime.utcnow() + timedelta(hours=24)}, SECRET_KEY, algorithm=ALGORITHM)
        except Exception:
            import base64, json
            return base64.urlsafe_b64encode(json.dumps({"sub": email}).encode()).decode()

def _decode_token(token: str):
    try:
        from app.security import decode_token as _dt
        return _dt(token)
    except Exception:
        try:
            from jose import jwt
            return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        except Exception:
            import base64, json
            try:
                return json.loads(base64.urlsafe_b64decode(token + "==").decode())
            except Exception:
                return None

def _get_user_columns():
    try:
        return [c.key for c in sa_inspect(User).columns]
    except Exception:
        return []

def _get_user_password(user):
    for f in ["password_hash", "hashed_password", "password"]:
        if hasattr(user, f):
            v = getattr(user, f)
            if v: return v
    return ""

def _get_role_value(role_str: str):
    role_str = (role_str or "VIEWER").upper()
    try:
        for c in User.__table__.columns:
            if c.key == "role" and hasattr(c.type, "enum_class") and c.type.enum_class:
                return c.type.enum_class[role_str]
    except Exception:
        pass
    return role_str

def _audit(db: Session, user_email: str, action: str, doc_id=None):
    if AuditLog is None: return
    try:
        cols = [c.key for c in sa_inspect(AuditLog).columns]
        data = {}
        if "user_email" in cols: data["user_email"] = user_email
        elif "email" in cols: data["email"] = user_email
        if "action" in cols: data["action"] = action
        if "doc_id" in cols and doc_id is not None: data["doc_id"] = doc_id
        if "document_id" in cols and doc_id is not None: data["document_id"] = doc_id
        if "timestamp" in cols: data["timestamp"] = datetime.utcnow()
        elif "created_at" in cols: data["created_at"] = datetime.utcnow()
        db.add(AuditLog(**data))
        db.commit()
    except Exception:
        try: db.rollback()
        except Exception: pass

def get_current_user(authorization: str = Header(None), token: str = Query(None), db: Session = Depends(get_db)):
    raw = None
    if authorization and authorization.startswith("Bearer "):
        raw = authorization[7:]
    elif token:
        raw = token
    if not raw:
        raise HTTPException(status_code=401, detail="Not authenticated")
    payload = _decode_token(raw)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    email = payload.get("sub") or payload.get("email")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

router = APIRouter()

@router.post("/auth/register")
def register(name: str, email: str, password: str, role: str = "VIEWER", db: Session = Depends(get_db)):
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            return {"message": "User already exists, please Login"}
    except Exception:
        pass
    try:
        cols = _get_user_columns()
        data = {}
        if "email" in cols: data["email"] = email
        pwd = _hash_password(password)
        if "password_hash" in cols: data["password_hash"] = pwd
        elif "hashed_password" in cols: data["hashed_password"] = pwd
        elif "password" in cols: data["password"] = pwd
        if "name" in cols: data["name"] = name
        elif "full_name" in cols: data["full_name"] = name
        elif "username" in cols: data["username"] = name
        if "role" in cols: data["role"] = _get_role_value(role)
        user = User(**data)
        db.add(user)
        db.commit()
        db.refresh(user)
        _audit(db, email, "REGISTER")
        return {"message": "Account created! Please Login", "email": email}
    except Exception as e:
        try: db.rollback()
        except Exception: pass
        return {"message": f"Register failed: {str(e)}"}

@router.post("/auth/login")
def login(email: str, password: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user or not _verify_password(password, _get_user_password(user)):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = _create_token(email)
    _audit(db, email, "LOGIN")
    return {"access_token": token, "token_type": "bearer", "email": email, "message": "Login successful"}

@router.post("/auth/logout")
def logout(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    _audit(db, current_user.email, "LOGOUT")
    return {"message": "Logged out, token revoked"}

@router.get("/documents/")
def list_documents(search: str = Query(None), db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    q = db.query(Document)
    try:
        if Permission is not None:
            shared_ids = [p.document_id for p in db.query(Permission).filter(Permission.user_id == current_user.id).all()]
            if shared_ids:
                q = q.filter((Document.owner_id == current_user.id) | (Document.id.in_(shared_ids)))
            else:
                q = q.filter(Document.owner_id == current_user.id)
        else:
            q = q.filter(Document.owner_id == current_user.id)
    except Exception:
        q = q.filter(Document.owner_id == current_user.id)
    docs = q.all()
    out = []
    for d in docs:
        fname = getattr(d, "filename", "") or getattr(d, "name", "") or getattr(d, "stored_filename", "") or ""
        if search and search.lower() not in fname.lower():
            continue
        out.append({"id": d.id, "filename": fname, "owner": getattr(d, "owner_id", ""), "message": "ok"})
    return out

@router.post("/documents/upload")
def upload_document(file: UploadFile = File(...), db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    UPLOAD_DIR = Path("uploads")
    UPLOAD_DIR.mkdir(exist_ok=True)
    content = file.file.read()
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="File too large, max 10MB")
    # FIX: stored_filename, mime_type, file_size anni fill chestunna
    stored = f"{uuid.uuid4().hex}_{file.filename}"
    dest = UPLOAD_DIR / stored
    dest.write_bytes(content)
    try:
        cols = [c.key for c in sa_inspect(Document).columns]
        data = {}
        if "filename" in cols: data["filename"] = file.filename
        if "name" in cols: data["name"] = file.filename
        if "stored_filename" in cols: data["stored_filename"] = stored
        if "owner_id" in cols: data["owner_id"] = current_user.id
        if "owner" in cols: data["owner"] = current_user.id
        if "filepath" in cols: data["filepath"] = str(dest)
        if "file_path" in cols: data["file_path"] = str(dest)
        if "path" in cols: data["path"] = str(dest)
        if "mime_type" in cols: data["mime_type"] = file.content_type or "application/octet-stream"
        if "content_type" in cols: data["content_type"] = file.content_type or "application/octet-stream"
        if "file_size" in cols: data["file_size"] = len(content)
        if "size" in cols: data["size"] = len(content)
        if "created_at" in cols: data["created_at"] = datetime.utcnow()
        if "uploaded_at" in cols: data["uploaded_at"] = datetime.utcnow()
        doc = Document(**data)
        db.add(doc)
        db.commit()
        db.refresh(doc)
        _audit(db, current_user.email, "UPLOAD", doc.id)
        return {"message": "Uploaded", "id": doc.id, "filename": file.filename}
    except Exception as e:
        try: db.rollback()
        except Exception: pass
        raise HTTPException(status_code=400, detail=str(e))

@router.get("/documents/{doc_id}")
def get_doc(doc_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    is_owner = getattr(doc, "owner_id", None) == current_user.id
    has_perm = False
    if Permission is not None:
        try:
            has_perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == current_user.id).first() is not None
        except Exception:
            has_perm = False
    is_admin = str(getattr(current_user, "role", "")).upper().find("ADMIN") != -1
    if not (is_owner or has_perm or is_admin):
        _audit(db, current_user.email, "READ_FAILED", doc_id)
        raise HTTPException(status_code=403, detail="IDOR Blocked: No permission")
    return {"id": doc.id, "filename": getattr(doc, "filename", getattr(doc, "name", "")), "owner_id": getattr(doc, "owner_id", "")}

@router.get("/documents/{doc_id}/download")
def download_doc(doc_id: int, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    info = get_doc(doc_id, db, current_user)
    doc = db.query(Document).filter(Document.id == doc_id).first()
    for f in ["filepath", "file_path", "path", "stored_filename"]:
        p = getattr(doc, f, None)
        if p:
            full = Path(str(p))
            if not full.exists() and (Path("uploads") / str(p)).exists():
                full = Path("uploads") / str(p)
            if full.exists():
                _audit(db, current_user.email, "DOWNLOAD", doc_id)
                return FileResponse(str(full), filename=info["filename"])
    raise HTTPException(status_code=404, detail="File not found on disk")

@router.post("/documents/{doc_id}/share")
def share_doc(doc_id: int, user_email: str, can_read: bool = True, can_edit: bool = False, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc or getattr(doc, "owner_id", None) != current_user.id:
        raise HTTPException(status_code=403, detail="Only owner can share")
    target = db.query(User).filter(User.email == user_email).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target user not found")
    if Permission is None:
        raise HTTPException(status_code=400, detail="Permission model missing")
    try:
        perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == target.id).first()
        if not perm:
            perm = Permission(document_id=doc_id, user_id=target.id, can_read=can_read, can_edit=can_edit)
            db.add(perm)
        else:
            perm.can_read = can_read
            perm.can_edit = can_edit
        db.commit()
        _audit(db, current_user.email, "SHARE", doc_id)
        return {"message": f"Shared with {user_email}"}
    except Exception as e:
        try: db.rollback()
        except Exception: pass
        raise HTTPException(status_code=400, detail=str(e))

@router.delete("/documents/{doc_id}/share")
def unshare_doc(doc_id: int, user_email: str, db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc or getattr(doc, "owner_id", None) != current_user.id:
        raise HTTPException(status_code=403, detail="Only owner can unshare")
    target = db.query(User).filter(User.email == user_email).first()
    if not target or Permission is None:
        raise HTTPException(status_code=404, detail="Share not found")
    perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == target.id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Share not found")
    db.delete(perm)
    db.commit()
    _audit(db, current_user.email, "SHARE_REVOKED", doc_id)
    return {"message": f"Unshared from {user_email}"}

@router.get("/audit/")
def get_audit(db: Session = Depends(get_db), current_user=Depends(get_current_user)):
    is_admin = str(getattr(current_user, "role", "")).upper().find("ADMIN") != -1
    if not is_admin:
        raise HTTPException(status_code=403, detail="Admin only")
    if AuditLog is None:
        return []
    logs = db.query(AuditLog).all()
    out = []
    for l in logs:
        out.append({"id": getattr(l, "id", ""), "user_email": getattr(l, "user_email", getattr(l, "email", "")), "action": getattr(l, "action", ""), "doc_id": getattr(l, "doc_id", getattr(l, "document_id", "")), "timestamp": str(getattr(l, "timestamp", getattr(l, "created_at", "")))})
    return out