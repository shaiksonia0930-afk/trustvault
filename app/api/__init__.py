# app/api/__init__.py - COMPLETE FILE - TrustVault
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from sqlalchemy import or_
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import os, shutil, magic

from app.database import get_db
from app.models import User, Document, Permission, AuditLog

router = APIRouter()

SECRET_KEY = os.getenv("SECRET_KEY", "trustvault-secret-key-change-in-prod")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
UPLOAD_DIR = "storage"
os.makedirs(UPLOAD_DIR, exist_ok=True)

pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

try:
    import redis
    redis_client = redis.Redis(host=os.getenv("REDIS_HOST", "localhost"), port=6379, decode_responses=True)
    redis_client.ping()
    USE_REDIS = True
except Exception:
    redis_client = None
    USE_REDIS = False
    revoked_tokens = set()

ALLOWED_EXT = {".pdf", ".png", ".jpg", ".jpeg", ".docx"}
MAX_SIZE = 10 * 1024 * 1024

def hash_password(p: str):
    return pwd_context.hash(p)

def verify_password(plain: str, hashed: str):
    return pwd_context.verify(plain, hashed)

def create_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def is_revoked(token: str):
    if USE_REDIS:
        return redis_client.exists(f"blacklist:{token}")
    return token in revoked_tokens

def add_audit(db: Session, user_id: int, action: str, doc_id=None, details=""):
    log = AuditLog(user_id=user_id, action=action, document_id=doc_id, details=details)
    db.add(log)
    db.commit()

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    if is_revoked(token):
        raise HTTPException(status_code=401, detail="Token revoked. Please login again.")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def is_admin(user: User):
    return user.role == "ADMIN"

@router.post("/auth/register")
def register(name: str, email: str, password: str, role: str = "VIEWER", db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(name=name, email=email, password_hash=hash_password(password), role=role.upper())
    db.add(user)
    db.commit()
    db.refresh(user)
    add_audit(db, user.id, "REGISTER", details=f"Registered {email}")
    return {"message": "User registered", "id": user.id, "email": user.email}

@router.post("/auth/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token({"sub": user.email, "role": user.role})
    add_audit(db, user.id, "LOGIN", details=f"Login {user.email}")
    return {"access_token": token, "token_type": "bearer", "role": user.role}

@router.post("/auth/logout")
def logout(token: str = Depends(oauth2_scheme), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if USE_REDIS:
        redis_client.setex(f"blacklist:{token}", 3600, "revoked")
    else:
        revoked_tokens.add(token)
    add_audit(db, current_user.id, "LOGOUT", details="Logout - token revoked")
    return {"message": "Logged out. Token revoked."}

@router.get("/auth/me")
def me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "name": current_user.name, "email": current_user.email, "role": current_user.role}

@router.post("/documents/upload")
def upload(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ALLOWED_EXT:
        raise HTTPException(status_code=400, detail="Only PDF, PNG, JPG, DOCX allowed")
    content = file.file.read()
    if len(content) > MAX_SIZE:
        raise HTTPException(status_code=400, detail="File too large. Max 10MB")
    try:
        mime = magic.from_buffer(content, mime=True)
        if "pdf" not in mime and "image" not in mime and "word" not in mime and "officedocument" not in mime and "zip" not in mime:
            raise HTTPException(status_code=400, detail="Invalid file content")
    except HTTPException:
        raise
    except Exception:
        pass
    safe_name = f"{current_user.id}_{int(datetime.utcnow().timestamp())}_{file.filename}"
    path = os.path.join(UPLOAD_DIR, safe_name)
    with open(path, "wb") as f:
        f.write(content)
    doc = Document(filename=file.filename, filepath=path, owner_id=current_user.id)
    db.add(doc)
    db.commit()
    db.refresh(doc)
    add_audit(db, current_user.id, "UPLOAD", doc.id, f"Uploaded {file.filename}")
    return {"message": "Uploaded", "id": doc.id, "filename": doc.filename}

@router.get("/documents/")
def list_documents(search: str = "", current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    shared_ids = db.query(Permission.document_id).filter(Permission.user_id == current_user.id)
    query = db.query(Document).filter(
        or_(Document.owner_id == current_user.id, Document.id.in_(shared_ids))
    )
    if search:
        query = query.filter(Document.filename.ilike(f"%{search}%"))
    docs = query.all()
    return [{"id": d.id, "filename": d.filename, "owner_id": d.owner_id} for d in docs]

@router.get("/documents/{doc_id}/download")
def download(doc_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if not doc:
        raise HTTPException(status_code=404, detail="Document not found")
    is_owner = doc.owner_id == current_user.id
    perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == current_user.id, Permission.can_read == True).first()
    if not is_owner and not perm and not is_admin(current_user):
        add_audit(db, current_user.id, "READ_FAILED", doc_id, f"IDOR blocked for {current_user.email}")
        raise HTTPException(status_code=403, detail="Access Denied: No read permission (IDOR Blocked)")
    add_audit(db, current_user.id, "DOWNLOAD", doc_id, f"Downloaded {doc.filename}")
    from fastapi.responses import FileResponse
    return FileResponse(doc.filepath, filename=doc.filename)

@router.post("/documents/{doc_id}/share")
def share(doc_id: int, user_email: str, can_read: bool = True, can_edit: bool = False, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id, Document.owner_id == current_user.id).first()
    if not doc:
        raise HTTPException(status_code=403, detail="Only owner can share")
    target = db.query(User).filter(User.email == user_email).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == target.id).first()
    if perm:
        perm.can_read = can_read
        perm.can_edit = can_edit
    else:
        perm = Permission(document_id=doc_id, user_id=target.id, can_read=can_read, can_edit=can_edit)
        db.add(perm)
    db.commit()
    add_audit(db, current_user.id, "SHARE", doc_id, f"Shared with {user_email}")
    return {"message": f"Shared with {user_email}"}

@router.delete("/documents/{doc_id}/share")
def unshare_document(doc_id: int, user_email: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.query(Document).filter(Document.id == doc_id, Document.owner_id == current_user.id).first()
    if not doc:
        raise HTTPException(status_code=403, detail="Only owner can revoke share")
    target = db.query(User).filter(User.email == user_email).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == target.id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="This user has no access to this document")
    db.delete(perm)
    db.commit()
    add_audit(db, current_user.id, "SHARE_REVOKED", doc_id, f"Revoked access for {user_email}")
    return {"message": f"Access revoked for {user_email}"}

@router.get("/audit/")
def get_audit(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not is_admin(current_user):
        raise HTTPException(status_code=403, detail="Admin only")
    logs = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(100).all()
    return [{"id": l.id, "user_id": l.user_id, "action": l.action, "document_id": l.document_id, "details": l.details} for l in logs]