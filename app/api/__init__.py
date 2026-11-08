# app/api/__init__.py - COMPLETE FILE - TrustVault - SEARCH + UNSHARE included
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Request
from sqlalchemy.orm import Session
from typing import List

from app.database import get_db
from app.models import User, Document, Permission
from app.schemas import DocumentOut, AuditOut
from app.core.security import get_current_active_user, get_password_hash, verify_password, create_access_token
from app.core.permissions import check_delete
from app.core.file_validator import validate_file
from app.services.audit import audit_log

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
    import os
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
    perm = db.query(Permission).filter(Permission.document_id == doc_id, Permission.user_id == current_user.id, Permission