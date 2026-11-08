from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
import os

# DB create - models nundi
from app.models import Base, engine

# Routers - api nundi
from app.api import auth_router, document_router, audit_router

# Create tables + storage folder
Base.metadata.create_all(bind=engine)
os.makedirs(os.getenv("STORAGE_PATH", "./storage"), exist_ok=True)

app = FastAPI(
    title="TrustVault - Secure Document Vault",
    description="Security Project - IDOR, JWT Revoke, Per-Person Permission, Immutable Audit",
    version="1.0.0"
)
@app.get("/", include_in_schema=False)
def home():
    return FileResponse("index.html")
@app.get("/features", include_in_schema=False)
def features_page():
    return FileResponse("features.html")

@app.get("/vault", include_in_schema=False)
def vault_page():
    return FileResponse("vault.html")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(document_router)
app.include_router(audit_router)

@app.get("/")
def root():
    return {"message": "TrustVault Running", "docs": "/docs", "check": "Secure"}

@app.get("/health")
def health():
    return {"status": "ok"}