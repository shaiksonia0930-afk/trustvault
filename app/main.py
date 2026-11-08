from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware

BASE_DIR = Path(__file__).resolve().parent.parent

app = FastAPI(
    title="TrustVault - Secure Document Vault",
    description="Security Project - IDOR, JWT Revoke, Per-Person Sharing, Audit Logs",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# API Routers - Idi lekunte Docs lo No operations vastundi
from app.api import router as api_router
app.include_router(api_router)

# ---- Homepage - File unte file chupistundi, lekapothe simple page chupistundi - Error radu ----
@app.get("/", include_in_schema=False)
def home():
    index_file = BASE_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return HTMLResponse("""
    <div style="font-family:Arial;text-align:center;margin-top:80px">
    <h1>🔒 TrustVault - Secure Document Vault</h1>
    <p>Your Documents. Only Your People.</p>
    <p><a href="/docs">View API Docs</a> | <a href="/features">Features</a> | <a href="/vault">Vault</a></p>
    <p>IDOR Protection | JWT Revoke | Per-Person Sharing | Audit Logs</p>
    </div>
    """)

@app.get("/features", include_in_schema=False)
def features_page():
    f = BASE_DIR / "features.html"
    if f.exists():
        return FileResponse(f)
    return HTMLResponse("<div style='font-family:Arial;text-align:center;margin-top:60px'><h1>Features</h1><p>1. IDOR Protection - 403 if no permission<br>2. JWT + Revoke - Logout blacklists token<br>3. Per-Person Sharing - Share to specific email<br>4. Immutable Audit Log - Admin only</p><a href='/'>Back to Home</a></div>")

@app.get("/vault", include_in_schema=False)
def vault_page():
    f = BASE_DIR / "vault.html"
    if f.exists():
        return FileResponse(f)
    return HTMLResponse("<div style='font-family:Arial;text-align:center;margin-top:60px'><h1>My Vault</h1><p>Login / Upload - Use <a href='/docs'>API Docs</a> to test.</p><a href='/'>Back to Home</a></div>")

# ---- API Router ----
try:
    from app.api import router as api_router
    app.include_router(api_router)
except Exception as e:
    print("API router not loaded from app.api:", e)
    try:
        from app.api.auth import router as auth_router
        app.include_router(auth_router)
    except Exception:
        pass

@app.get("/health", include_in_schema=False)
def health():
    return {"status": "ok", "app": "TrustVault"}