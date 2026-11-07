# TrustVault - Secure Document Vault

Live: https://trustvault-94qe.onrender.com/docs
GitHub: https://github.com/shaiksonia0930-afk/trustvault

## What it does
- Register / Login with JWT
- Upload PDF, PNG, JPG, DOCX (max 10MB, magic bytes check)
- Share file with specific user (per-person permission)
- IDOR blocked - without permission 403
- Logout revokes token instantly (Redis blacklist)
- Audit logs - only ADMIN can view

## What it does NOT do
- No real ClamAV - dummy check only, placeholder
- No real S3 - local storage for demo

## Run
pip install -r requirements.txt
uvicorn app.main:app --reload

## Test
pytest tests/test_idor.py -v