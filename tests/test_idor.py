"""
Test: Viewer vere vaadi file download cheyalekapovali - IDOR Test
Run: pytest tests/test_idor.py -v
"""
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_idor_block():
    # 1. Register Owner A
    client.post("/auth/register", json={"email": "ownerA@test.com", "password": "password123", "full_name": "Owner A", "role": "OWNER"})
    # 2. Register Viewer B
    client.post("/auth/register", json={"email": "viewerB@test.com", "password": "password123", "full_name": "Viewer B", "role": "VIEWER"})

    # 3. Login as A
    resA = client.post("/auth/login", json={"email": "ownerA@test.com", "password": "password123"})
    tokenA = resA.json()["access_token"]
    
    # 4. A uploads file
    files = {"file": ("test.pdf", b"%PDF-1.4 fake pdf content", "application/pdf")}
    res_upload = client.post("/documents/upload", files=files, headers={"Authorization": f"Bearer {tokenA}"})
    assert res_upload.status_code == 200
    doc_id = res_upload.json()["id"]

    # 5. Login as B
    resB = client.post("/auth/login", json={"email": "viewerB@test.com", "password": "password123"})
    tokenB = resB.json()["access_token"]

    # 6. B tries to download A's file WITHOUT permission -> MUST FAIL 403
    res_fail = client.get(f"/documents/{doc_id}/download", headers={"Authorization": f"Bearer {tokenB}"})
    assert res_fail.status_code == 403, "IDOR FAILED: Viewer accessed without permission!"
    print("IDOR Test Passed: Viewer blocked")

    # 7. A shares with B
    share_res = client.post(f"/documents/{doc_id}/share", json={"user_email": "viewerB@test.com", "can_read": True}, headers={"Authorization": f"Bearer {tokenA}"})
    assert share_res.status_code == 200

    # 8. Now B should be able to download -> MUST PASS 200
    res_pass = client.get(f"/documents/{doc_id}/download", headers={"Authorization": f"Bearer {tokenB}"})
    assert res_pass.status_code == 200, "Share failed"
    print("Share Test Passed: Viewer can access after permission")

    # 9. Test JWT Revoke
    client.post("/auth/logout", headers={"Authorization": f"Bearer {tokenB}"})
    res_revoked = client.get("/auth/me", headers={"Authorization": f"Bearer {tokenB}"})
    assert res_revoked.status_code == 401, "JWT Revoke Failed"
    print("JWT Revoke Test Passed")