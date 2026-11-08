import sys
import io
import requests

BASE_URL = "https://trustvault-frontend-seven.vercel.app"

ADMIN_EMAIL = "admin@trustvault.io"
ADMIN_PASS = "AdminVaultPass2026!"

OWNER_EMAIL = "alice.owner@trustvault.io"
OWNER_PASS = "AliceVaultPass2026!"

VIEWER_EMAIL = "charlie.viewer@trustvault.io"
VIEWER_PASS = "CharlieVaultPass2026!"

def login(email, password):
    session = requests.Session()
    r = session.post(
        f"{BASE_URL}/api/auth/login",
        json={"email": email, "password": password},
        headers={"Content-Type": "application/json"}
    )
    print(f"Login {email}: status={r.status_code}")
    if r.status_code != 200:
        print(f"Error response: {r.text}")
        sys.exit(1)
    csrf_token = session.cookies.get("tv_csrf")
    return session, csrf_token

def main():
    print("--- 1. Testing Health Check ---")
    r_health = requests.get(f"{BASE_URL}/api/health")
    print(f"Health check: status={r_health.status_code}, body={r_health.text}")
    assert r_health.status_code == 200
    assert r_health.json().get("status") == "ok"
    assert r_health.json().get("db") is True

    print("\n--- 2. Login as Owner ---")
    owner_session, owner_csrf = login(OWNER_EMAIL, OWNER_PASS)

    print("\n--- 3. Upload Document as Owner ---")
    test_content = b"TrustVault E2E Test Document - Provable Audit Trail and Encrypted Bytea Storage."
    files = {
        "file": ("e2e_test_doc.txt", io.BytesIO(test_content), "text/plain")
    }
    data = {
        "name": "Live E2E Test Document.txt",
        "category": "Verification",
        "description": "Uploaded via live E2E verification test"
    }
    headers = {"X-CSRF-Token": owner_csrf}
    r_upload = owner_session.post(
        f"{BASE_URL}/api/documents",
        files=files,
        data=data,
        headers=headers
    )
    print(f"Upload doc: status={r_upload.status_code}, body={r_upload.text}")
    assert r_upload.status_code == 201, f"Upload failed: {r_upload.text}"
    doc_data = r_upload.json()
    doc_id = doc_data["id"]
    print(f"Created doc_id: {doc_id}")

    print("\n--- 4. Share Document with Viewer ---")
    r_grant = owner_session.post(
        f"{BASE_URL}/api/documents/{doc_id}/grants",
        json={"user_email": VIEWER_EMAIL, "perm": "read"},
        headers={"X-CSRF-Token": owner_csrf, "Content-Type": "application/json"}
    )
    print(f"Grant access: status={r_grant.status_code}, body={r_grant.text}")
    assert r_grant.status_code in (200, 201), f"Grant failed: {r_grant.text}"
    grant_id = r_grant.json()["id"]
    print(f"Created grant_id: {grant_id}")

    print("\n--- 5. Login as Viewer and Download ---")
    viewer_session, viewer_csrf = login(VIEWER_EMAIL, VIEWER_PASS)
    r_download = viewer_session.get(f"{BASE_URL}/api/documents/{doc_id}/download")
    print(f"Viewer download: status={r_download.status_code}, length={len(r_download.content)}")
    assert r_download.status_code == 200, f"Download failed: {r_download.status_code} {r_download.text}"
    assert r_download.content == test_content, f"Content mismatch! Received: {r_download.content}"
    print("Downloaded content matches uploaded content perfectly!")

    print("\n--- 6. Revoke Grant as Owner ---")
    r_revoke = owner_session.delete(
        f"{BASE_URL}/api/documents/{doc_id}/grants/{grant_id}",
        headers={"X-CSRF-Token": owner_csrf}
    )
    print(f"Revoke grant: status={r_revoke.status_code}, body={r_revoke.text}")
    assert r_revoke.status_code == 200, f"Revoke failed: {r_revoke.text}"

    print("\n--- 7. Viewer Attempts Download After Revocation (Must 404) ---")
    r_revoked_download = viewer_session.get(f"{BASE_URL}/api/documents/{doc_id}/download")
    print(f"Viewer download after revocation: status={r_revoked_download.status_code}, body={r_revoked_download.text}")
    assert r_revoked_download.status_code == 404, f"Expected 404, got {r_revoked_download.status_code}"
    print("Confirmed: Viewer receives 404 (anti-enumeration security requirement satisfied)!")

    print("\n--- 8. Access Random Stranger Document ID (Must 404) ---")
    random_id = "00000000-0000-0000-0000-000000000000"
    r_random = viewer_session.get(f"{BASE_URL}/api/documents/{random_id}/download")
    print(f"Random doc download: status={r_random.status_code}, body={r_random.text}")
    assert r_random.status_code == 404

    print("\n--- 9. Login as Admin and Verify Audit Chain ---")
    admin_session, admin_csrf = login(ADMIN_EMAIL, ADMIN_PASS)
    r_verify = admin_session.get(f"{BASE_URL}/api/admin/audit/verify")
    print(f"Audit chain verify: status={r_verify.status_code}, body={r_verify.text}")
    assert r_verify.status_code == 200
    chain_result = r_verify.json()
    assert chain_result.get("ok") is True, f"Chain invalid: {chain_result}"
    print(f"Audit chain verified successfully! Chain ok: {chain_result.get('ok')}, total_events: {chain_result.get('total_events')}")

    print("\n==========================================")
    print("ALL LIVE TESTS PASSED SUCCESSFULLY!")
    print("==========================================")

if __name__ == "__main__":
    main()
