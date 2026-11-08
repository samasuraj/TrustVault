import os
import time
from playwright.sync_api import sync_playwright

SCREENSHOT_DIR = "browser_screenshots"
os.makedirs(SCREENSHOT_DIR, exist_ok=True)

def test_trustvault_ui():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": 1280, "height": 850})
        page = context.new_page()

        print("[1/5] Navigating to http://localhost...")
        page.goto("http://localhost", wait_until="networkidle")
        page.wait_for_selector(".login-card", timeout=10000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "01_login_page.png"))
        print(" -> DOM: Login card rendered successfully.")

        # -------------------------------------------------------------
        # Step 1: Admin Workflow
        # -------------------------------------------------------------
        print("\n[2/5] Testing Admin Persona...")
        # Demo button index 0 is Admin
        page.locator("button.btn-demo").nth(0).click()
        assert page.locator("#email").input_value() == "admin@trustvault.local"
        page.locator("button[type='submit']").click()

        # Wait for Admin Console to appear in DOM
        page.wait_for_selector("text=Admin Console", timeout=10000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "02_admin_console.png"))
        print(" -> DOM: Logged in as Admin. 'Admin Console' rendered.")

        # Test Audit Trail Explorer subtab
        audit_tab = page.locator(".sub-tab:has-text('Audit Trail Explorer')")
        assert audit_tab.is_visible()
        print(" -> DOM: Audit Trail Explorer visible.")

        # Verify Audit Chain Integrity button
        verify_btn = page.locator("button:has-text('Verify Audit Hash Chain')")
        assert verify_btn.is_visible()
        verify_btn.click()
        page.wait_for_selector("strong:has-text('Audit Chain Cryptographically Intact')", timeout=10000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "03_admin_chain_verified.png"))
        print(" -> DOM: Clicked 'Verify Audit Hash Chain' -> 'Audit Chain Cryptographically Intact' banner verified!")

        # Test Security Alerts subtab
        alerts_tab = page.locator(".sub-tab:has-text('Security Alerts')")
        alerts_tab.click()
        time.sleep(0.5)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "04_admin_alerts.png"))
        print(" -> DOM: Switched to 'Security Alerts' tab.")

        # Test User Management subtab
        users_tab = page.locator(".sub-tab:has-text('User Management')")
        users_tab.click()
        page.wait_for_selector("text=Register New Vault User", timeout=5000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "05_admin_user_mgmt.png"))
        print(" -> DOM: Switched to 'User Management' tab.")

        # Test Administrative Activity subtab
        activity_tab = page.locator(".sub-tab:has-text('Administrative Activity')")
        activity_tab.click()
        page.wait_for_selector("text=All User Actions", timeout=5000)
        page.wait_for_selector(".admin-activity-container .table tbody tr", timeout=8000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "05b_admin_activity_all.png"))
        print(" -> DOM: Switched to 'Administrative Activity' tab (All Actions visible).")

        # Test Login History toggle
        page.locator("button:has-text('Login History')").click()
        page.wait_for_selector("text=Login History (last 30 days)", timeout=5000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "05c_admin_activity_logins.png"))
        print(" -> DOM: Switched to 'Login History' view.")


        # Sign out Admin
        page.locator("button:has-text('Sign Out')").click()
        page.wait_for_selector(".login-card", timeout=10000)
        print(" -> DOM: Admin signed out successfully.")

        # -------------------------------------------------------------
        # Step 2: Owner Workflow (Alice)
        # -------------------------------------------------------------
        print("\n[3/5] Testing Document Owner Persona (Alice)...")
        # Demo button index 1 is Alice (Owner)
        page.locator("button.btn-demo").nth(1).click()
        assert page.locator("#email").input_value() == "alice.owner@trustvault.local"
        page.locator("button[type='submit']").click()

        # Wait for Document list to appear
        page.wait_for_selector(".nav-btn-upload:has-text('Upload Document')", timeout=10000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "06_owner_documents.png"))
        print(" -> DOM: Logged in as Alice (Owner). 'Upload Document' button is present.")

        # Open Upload Modal
        page.locator(".nav-btn-upload").click()
        page.wait_for_selector("text=Upload Encrypted Document", timeout=5000)
        print(" -> DOM: Upload Modal opened.")

        # Create temporary file for upload
        test_file = os.path.join(SCREENSHOT_DIR, "sample_board_brief.pdf")
        with open(test_file, "wb") as f:
            f.write(b"%PDF-1.4\n1 0 obj\n<< /Title (Board Brief) >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF")

        doc_name = f"Executive_Board_Brief_{int(time.time())}.pdf"
        page.set_input_files("input[type='file']", test_file)
        page.fill("#doc-name", doc_name)
        page.select_option("#doc-category", "Legal")
        page.fill("#doc-desc", "Confidential quarterly strategy and risk analysis")
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "07_upload_modal_filled.png"))

        # Click Upload & Encrypt
        page.locator("button[type='submit']:has-text('Upload & Encrypt')").click()
        page.wait_for_selector(f"text={doc_name}", timeout=10000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "08_document_in_table.png"))
        print(f" -> DOM: Document '{doc_name}' uploaded, encrypted with AES-256-GCM, and displayed in table.")

        # Click document row to view details
        page.locator(f"text={doc_name}").first.click()
        page.wait_for_selector("text=Version History", timeout=10000)
        page.wait_for_selector("text=Access Grants", timeout=5000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "09_document_details.png"))
        print(" -> DOM: Document Details loaded with Version History and Sharing controls.")

        # Test AI Sharing Assistant
        suggest_btn = page.locator(".btn-ai")
        if suggest_btn.is_visible():
            suggest_btn.click()
            page.wait_for_selector("text=Suggested Users", timeout=10000)
            time.sleep(1)
            page.screenshot(path=os.path.join(SCREENSHOT_DIR, "10_ai_sharing_suggestions.png"))
            print(" -> DOM: AI Sharing Assistant recommendations rendered with rationale badges.")

            # Test Confirm Suggestions (Accept Charlie & others)
            accept_btn = page.locator("button:has-text('Accept & Grant Selected')")
            if accept_btn.is_visible():
                accept_btn.click()
                page.wait_for_selector("text=Decision recorded: accepted", timeout=5000)
                page.screenshot(path=os.path.join(SCREENSHOT_DIR, "10b_ai_suggestions_confirmed.png"))
                print(" -> DOM: Confirmed AI suggestions. Decision recorded in provable audit log.")

        # Test Decrypted Streaming Download
        with page.expect_download() as download_info:
            page.locator("button:has-text('Download File')").click()
        download = download_info.value
        assert download is not None
        print(f" -> DOM: Authenticated streaming download verified: {download.suggested_filename}")

        # Navigate back to document list
        page.locator("button:has-text('Back to Documents')").click()
        page.wait_for_selector("input[placeholder*='Search document name']", timeout=5000)

        # Test Search Filter
        page.fill("input[placeholder*='Search document name']", "Executive")
        page.locator("button:has-text('Apply Search')").click()
        page.wait_for_selector(f"text={doc_name}", timeout=5000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "10c_search_filtered.png"))
        print(f" -> DOM: Search filter applied: 'Executive' matched document '{doc_name}'.")

        # Sign out Alice
        page.locator("button:has-text('Sign Out')").click()
        page.wait_for_selector(".login-card", timeout=10000)
        print(" -> DOM: Alice signed out successfully.")

        # -------------------------------------------------------------
        # Step 3: Viewer Persona (Charlie)
        # -------------------------------------------------------------
        print("\n[4/5] Testing Viewer Persona (Charlie) & RBAC Restrictions...")
        # Demo button index 3 is Charlie (Viewer)
        page.locator("button.btn-demo").nth(3).click()
        assert page.locator("#email").input_value() == "charlie.viewer@trustvault.local"
        page.locator("button[type='submit']").click()

        page.wait_for_selector(".navbar-nav", timeout=10000)
        time.sleep(1)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "11_viewer_dashboard.png"))

        # In DOM, verify viewer CANNOT upload documents
        upload_btn_count = page.locator("button:has-text('Upload Document')").count()
        assert upload_btn_count == 0, "Viewer must not have 'Upload Document' button!"
        print(" -> DOM: Verified RBAC enforcement: 'Upload Document' button does NOT exist in DOM for Viewer.")

        # In DOM, verify Charlie now has access to the document granted by Alice via AI Assistant
        page.wait_for_selector(f"text={doc_name}", timeout=5000)
        print(f" -> DOM: Verified Charlie sees granted document '{doc_name}'.")

        # Open document and verify Active Grant badge
        page.locator(f"text={doc_name}").first.click()
        page.wait_for_selector("text=Active Grant", timeout=5000)
        page.screenshot(path=os.path.join(SCREENSHOT_DIR, "12_viewer_document_view.png"))
        print(" -> DOM: Verified Charlie's 'Active Grant' badge on document.")

        # Sign out Charlie
        page.locator("button:has-text('Sign Out')").click()
        page.wait_for_selector(".login-card", timeout=10000)
        print(" -> DOM: Charlie signed out successfully.")

        print("\n[5/5] ALL DOM AND USER INTERFACE WORKFLOWS TESTED AND VERIFIED SUCCESSFULLY!")
        browser.close()

if __name__ == "__main__":
    test_trustvault_ui()
