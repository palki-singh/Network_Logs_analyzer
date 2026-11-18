"""
Comprehensive automated test suite for SecureChat.
Verifies all user workflows, security logging, intrusion detection rules, and admin SOC dashboard.
"""

import unittest
import json
import os
import io
from app import app
from config import Config
from modules.storage import load_json
from modules.intrusion_detection import ids_engine
from modules.logging_system import security_logger

class SecureChatTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def test_01_index_loads(self):
        """Verify landing page loads successfully."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SecureChat", response.data)
        print("✓ Landing page loads successfully")

    def test_02_user_registration(self):
        """Verify new user registration and audit logging."""
        resp = self.client.get("/register")
        self.assertEqual(resp.status_code, 200)
        
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        unique_name = f"tester_{os.urandom(4).hex()}"
        reg_data = {
            "csrf_token": csrf_token,
            "full_name": "Test Testerson",
            "username": unique_name,
            "email": f"{unique_name}@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!"
        }
        post_resp = self.client.post("/register", data=reg_data, follow_redirects=True)
        self.assertEqual(post_resp.status_code, 200)
        self.assertIn(b"Account registered successfully", post_resp.data)

        # Check users.json
        users = load_json(Config.USERS_FILE)
        self.assertTrue(any(u["username"] == unique_name for u in users))

        # Check security_logs.json for USER_REGISTER
        logs = load_json(Config.LOGS_FILE)
        reg_logs = [l for l in logs if l.get("event_type") == "USER_REGISTER" and l.get("username") == unique_name]
        self.assertTrue(len(reg_logs) > 0)
        print("✓ User registration and logging verified")

    def test_03_successful_and_failed_login(self):
        """Verify login verification, session creation, and failed login audit logging."""
        # 1. Failed login
        resp = self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        bad_login = {
            "csrf_token": csrf_token,
            "identifier": "alice",
            "password": "WrongPassword!"
        }
        fail_resp = self.client.post("/login", data=bad_login, follow_redirects=True)
        self.assertIn(b"Invalid credentials", fail_resp.data)

        # Check security_logs.json for LOGIN_FAILED
        logs = load_json(Config.LOGS_FILE)
        fail_logs = [l for l in logs if l.get("event_type") == "LOGIN_FAILED" and l.get("username") == "alice"]
        self.assertTrue(len(fail_logs) > 0)

        # 2. Successful login
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        good_login = {
            "csrf_token": csrf_token,
            "identifier": "alice",
            "password": "Password123!"
        }
        succ_resp = self.client.post("/login", data=good_login, follow_redirects=True)
        self.assertIn(b"Welcome back", succ_resp.data)

        # Check session
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "alice")
            self.assertEqual(sess.get("role"), "user")

        print("✓ Successful and failed login audit logging verified")

    def test_04_private_messaging_and_metadata_logging(self):
        """Verify private messaging works and security log ONLY records metadata (no message text)."""
        # Login as alice
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        self.client.post("/login", data={"csrf_token": csrf_token, "identifier": "alice", "password": "Password123!"}, follow_redirects=True)

        # Alice sends message to Bob
        users = load_json(Config.USERS_FILE)
        bob = next(u for u in users if u["username"] == "bob")

        secret_message = "This_is_a_highly_confidential_message_xyz987"
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        msg_resp = self.client.post(
            f"/chat/{bob['user_id']}/send",
            data={"csrf_token": csrf_token, "content": secret_message},
            follow_redirects=True
        )
        self.assertEqual(msg_resp.status_code, 200)

        # Verify chats.json contains message
        chats = load_json(Config.CHATS_FILE)
        self.assertTrue(any(m["content"] == secret_message for m in chats))

        # CRITICAL SECURITY CHECK: Ensure secret_message is NOT in security_logs.json!
        logs = load_json(Config.LOGS_FILE)
        for log in logs:
            if log.get("event_type") == "MESSAGE_SENT" and log.get("username") == "alice":
                self.assertNotIn(secret_message, log.get("description", ""))
                self.assertIn("chars", log.get("description", ""))
        print("✓ Private messaging works and zero message content leakage in logs confirmed")

    def test_05_profile_update_and_file_upload_validation(self):
        """Verify profile modification, avatar upload, and rejection of disallowed extensions."""
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        self.client.post("/login", data={"csrf_token": csrf_token, "identifier": "alice", "password": "Password123!"}, follow_redirects=True)

        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        # 1. Reject invalid file extension (.exe)
        bad_upload = {
            "csrf_token": csrf_token,
            "full_name": "Alice Johnson",
            "email": "alice@securechat.local",
            "bio": "Updated bio test",
            "profile_pic": (io.BytesIO(b"malicious payload"), "malware.exe")
        }
        rej_resp = self.client.post("/profile/edit", data=bad_upload, follow_redirects=True)
        self.assertIn(b"Invalid file type", rej_resp.data)

        # 2. Accept valid PNG avatar
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        good_upload = {
            "csrf_token": csrf_token,
            "full_name": "Alice J. Researcher",
            "email": "alice@securechat.local",
            "bio": "Cybersecurity researcher.",
            "profile_pic": (io.BytesIO(b"\x89PNG\r\n\x1a\nfakeimagecontent"), "avatar.png")
        }
        succ_resp = self.client.post("/profile/edit", data=good_upload, follow_redirects=True)
        self.assertIn(b"Profile updated successfully", succ_resp.data)
        print("✓ Profile update and file upload extension restriction verified")

    def test_06_intrusion_detection_rules(self):
        """Verify IDS triggers: brute force, 404 scanning, and abnormal messaging."""
        # 1. Trigger Brute-force rule (5 failed logins from one IP)
        test_ip = "192.0.2.11"
        for _ in range(5):
            security_logger.log_event(
                event_type="LOGIN_FAILED",
                description="Failed login test",
                username="victim_user",
                ip_address=test_ip,
                status="FAILED",
                severity="MEDIUM"
            )

        alerts = ids_engine.get_all_alerts()
        bf_alerts = [a for a in alerts if a.get("alert_type") == "BRUTE_FORCE" and a.get("source_ip") == test_ip]
        self.assertTrue(len(bf_alerts) > 0)
        self.assertEqual(bf_alerts[0]["severity"], "HIGH")

        # 2. Trigger 404 Scanning rule
        scan_ip = "192.0.2.22"
        for i in range(5):
            security_logger.log_event(
                event_type="INVALID_URL_REQUEST",
                description=f"Scan probe {i}",
                ip_address=scan_ip,
                endpoint=f"/probe_{i}",
                status="NOT_FOUND",
                severity="LOW"
            )

        alerts = ids_engine.get_all_alerts()
        scan_alerts = [a for a in alerts if a.get("alert_type") == "ENDPOINT_SCANNING" and a.get("source_ip") == scan_ip]
        self.assertTrue(len(scan_alerts) > 0)

        # 3. Trigger Abnormal Message Activity (15 messages from a user)
        spam_uid = "u-spammer-99"
        for i in range(16):
            security_logger.log_event(
                event_type="MESSAGE_SENT",
                description=f"Spam message {i}",
                username="spambot",
                user_id=spam_uid,
                ip_address="192.0.2.33",
                status="SUCCESS",
                severity="LOW"
            )

        alerts = ids_engine.get_all_alerts()
        spam_alerts = [a for a in alerts if a.get("alert_type") == "ABNORMAL_MESSAGE_ACTIVITY"]
        self.assertTrue(len(spam_alerts) > 0)
        print("✓ Intrusion Detection System rules verified (Brute-Force, 404 Scanning, Abnormal Velocity)")

    def test_07_admin_dashboard_and_export(self):
        """Verify admin login, dashboard metrics, log explorer, alert triage, and JSON export."""
        # Non-admin access to admin dashboard should redirect to /admin/login
        unauth_resp = self.client.get("/admin/dashboard", follow_redirects=True)
        self.assertIn(b"Administrator access required", unauth_resp.data)

        # Authenticate as admin
        self.client.get("/admin/login")
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        admin_login = {
            "csrf_token": csrf_token,
            "identifier": "admin",
            "password": "Admin@SecureChat2026!"
        }
        auth_resp = self.client.post("/admin/login", data=admin_login, follow_redirects=True)
        self.assertIn(b"SOC Defense Console unlocked", auth_resp.data)

        # Access dashboard
        dash_resp = self.client.get("/admin/dashboard")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn(b"Cybersecurity SOC Overview", dash_resp.data)

        # Access logs explorer
        logs_resp = self.client.get("/admin/logs")
        self.assertEqual(logs_resp.status_code, 200)

        # Access JSON raw viewer
        viewer_resp = self.client.get("/admin/logs_viewer")
        self.assertEqual(viewer_resp.status_code, 200)

        # Triage and resolve an alert
        unresolved = ids_engine.get_unresolved_alerts()
        if unresolved:
            target_alert = unresolved[0]
            with self.client.session_transaction() as sess:
                csrf_token = sess.get("csrf_token")
            res_resp = self.client.post(
                f"/admin/alerts/{target_alert['alert_id']}/resolve",
                data={"csrf_token": csrf_token},
                follow_redirects=True
            )
            self.assertEqual(res_resp.status_code, 200)
            updated_alert = ids_engine.get_alert_by_id(target_alert["alert_id"])
            self.assertEqual(updated_alert["status"], "RESOLVED")

        # Export logs
        with self.client.get("/admin/export_logs") as export_resp:
            self.assertEqual(export_resp.status_code, 200)
            self.assertEqual(export_resp.mimetype, "application/json")
            exported_data = json.loads(export_resp.data.decode("utf-8"))
            self.assertIsInstance(exported_data, list)

        print("✓ Admin SOC dashboard, alert resolution, and JSON export verified")

    def test_08_ai_anomaly_detection_and_dashboard_warning(self):
        """Verify AI Anomaly Detection: unauthorized request & unusual login volume warnings."""
        from modules.ai_detector import ai_detector

        # 1. Trigger AI Detection on Unauthorized Request
        test_ip = "192.0.2.199"
        security_logger.log_event(
            event_type="UNAUTHORIZED_ACCESS",
            description="Malicious unauthorized access attempt to /admin/secret_keys",
            username="anonymous",
            user_id="unauthenticated",
            ip_address=test_ip,
            endpoint="/admin/secret_keys",
            http_method="POST",
            status="DENIED",
            severity="HIGH"
        )

        # Verify AI warning alert generated
        alerts = ids_engine.get_all_alerts()
        ai_unauth_alerts = [a for a in alerts if a.get("alert_type") == "AI_UNAUTHORIZED_REQUEST_ANOMALY" and a.get("source_ip") == test_ip]
        self.assertTrue(len(ai_unauth_alerts) > 0)
        self.assertIn("AI Warning", ai_unauth_alerts[0]["description"])

        # 2. Trigger AI Detection on Unusual Amount of Logins
        burst_ip = "192.0.2.188"
        for i in range(8):
            security_logger.log_event(
                event_type="LOGIN_FAILED",
                description=f"Rapid login guessing attempt {i+1}/8",
                username="victim_account",
                user_id="unauthenticated",
                ip_address=burst_ip,
                endpoint="/login",
                http_method="POST",
                status="FAILED",
                severity="MEDIUM"
            )

        # Verify AI unusual login alert generated
        alerts = ids_engine.get_all_alerts()
        ai_login_alerts = [a for a in alerts if a.get("alert_type") == "AI_UNUSUAL_LOGIN_VOLUME" and a.get("source_ip") == burst_ip]
        self.assertTrue(len(ai_login_alerts) > 0)

        # 3. Authenticate as Admin and verify AI Warning displays on Dashboard
        self.client.get("/admin/login")
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        self.client.post("/admin/login", data={"csrf_token": csrf_token, "identifier": "admin", "password": "Admin@SecureChat2026!"}, follow_redirects=True)
        dash_resp = self.client.get("/admin/dashboard")
        self.assertEqual(dash_resp.status_code, 200)
        self.assertIn(b"AI LOG ANOMALY WARNING DISPATCHED", dash_resp.data)

        # 4. Verify AI Analysis Console loads
        ai_resp = self.client.get("/admin/ai_analysis")
        self.assertEqual(ai_resp.status_code, 200)
        self.assertIn(b"AI Log Anomaly Detection System", ai_resp.data)
        self.assertIn(b"Isolation Forest", ai_resp.data)

        print("✓ AI Log Anomaly Detection (unauthorized requests & unusual login volume warnings) verified")

if __name__ == "__main__":
    unittest.main()
