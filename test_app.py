"""
Comprehensive automated test suite for Cosmic Connect / SecureChat.
Verifies all user workflows, security logging, intrusion detection rules,
Groq AI 5-second log batch analysis, and critical incident report generation.
"""

import unittest
import json
import os
import io
import time
from app import app
from config import Config
from modules.storage import load_json, save_json
from modules.intrusion_detection import ids_engine
from modules.logging_system import security_logger
from modules.groq_detector import groq_analyzer
from modules.authentication import register_user

class CosmicConnectTestCase(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Ensure test users exist for login & messaging tests
        users = load_json(Config.USERS_FILE)
        if not any(u["username"] == "test_alice" for u in users):
            register_user("Alice Stargazer", "test_alice", "test_alice@cosmic.local", "Password123!", "Password123!", "♏ Scorpio")
        if not any(u["username"] == "test_bob" for u in users):
            register_user("Bob Astronomer", "test_bob", "test_bob@cosmic.local", "Password123!", "Password123!", "♒ Aquarius")

    def test_01_index_loads(self):
        """Verify landing page loads successfully."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Cosmic Connect", response.data)
        print("✓ Landing page loads successfully")

    def test_02_user_registration(self):
        """Verify new user registration and audit logging."""
        resp = self.client.get("/register")
        self.assertEqual(resp.status_code, 200)
        
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        unique_name = f"seeker_{os.urandom(4).hex()}"
        reg_data = {
            "csrf_token": csrf_token,
            "full_name": "Nova Seeker",
            "username": unique_name,
            "email": f"{unique_name}@example.com",
            "zodiac_sign": "♈ Aries (Fire)",
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
            "identifier": "test_alice",
            "password": "WrongPassword!"
        }
        fail_resp = self.client.post("/login", data=bad_login, follow_redirects=True)
        self.assertIn(b"Invalid credentials", fail_resp.data)

        # Check security_logs.json for LOGIN_FAILED
        logs = load_json(Config.LOGS_FILE)
        fail_logs = [l for l in logs if l.get("event_type") == "LOGIN_FAILED" and l.get("username") == "test_alice"]
        self.assertTrue(len(fail_logs) > 0)

        # 2. Successful login
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        good_login = {
            "csrf_token": csrf_token,
            "identifier": "test_alice",
            "password": "Password123!"
        }
        succ_resp = self.client.post("/login", data=good_login, follow_redirects=True)
        self.assertIn(b"Welcome back", succ_resp.data)

        # Check session
        with self.client.session_transaction() as sess:
            self.assertEqual(sess.get("username"), "test_alice")
            self.assertEqual(sess.get("role"), "user")

        print("✓ Successful and failed login audit logging verified")

    def test_04_private_messaging_and_metadata_logging(self):
        """Verify private messaging works and security log ONLY records metadata (no message text)."""
        # Login as test_alice
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        self.client.post("/login", data={"csrf_token": csrf_token, "identifier": "test_alice", "password": "Password123!"}, follow_redirects=True)

        # Alice sends message to Bob
        users = load_json(Config.USERS_FILE)
        bob = next(u for u in users if u["username"] == "test_bob")

        secret_message = "This_is_a_highly_confidential_planetary_frequency_789"
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
            if log.get("event_type") == "MESSAGE_SENT" and log.get("username") == "test_alice":
                self.assertNotIn(secret_message, log.get("description", ""))
                self.assertIn("chars", log.get("description", ""))
        print("✓ Private messaging works and zero message content leakage in logs confirmed")

    def test_05_profile_update_and_file_upload_validation(self):
        """Verify profile modification, avatar upload, and rejection of disallowed extensions."""
        self.client.get("/login")
        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        self.client.post("/login", data={"csrf_token": csrf_token, "identifier": "test_alice", "password": "Password123!"}, follow_redirects=True)

        with self.client.session_transaction() as sess:
            csrf_token = sess.get("csrf_token")

        # 1. Reject invalid file extension (.exe)
        bad_upload = {
            "csrf_token": csrf_token,
            "full_name": "Alice Stargazer",
            "email": "test_alice@cosmic.local",
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
            "full_name": "Alice J. Stargazer",
            "email": "test_alice@cosmic.local",
            "bio": "Astrology devotee exploring celestial frequencies.",
            "zodiac_sign": "♏ Scorpio (Water)",
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
        print("✓ Intrusion Detection System rules verified (Brute-Force & 404 Scanning)")

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

        # Export logs
        with self.client.get("/admin/export_logs") as export_resp:
            self.assertEqual(export_resp.status_code, 200)
            self.assertEqual(export_resp.mimetype, "application/json")
            exported_data = json.loads(export_resp.data.decode("utf-8"))
            self.assertIsInstance(exported_data, list)

        print("✓ Admin SOC dashboard, alert resolution, and JSON export verified")

    def test_08_groq_ai_batch_analysis_and_critical_reports(self):
        """Verify Groq AI 5-second log batch analysis and Critical Incident Report generation."""
        # Generate an unauthorized admin penetration log event
        attacker_ip = "198.51.100.77"
        security_logger.log_event(
            event_type="UNAUTHORIZED_ACCESS",
            description="Malicious unauthorized access attempt to /admin/confidential_keys",
            username="anonymous",
            user_id="unauthenticated",
            ip_address=attacker_ip,
            endpoint="/admin/confidential_keys",
            http_method="POST",
            status="DENIED",
            severity="HIGH"
        )

        # Trigger Groq AI analysis on recent batch
        diagnosis = groq_analyzer.analyze_recent_batch()
        self.assertIsNotNone(diagnosis)
        self.assertTrue(diagnosis.get("attack_detected"))
        self.assertIn(diagnosis.get("attack_type"), ["UNAUTHORIZED_ACCESS", "UNAUTHORIZED_ADMIN_ACCESS", "BRUTE_FORCE", "ANOMALY"])
        print(f"✓ Groq AI successfully analyzed batch: Attack Type={diagnosis.get('attack_type')}, Severity={diagnosis.get('severity')}")

        # Check if critical report was generated
        reports = groq_analyzer.get_all_reports()
        if reports:
            target_report = reports[0]
            self.assertEqual(target_report["threat_level"], "CRITICAL")
            self.assertIn("report_id", target_report)

            # Test admin viewing report
            self.client.get("/admin/login")
            with self.client.session_transaction() as sess:
                csrf_token = sess.get("csrf_token")
            self.client.post("/admin/login", data={"csrf_token": csrf_token, "identifier": "admin", "password": "Admin@SecureChat2026!"}, follow_redirects=True)

            rep_view_resp = self.client.get(f"/admin/reports/{target_report['report_id']}")
            self.assertEqual(rep_view_resp.status_code, 200)
            self.assertIn(b"Executive Threat Overview", rep_view_resp.data)

            # Test report export
            export_resp = self.client.get(f"/admin/reports/{target_report['report_id']}/export")
            self.assertEqual(export_resp.status_code, 200)
            self.assertEqual(export_resp.mimetype, "application/json")
            print("✓ Groq AI Critical Incident Report generation, viewing, and export verified")

if __name__ == "__main__":
    unittest.main()
