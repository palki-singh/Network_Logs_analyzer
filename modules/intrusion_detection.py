"""
Rule-Based Intrusion Detection System (IDS) for SecureChat.
Analyzes structured security logs to detect malicious patterns, brute-force attacks,
unauthorized access attempts, abnormal velocity, endpoint reconnaissance, and session anomalies.
"""

import uuid
from datetime import datetime, timezone, timedelta
from config import Config
from modules.storage import load_json, save_json, append_json_item

class IntrusionDetectionEngine:
    def __init__(self, alerts_file=None, logs_file=None):
        self.alerts_file = alerts_file or Config.ALERTS_FILE
        self.logs_file = logs_file or Config.LOGS_FILE

    def get_all_alerts(self):
        """Returns all alerts ordered from newest to oldest."""
        alerts = load_json(self.alerts_file, default=[])
        # Sort descending by timestamp
        return sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)

    def get_unresolved_alerts(self):
        """Returns only unresolved security alerts."""
        alerts = self.get_all_alerts()
        return [a for a in alerts if a.get("status") == "UNRESOLVED"]

    def get_alert_by_id(self, alert_id):
        """Retrieve a single alert by ID."""
        alerts = load_json(self.alerts_file, default=[])
        for a in alerts:
            if a.get("alert_id") == alert_id:
                return a
        return None

    def resolve_alert(self, alert_id, resolved_by="admin"):
        """Marks an alert as RESOLVED."""
        alerts = load_json(self.alerts_file, default=[])
        resolved = False
        now_iso = datetime.now(timezone.utc).isoformat()
        for a in alerts:
            if a.get("alert_id") == alert_id:
                a["status"] = "RESOLVED"
                a["resolved_at"] = now_iso
                a["resolved_by"] = resolved_by
                resolved = True
                break
        if resolved:
            save_json(self.alerts_file, alerts)
        return resolved

    def _is_recent_duplicate(self, alert_type, source_ip, window_seconds=60):
        """
        Check if an identical unresolved alert for the same IP was recorded recently.
        Prevents alert flooding.
        """
        alerts = load_json(self.alerts_file, default=[])
        now = datetime.now(timezone.utc)
        for a in reversed(alerts):
            if a.get("alert_type") == alert_type and a.get("source_ip") == source_ip and a.get("status") == "UNRESOLVED":
                ts_str = a.get("timestamp", "")
                try:
                    ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    if (now - ts).total_seconds() < window_seconds:
                        return True
                except (ValueError, TypeError):
                    continue
        return False

    def create_alert(self, alert_type, source_ip, severity, description):
        """
        Constructs, logs, and stores a security alert.
        """
        if self._is_recent_duplicate(alert_type, source_ip):
            return None

        alert = {
            "alert_id": f"alert-{uuid.uuid4().hex[:10]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "source_ip": source_ip or "127.0.0.1",
            "severity": severity,
            "description": description,
            "status": "UNRESOLVED"
        }
        append_json_item(self.alerts_file, alert)
        return alert

    def _parse_time(self, ts_str):
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    def analyze_event(self, current_log):
        """
        Evaluates rule-based detection rules against the current log entry
        and historical security logs.
        """
        if not current_log or not isinstance(current_log, dict):
            return []

        all_logs = load_json(self.logs_file, default=[])
        generated_alerts = []

        now = datetime.now(timezone.utc)
        event_type = current_log.get("event_type", "")
        ip = current_log.get("ip_address", "127.0.0.1")
        username = current_log.get("username") or "anonymous"
        user_id = current_log.get("user_id") or ""
        endpoint = current_log.get("endpoint") or ""

        # Filter logs within the last 15 minutes for analysis
        cutoff_15m = now - timedelta(minutes=15)
        recent_logs = [
            l for l in all_logs
            if self._parse_time(l.get("timestamp", "")) >= cutoff_15m
        ]

        # -------------------------------------------------------------
        # Rule 1: Brute-Force Login Detection
        # -------------------------------------------------------------
        if event_type == "LOGIN_FAILED":
            bf_window = now - timedelta(seconds=Config.BRUTE_FORCE_WINDOW_SECONDS)
            failed_logins = [
                l for l in recent_logs
                if l.get("event_type") == "LOGIN_FAILED"
                and l.get("ip_address") == ip
                and self._parse_time(l.get("timestamp", "")) >= bf_window
            ]
            count = len(failed_logins)
            if count >= Config.BRUTE_FORCE_THRESHOLD:
                alert = self.create_alert(
                    alert_type="BRUTE_FORCE",
                    source_ip=ip,
                    severity="HIGH",
                    description=f"Brute-force login attack detected: {count} failed login attempts from IP {ip} within {Config.BRUTE_FORCE_WINDOW_SECONDS // 60} minutes (Target username: {username})."
                )
                if alert:
                    generated_alerts.append(alert)

        # -------------------------------------------------------------
        # Rule 2: Suspicious Rapid Login Activity
        # -------------------------------------------------------------
        if event_type in ("LOGIN_SUCCESS", "LOGIN_FAILED", "ADMIN_LOGIN_SUCCESS", "ADMIN_LOGIN_FAILED"):
            burst_window = now - timedelta(seconds=Config.FREQUENT_LOGIN_WINDOW_SECONDS)
            attempts = [
                l for l in recent_logs
                if l.get("event_type") in ("LOGIN_SUCCESS", "LOGIN_FAILED", "ADMIN_LOGIN_SUCCESS", "ADMIN_LOGIN_FAILED")
                and l.get("ip_address") == ip
                and self._parse_time(l.get("timestamp", "")) >= burst_window
            ]
            count = len(attempts)
            if count >= Config.FREQUENT_LOGIN_THRESHOLD:
                alert = self.create_alert(
                    alert_type="SUSPICIOUS_LOGIN_BURST",
                    source_ip=ip,
                    severity="MEDIUM",
                    description=f"Suspicious frequent login activity: {count} login attempts from IP {ip} within {Config.FREQUENT_LOGIN_WINDOW_SECONDS} seconds."
                )
                if alert:
                    generated_alerts.append(alert)

        # -------------------------------------------------------------
        # Rule 3: Unauthorized Access Detection
        # -------------------------------------------------------------
        if event_type == "UNAUTHORIZED_ACCESS":
            # Direct attack on admin section
            if endpoint.startswith("/admin"):
                alert = self.create_alert(
                    alert_type="UNAUTHORIZED_ADMIN_ACCESS",
                    source_ip=ip,
                    severity="HIGH",
                    description=f"Unauthorized access attempt detected targeting administrative route '{endpoint}' by user '{username}' from IP {ip}."
                )
                if alert:
                    generated_alerts.append(alert)
            else:
                unauth_window = now - timedelta(seconds=Config.UNAUTHORIZED_ACCESS_WINDOW_SECONDS)
                unauth_events = [
                    l for l in recent_logs
                    if l.get("event_type") == "UNAUTHORIZED_ACCESS"
                    and l.get("ip_address") == ip
                    and self._parse_time(l.get("timestamp", "")) >= unauth_window
                ]
                count = len(unauth_events)
                if count >= Config.UNAUTHORIZED_ACCESS_THRESHOLD:
                    alert = self.create_alert(
                        alert_type="UNAUTHORIZED_ACCESS",
                        source_ip=ip,
                        severity="MEDIUM",
                        description=f"Multiple unauthorized access attempts ({count}) to protected endpoints from IP {ip} within {Config.UNAUTHORIZED_ACCESS_WINDOW_SECONDS // 60} minutes."
                    )
                    if alert:
                        generated_alerts.append(alert)

        # -------------------------------------------------------------
        # Rule 4: Abnormal Message Sending Frequency
        # -------------------------------------------------------------
        if event_type == "MESSAGE_SENT" and user_id:
            msg_window = now - timedelta(seconds=Config.ABNORMAL_MESSAGE_WINDOW_SECONDS)
            user_msgs = [
                l for l in recent_logs
                if l.get("event_type") == "MESSAGE_SENT"
                and l.get("user_id") == user_id
                and self._parse_time(l.get("timestamp", "")) >= msg_window
            ]
            count = len(user_msgs)
            if count >= Config.ABNORMAL_MESSAGE_THRESHOLD:
                alert = self.create_alert(
                    alert_type="ABNORMAL_MESSAGE_ACTIVITY",
                    source_ip=ip,
                    severity="HIGH",
                    description=f"Abnormal message sending frequency: User '{username}' sent {count} messages in {Config.ABNORMAL_MESSAGE_WINDOW_SECONDS} seconds (Potential automated spam or bot activity)."
                )
                if alert:
                    generated_alerts.append(alert)

        # -------------------------------------------------------------
        # Rule 5: Invalid Endpoint Requests / Scanning Detection
        # -------------------------------------------------------------
        if event_type == "INVALID_URL_REQUEST":
            scan_window = now - timedelta(seconds=Config.INVALID_ENDPOINT_WINDOW_SECONDS)
            not_founds = [
                l for l in recent_logs
                if l.get("event_type") == "INVALID_URL_REQUEST"
                and l.get("ip_address") == ip
                and self._parse_time(l.get("timestamp", "")) >= scan_window
            ]
            count = len(not_founds)
            if count >= Config.INVALID_ENDPOINT_THRESHOLD:
                alert = self.create_alert(
                    alert_type="ENDPOINT_SCANNING",
                    source_ip=ip,
                    severity="MEDIUM",
                    description=f"Reconnaissance / scanning detected: {count} requests to nonexistent endpoints from IP {ip} within {Config.INVALID_ENDPOINT_WINDOW_SECONDS // 60} minutes (Latest: {endpoint})."
                )
                if alert:
                    generated_alerts.append(alert)

        # -------------------------------------------------------------
        # Rule 6: Session Security Violations
        # -------------------------------------------------------------
        if event_type in ("SESSION_TAMPERING", "SESSION_HIJACK_ATTEMPT", "INVALID_SESSION"):
            alert = self.create_alert(
                alert_type="SESSION_SECURITY_VIOLATION",
                source_ip=ip,
                severity="HIGH",
                description=f"Session security violation detected from IP {ip}: {current_log.get('description', 'Session anomaly detected')}."
            )
            if alert:
                generated_alerts.append(alert)

        return generated_alerts

# Global engine instance
ids_engine = IntrusionDetectionEngine()
