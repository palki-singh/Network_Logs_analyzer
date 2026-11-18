"""
Cybersecurity Logging Module for SecureChat.
Records all security-relevant application events in structured JSON format.
Ensures zero exposure of passwords, tokens, or private chat contents.
Automatically triggers the Intrusion Detection System upon new events.
"""

import uuid
from datetime import datetime, timezone
from flask import request, has_request_context, session
from config import Config
from modules.storage import load_json, append_json_item
from modules.intrusion_detection import ids_engine

class SecurityLogger:
    def __init__(self, logs_file=None):
        self.logs_file = logs_file or Config.LOGS_FILE

    def log_event(self,
                  event_type,
                  description,
                  username=None,
                  user_id=None,
                  ip_address=None,
                  endpoint=None,
                  http_method=None,
                  status="SUCCESS",
                  severity="LOW",
                  trigger_ids=True):
        """
        Record a security event to security_logs.json.
        Automatically infers IP, endpoint, HTTP method, and session user from Flask request if not provided.
        """
        # Infer context if within active Flask request
        if has_request_context():
            if ip_address is None:
                # Handle X-Forwarded-For if behind reverse proxy safely
                if request.headers.get("X-Forwarded-For"):
                    ip_address = request.headers.get("X-Forwarded-For").split(",")[0].strip()
                else:
                    ip_address = request.remote_addr or "127.0.0.1"

            if endpoint is None:
                endpoint = request.path

            if http_method is None:
                http_method = request.method

            if username is None and "username" in session:
                username = session.get("username")

            if user_id is None and "user_id" in session:
                user_id = session.get("user_id")

        # Fallbacks
        username = username or "anonymous"
        user_id = user_id or "unauthenticated"
        ip_address = ip_address or "127.0.0.1"
        endpoint = endpoint or "/"
        http_method = http_method or "SYSTEM"

        # Construct log entry matching strictly the required schema
        log_entry = {
            "log_id": f"log-{uuid.uuid4().hex[:12]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "username": username,
            "user_id": user_id,
            "event_type": event_type,
            "ip_address": ip_address,
            "endpoint": endpoint,
            "http_method": http_method,
            "status": status,
            "severity": severity,
            "description": description
        }

        # Thread-safe persistent save
        append_json_item(self.logs_file, log_entry)

        # Trigger Intrusion Detection System & AI Anomaly Detection
        if trigger_ids:
            try:
                alerts = ids_engine.analyze_event(log_entry)
                if alerts:
                    # Log that an IDS alert was triggered without triggering recursive IDS
                    for alert in alerts:
                        self.log_event(
                            event_type="SUSPICIOUS_ACTIVITY",
                            description=f"Intrusion detection trigger: [{alert['alert_type']}] - {alert['description']}",
                            username=username,
                            user_id=user_id,
                            ip_address=ip_address,
                            endpoint=endpoint,
                            http_method=http_method,
                            status="ALERT_TRIGGERED",
                            severity=alert["severity"],
                            trigger_ids=False
                        )

                # Trigger AI Anomaly Detection Engine
                from modules.ai_detector import ai_detector
                ai_alert, analysis = ai_detector.analyze_and_dispatch_warning(log_entry)
                if ai_alert:
                    self.log_event(
                        event_type="SUSPICIOUS_ACTIVITY",
                        description=f"AI Anomaly Alert [{ai_alert['alert_type']}]: {ai_alert['description']}",
                        username=username,
                        user_id=user_id,
                        ip_address=ip_address,
                        endpoint=endpoint,
                        http_method=http_method,
                        status="ALERT_TRIGGERED",
                        severity=ai_alert["severity"],
                        trigger_ids=False
                    )
            except Exception as e:
                # Never crash the main app if IDS/AI analysis encounters an edge case
                pass

        return log_entry

    def get_all_logs(self, reverse=True):
        """Retrieve all logs, newest first by default."""
        logs = load_json(self.logs_file, default=[])
        if reverse:
            return sorted(logs, key=lambda x: x.get("timestamp", ""), reverse=True)
        return logs

    def get_log_by_id(self, log_id):
        """Find a specific log entry by its unique log_id."""
        logs = load_json(self.logs_file, default=[])
        for l in logs:
            if l.get("log_id") == log_id:
                return l
        return None

    def filter_logs(self, username=None, ip_address=None, event_type=None, severity=None, search=None):
        """
        Filters logs by criteria for the dashboard Log Explorer.
        """
        logs = self.get_all_logs(reverse=True)
        filtered = []

        for log in logs:
            if username and username.lower() not in (log.get("username") or "").lower():
                continue
            if ip_address and ip_address.lower() not in (log.get("ip_address") or "").lower():
                continue
            if event_type and event_type != "ALL" and log.get("event_type") != event_type:
                continue
            if severity and severity != "ALL" and log.get("severity") != severity:
                continue
            if search:
                query = search.lower()
                matched = (
                    query in (log.get("description") or "").lower() or
                    query in (log.get("endpoint") or "").lower() or
                    query in (log.get("log_id") or "").lower() or
                    query in (log.get("username") or "").lower() or
                    query in (log.get("ip_address") or "").lower()
                )
                if not matched:
                    continue
            filtered.append(log)

        return filtered

# Global logger instance
security_logger = SecurityLogger()
