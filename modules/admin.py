"""
Admin Cybersecurity Dashboard Module for SecureChat.
Provides telemetry, log exploration, intrusion alert triage, user activity auditing,
and JSON data export capabilities for cybersecurity administrators.
"""

from datetime import datetime, timezone
from config import Config
from modules.storage import load_json
from modules.logging_system import security_logger
from modules.intrusion_detection import ids_engine
from modules.authentication import get_all_users

def get_dashboard_metrics():
    """
    Computes real-time cybersecurity metrics from JSON storage.
    """
    users = get_all_users()
    logs = security_logger.get_all_logs()
    alerts = ids_engine.get_all_alerts()
    chats = load_json(Config.CHATS_FILE, default=[])

    total_users = len(users)
    total_logs = len(logs)
    total_messages = len(chats)

    successful_logins = sum(1 for l in logs if l.get("event_type") in ("LOGIN_SUCCESS", "ADMIN_LOGIN_SUCCESS"))
    failed_logins = sum(1 for l in logs if l.get("event_type") in ("LOGIN_FAILED", "ADMIN_LOGIN_FAILED"))
    total_login_attempts = successful_logins + failed_logins

    suspicious_activities = sum(1 for l in logs if l.get("event_type") == "SUSPICIOUS_ACTIVITY" or l.get("severity") in ("HIGH", "CRITICAL"))
    unresolved_alerts = sum(1 for a in alerts if a.get("status") == "UNRESOLVED")

    # Severity distribution
    severity_counts = {
        "LOW": sum(1 for l in logs if l.get("severity") == "LOW"),
        "MEDIUM": sum(1 for l in logs if l.get("severity") == "MEDIUM"),
        "HIGH": sum(1 for l in logs if l.get("severity") == "HIGH"),
        "CRITICAL": sum(1 for l in logs if l.get("severity") == "CRITICAL"),
    }

    alert_severity_counts = {
        "LOW": sum(1 for a in alerts if a.get("severity") == "LOW"),
        "MEDIUM": sum(1 for a in alerts if a.get("severity") == "MEDIUM"),
        "HIGH": sum(1 for a in alerts if a.get("severity") == "HIGH"),
        "CRITICAL": sum(1 for a in alerts if a.get("severity") == "CRITICAL"),
    }

    # AI Anomaly Detection metrics
    from modules.ai_detector import ai_detector
    active_ai_warnings = ai_detector.get_active_ai_warnings()
    all_ai_warnings = ai_detector.get_recent_ai_warnings(limit=10)

    ai_telemetry = {
        "model_name": "IsolationForest (scikit-learn) + Feature Ensemble",
        "status": "ONLINE",
        "is_trained": ai_detector.is_trained,
        "last_trained_at": ai_detector.last_trained_at,
        "active_warning_count": len(active_ai_warnings),
        "total_ai_alerts": len(all_ai_warnings),
        "active_warnings": active_ai_warnings,
        "recent_ai_warnings": all_ai_warnings
    }

    return {
        "total_users": total_users,
        "total_logs": total_logs,
        "total_messages": total_messages,
        "total_login_attempts": total_login_attempts,
        "successful_logins": successful_logins,
        "failed_logins": failed_logins,
        "suspicious_activities": suspicious_activities,
        "unresolved_alerts": unresolved_alerts,
        "severity_counts": severity_counts,
        "alert_severity_counts": alert_severity_counts,
        "recent_logs": logs[:10],
        "recent_alerts": alerts[:8],
        "ai_telemetry": ai_telemetry
    }

def get_user_monitoring_stats():
    """
    Computes per-user security telemetry:
    total logins, failed logins, total messages sent, and last observed IP & timestamp.
    """
    users = get_all_users()
    logs = security_logger.get_all_logs()
    chats = load_json(Config.CHATS_FILE, default=[])

    user_stats = []

    for u in users:
        u_id = u.get("user_id")
        u_name = u.get("username")

        u_logs = [l for l in logs if l.get("user_id") == u_id or l.get("username") == u_name]
        successful_logins = sum(1 for l in u_logs if l.get("event_type") in ("LOGIN_SUCCESS", "ADMIN_LOGIN_SUCCESS"))
        failed_logins = sum(1 for l in u_logs if l.get("event_type") in ("LOGIN_FAILED", "ADMIN_LOGIN_FAILED"))
        messages_sent = sum(1 for m in chats if m.get("sender_id") == u_id)

        last_log = u_logs[0] if u_logs else None
        last_seen = last_log.get("timestamp") if last_log else u.get("created_at")
        last_ip = last_log.get("ip_address") if last_log else "N/A"

        user_stats.append({
            "user_id": u_id,
            "username": u_name,
            "full_name": u.get("full_name"),
            "email": u.get("email"),
            "role": u.get("role", "user"),
            "created_at": u.get("created_at"),
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "messages_sent": messages_sent,
            "last_seen": last_seen,
            "last_ip": last_ip,
            "is_active": u.get("is_active", True)
        })

    return user_stats
