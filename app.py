"""
SecureChat - Main Flask Application
A private messaging web application integrated with an automated cybersecurity
log monitoring system, rule-based Intrusion Detection System (IDS), and SOC Admin Dashboard.
"""

import os
import json
import secrets
from datetime import datetime, timezone, timedelta
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, session, jsonify, send_file, abort
)
from config import Config
from modules.storage import load_json, save_json
from modules.logging_system import security_logger
from modules.intrusion_detection import ids_engine
from modules.authentication import (
    get_all_users, get_user_by_id, register_user, authenticate_user,
    login_user_session, logout_user_session, login_required, admin_required,
    init_default_admin
)
from modules.profiles import update_user_profile
from modules.chat import (
    get_conversation, get_user_conversations_summary, send_message, search_users
)
from modules.admin import get_dashboard_metrics, get_user_monitoring_stats

# Initialize Flask App
app = Flask(__name__)
app.config.from_object(Config)

# Ensure upload directory exists
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
os.makedirs(app.config["DATA_DIR"], exist_ok=True)

# Initialize administrator account & start Groq AI 5-second analyzer on startup
with app.app_context():
    init_default_admin()
    from modules.groq_detector import groq_analyzer
    groq_analyzer.start_background_analyzer()

# ---------------------------------------------------------------------------
# CSRF and Session Security Handlers
# ---------------------------------------------------------------------------

@app.before_request
def csrf_and_session_defense():
    """
    1. Generates and manages session CSRF tokens.
    2. Validates CSRF tokens on state-modifying requests (POST).
    """
    # Ensure a cryptographically secure CSRF token exists for the session
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(24)

    # Validate CSRF on POST requests
    if request.method == "POST":
        token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
        
        # If request is JSON payload, also check in json body
        if not token and request.is_json:
            token = request.get_json(silent=True, force=False)
            if isinstance(token, dict):
                token = token.get("csrf_token")

        if not token or token != session.get("csrf_token"):
            security_logger.log_event(
                event_type="SUSPICIOUS_ACTIVITY",
                description=f"Potential CSRF attack detected or missing CSRF token on route '{request.path}'",
                status="DENIED",
                severity="HIGH"
            )
            if request.is_json:
                return jsonify({"error": "Invalid or missing CSRF security token."}), 403
            flash("Security check failed: invalid or expired session token. Please try again.", "danger")
            return redirect(request.referrer or url_for("index"))

@app.context_processor
def inject_template_globals():
    """Injects CSRF token, unresolved alerts, AI warnings, and critical reports counts into Jinja2 templates."""
    unresolved_count = len(ids_engine.get_unresolved_alerts()) if session.get("role") == "admin" else 0
    from modules.ai_detector import ai_detector
    from modules.groq_detector import groq_analyzer
    ai_warning_count = len(ai_detector.get_active_ai_warnings()) if session.get("role") == "admin" else 0
    critical_reports_count = len(groq_analyzer.get_all_reports()) if session.get("role") == "admin" else 0
    return {
        "csrf_token": session.get("csrf_token", ""),
        "unresolved_count": unresolved_count,
        "ai_warning_count": ai_warning_count,
        "critical_reports_count": critical_reports_count
    }

@app.after_request
def apply_security_headers(response):
    """Hardens the application with standard cybersecurity response headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# ---------------------------------------------------------------------------
# Error Handlers (Integrated with IDS Reconnaissance Rules)
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def page_not_found(e):
    """
    Catches 404 routes, logs INVALID_URL_REQUEST, and triggers IDS Rule 5
    to detect endpoint scanning / automated directory bruteforce probing.
    """
    security_logger.log_event(
        event_type="INVALID_URL_REQUEST",
        description=f"HTTP 404: Nonexistent endpoint requested: {request.path}",
        status="NOT_FOUND",
        severity="LOW"
    )
    return render_template("base.html", content_override=True), 404

@app.errorhandler(500)
def internal_server_error(e):
    security_logger.log_event(
        event_type="SUSPICIOUS_ACTIVITY",
        description=f"HTTP 500: Internal server error on route {request.path}",
        status="ERROR",
        severity="HIGH"
    )
    return "<h3>Internal Server Error</h3><p>An unexpected condition occurred. The event has been audited.</p>", 500

# ---------------------------------------------------------------------------
# Public & Authentication Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Landing homepage with cybersecurity system overview."""
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    """Handles new user registration with strict validation and password hashing."""
    if "user_id" in session:
        return redirect(url_for("profile"))

    if request.method == "POST":
        full_name = request.form.get("full_name")
        username = request.form.get("username")
        email = request.form.get("email")
        password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")
        zodiac_sign = request.form.get("zodiac_sign")

        success, result = register_user(full_name, username, email, password, confirm_password, zodiac_sign=zodiac_sign)
        if success:
            flash(f"Account registered successfully for @{username}! Please sign in.", "success")
            return redirect(url_for("login"))
        else:
            flash(result, "danger")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Authenticates standard users, initializes sessions, and records audit telemetry."""
    if "user_id" in session:
        return redirect(url_for("profile"))

    if request.method == "POST":
        identifier = request.form.get("identifier")
        password = request.form.get("password")
        next_url = request.args.get("next")

        user, err = authenticate_user(identifier, password, require_admin=False)
        if user:
            login_user_session(user)
            flash(f"Welcome back, {user['full_name']}!", "success")
            if next_url and next_url.startswith("/"):
                return redirect(next_url)
            return redirect(url_for("profile"))
        else:
            flash(err, "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():
    """Clears authenticated session and logs logout activity."""
    logout_user_session()
    flash("You have been securely logged out.", "info")
    return redirect(url_for("login"))

# ---------------------------------------------------------------------------
# User Profile Routes
# ---------------------------------------------------------------------------

@app.route("/profile")
@login_required
def profile():
    """Displays current logged-in user profile details."""
    user = get_user_by_id(session["user_id"])
    if not user:
        flash("User record not found.", "danger")
        return redirect(url_for("logout"))
    return render_template("profile.html", user=user, is_own_profile=True)

@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def edit_profile():
    """Allows user to update profile details and upload new avatar safely."""
    user = get_user_by_id(session["user_id"])
    if not user:
        return redirect(url_for("logout"))

    if request.method == "POST":
        full_name = request.form.get("full_name")
        bio = request.form.get("bio")
        email = request.form.get("email")
        zodiac_sign = request.form.get("zodiac_sign")
        pic_file = request.files.get("profile_pic")

        success, msg = update_user_profile(user["user_id"], full_name, bio, email, pic_file, zodiac_sign=zodiac_sign)
        if success:
            session["full_name"] = full_name
            flash(msg, "success")
            return redirect(url_for("profile"))
        else:
            flash(msg, "danger")

    return render_template("edit_profile.html", user=user)

@app.route("/user/<user_id>")
@login_required
def view_user_profile(user_id):
    """View public profile of another community member."""
    if user_id == session.get("user_id"):
        return redirect(url_for("profile"))

    target_user = get_user_by_id(user_id)
    if not target_user:
        flash("User profile does not exist.", "warning")
        return redirect(url_for("users_discovery"))

    return render_template("profile.html", user=target_user, is_own_profile=False)

# ---------------------------------------------------------------------------
# User Discovery & Private Chat System
# ---------------------------------------------------------------------------

@app.route("/users")
@login_required
def users_discovery():
    """Community member discovery with search filtering."""
    query = request.args.get("q", "")
    discovered = search_users(session["user_id"], query)
    return render_template("users.html", users=discovered, query=query)

@app.route("/chat")
@login_required
def chat_index():
    """Chat hub: shows active conversations or defaults to empty state."""
    conversations = get_user_conversations_summary(session["user_id"])
    if conversations:
        # Redirect to first conversation for convenience
        first_partner = conversations[0]["partner"]
        return redirect(url_for("chat_conversation", partner_id=first_partner["user_id"]))
    return render_template("chat.html", conversations=[], active_partner=None, messages=[])

@app.route("/chat/<partner_id>")
@login_required
def chat_conversation(partner_id):
    """
    Renders private conversation between current user and partner.
    Strictly verifies participant authorization.
    """
    current_uid = session["user_id"]
    if partner_id == current_uid:
        flash("You cannot initiate a private conversation with yourself.", "warning")
        return redirect(url_for("users_discovery"))

    partner = get_user_by_id(partner_id)
    if not partner:
        flash("Recipient user not found.", "danger")
        return redirect(url_for("chat_index"))

    # Fetch conversation and mark messages as read for current user
    messages = get_conversation(current_uid, partner_id, mark_as_read_for_user=current_uid)
    conversations = get_user_conversations_summary(current_uid)

    return render_template(
        "chat.html",
        conversations=conversations,
        active_partner=partner,
        messages=messages
    )

@app.route("/chat/<partner_id>/send", methods=["POST"])
@login_required
def chat_send_message(partner_id):
    """Processes standard form message submissions."""
    current_user = get_user_by_id(session["user_id"])
    partner_user = get_user_by_id(partner_id)

    if not partner_user:
        flash("Invalid message recipient.", "danger")
        return redirect(url_for("chat_index"))

    content = request.form.get("content")
    success, msg_or_err = send_message(current_user, partner_user, content)

    if not success:
        flash(msg_or_err, "danger")

    return redirect(url_for("chat_conversation", partner_id=partner_id))

@app.route("/api/chat/<partner_id>/messages", methods=["GET"])
@login_required
def api_get_messages(partner_id):
    """
    API endpoint for basic polling: returns private messages between
    the authenticated user and the partner.
    """
    current_uid = session["user_id"]
    partner = get_user_by_id(partner_id)
    if not partner:
        return jsonify({"error": "User not found"}), 404

    messages = get_conversation(current_uid, partner_id, mark_as_read_for_user=current_uid)
    return jsonify({"messages": messages, "count": len(messages)})

@app.route("/api/chat/<partner_id>/send", methods=["POST"])
@login_required
def api_send_message(partner_id):
    """AJAX API endpoint for seamless live chat message delivery."""
    current_user = get_user_by_id(session["user_id"])
    partner_user = get_user_by_id(partner_id)

    if not partner_user:
        return jsonify({"error": "Invalid recipient"}), 404

    data = request.get_json(silent=True) or {}
    content = data.get("content") or request.form.get("content")

    success, result = send_message(current_user, partner_user, content)
    if success:
        return jsonify({"status": "success", "message": result})
    else:
        return jsonify({"error": result}), 400

# ---------------------------------------------------------------------------
# Admin Authentication & SOC Dashboard Routes
# ---------------------------------------------------------------------------

@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    """Dedicated cybersecurity administrator authentication portal."""
    if "user_id" in session and session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier")
        password = request.form.get("password")

        admin_user, err = authenticate_user(identifier, password, require_admin=True)
        if admin_user:
            login_user_session(admin_user)
            flash(f"SOC Defense Console unlocked. Welcome, Administrator {admin_user['username']}.", "success")
            return redirect(url_for("admin_dashboard"))
        else:
            flash(err, "danger")

    return render_template("admin/admin_login.html")

@app.route("/admin/logout")
def admin_logout():
    """Logs administrator out and terminates admin session."""
    logout_user_session()
    flash("Administrator session terminated.", "info")
    return redirect(url_for("admin_login"))

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    """Primary cybersecurity SOC telemetry dashboard."""
    metrics = get_dashboard_metrics()
    return render_template("admin/dashboard.html", metrics=metrics, active_tab="dashboard")

@app.route("/admin/logs")
@admin_required
def admin_logs():
    """Live activity log stream with dynamic filtering and search."""
    search = request.args.get("search", "")
    event_type = request.args.get("event_type", "ALL")
    severity = request.args.get("severity", "ALL")

    filtered_logs = security_logger.filter_logs(
        search=search,
        event_type=event_type,
        severity=severity
    )

    return render_template(
        "admin/logs.html",
        logs=filtered_logs,
        search_query=search,
        selected_event=event_type,
        selected_severity=severity,
        active_tab="logs"
    )

@app.route("/admin/log/<log_id>")
@admin_required
def admin_log_details(log_id):
    """Detailed view and JSON inspection for an individual security log event."""
    log = security_logger.get_log_by_id(log_id)
    if not log:
        flash("Log event not found.", "warning")
        return redirect(url_for("admin_logs"))

    raw_json = json.dumps(log, indent=4)
    return render_template("admin/log_details.html", log=log, raw_json=raw_json, active_tab="logs")

@app.route("/admin/alerts")
@admin_required
def admin_alerts():
    """Intrusion Detection System alerts list with status filters."""
    status_filter = request.args.get("status", "ALL")
    severity_filter = request.args.get("severity", "ALL")

    all_alerts = ids_engine.get_all_alerts()
    filtered = []
    for a in all_alerts:
        if status_filter != "ALL" and a.get("status") != status_filter:
            continue
        if severity_filter != "ALL" and a.get("severity") != severity_filter:
            continue
        filtered.append(a)

    return render_template(
        "admin/alerts.html",
        alerts=filtered,
        selected_status=status_filter,
        selected_severity=severity_filter,
        active_tab="alerts"
    )

@app.route("/admin/alerts/<alert_id>/resolve", methods=["POST"])
@admin_required
def admin_resolve_alert(alert_id):
    """Marks an unresolved alert as RESOLVED by the administrator."""
    admin_name = session.get("username", "admin")
    if ids_engine.resolve_alert(alert_id, resolved_by=admin_name):
        security_logger.log_event(
            event_type="SUSPICIOUS_ACTIVITY",
            description=f"Security alert '{alert_id}' marked as RESOLVED by administrator '{admin_name}'",
            status="RESOLVED",
            severity="LOW",
            trigger_ids=False
        )
        flash(f"Alert {alert_id} marked as RESOLVED.", "success")
    else:
        flash(f"Failed to resolve alert {alert_id}.", "danger")

    return redirect(request.referrer or url_for("admin_alerts"))

@app.route("/admin/users")
@admin_required
def admin_users():
    """User security auditing and activity footprint monitoring."""
    user_stats = get_user_monitoring_stats()
    return render_template("admin/users.html", users=user_stats, active_tab="users")

@app.route("/admin/logs_viewer")
@admin_required
def admin_json_viewer():
    """Direct visual inspector for the raw security_logs.json file."""
    logs_data = load_json(Config.LOGS_FILE, default=[])
    formatted_json = json.dumps(logs_data, indent=4)
    file_size_kb = round(len(formatted_json.encode("utf-8")) / 1024, 2)

    return render_template(
        "admin/json_viewer.html",
        raw_json_data=formatted_json,
        file_size_kb=file_size_kb,
        record_count=len(logs_data),
        active_tab="json_viewer"
    )

@app.route("/admin/export_logs")
@admin_required
def admin_export_logs():
    """Exports security_logs.json file for offline incident analysis."""
    if not os.path.exists(Config.LOGS_FILE):
        save_json(Config.LOGS_FILE, [])
    return send_file(
        Config.LOGS_FILE,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"security_logs_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    )

@app.route("/admin/export_alerts")
@admin_required
def admin_export_alerts():
    """Exports security_alerts.json file for offline incident analysis."""
    if not os.path.exists(Config.ALERTS_FILE):
        save_json(Config.ALERTS_FILE, [])
    return send_file(
        Config.ALERTS_FILE,
        mimetype="application/json",
        as_attachment=True,
        download_name=f"security_alerts_export_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    )

@app.route("/admin/simulator")
@admin_required
def admin_simulator():
    """Interactive control panel to test and demonstrate IDS detection rules."""
    return render_template("admin/simulator.html", active_tab="simulator")

@app.route("/admin/simulator/trigger", methods=["POST"])
@admin_required
def admin_trigger_simulation():
    """Executes safe simulated attack vectors to demonstrate real-time IDS alerting."""
    scenario = request.form.get("scenario")

    if scenario == "brute_force":
        # Simulate 5 failed login attempts
        test_ip = "198.51.100.22"
        for i in range(5):
            security_logger.log_event(
                event_type="LOGIN_FAILED",
                description=f"Simulated failed login attempt {i+1}/5 for target 'alice'",
                username="alice",
                user_id="unauthenticated",
                ip_address=test_ip,
                endpoint="/login",
                http_method="POST",
                status="FAILED",
                severity="MEDIUM"
            )
        flash("Simulated 5 failed login attempts from 198.51.100.22. Brute-Force HIGH alert generated!", "success")

    elif scenario == "login_burst":
        # Simulate 10 rapid login attempts
        test_ip = "203.0.113.88"
        for i in range(10):
            security_logger.log_event(
                event_type="LOGIN_FAILED" if i % 2 == 0 else "LOGIN_SUCCESS",
                description=f"Simulated rapid login burst attempt {i+1}/10",
                username="bob",
                user_id="u-user-002",
                ip_address=test_ip,
                endpoint="/login",
                http_method="POST",
                status="FAILED" if i % 2 == 0 else "SUCCESS",
                severity="LOW"
            )
        flash("Simulated 10 rapid logins from 203.0.113.88. Suspicious Login Burst alert generated!", "success")

    elif scenario == "unauth_admin":
        # Simulate unauthorized admin probe
        test_ip = "198.51.100.99"
        security_logger.log_event(
            event_type="UNAUTHORIZED_ACCESS",
            description="Simulated unauthenticated access probe against /admin/system_config",
            username="anonymous",
            user_id="unauthenticated",
            ip_address=test_ip,
            endpoint="/admin/system_config",
            http_method="GET",
            status="DENIED",
            severity="HIGH"
        )
        flash("Simulated unauthorized admin route access probe. High severity alert generated!", "success")

    elif scenario == "abnormal_messages":
        # Simulate 16 rapid messages
        test_user = get_user_by_id(session["user_id"])
        test_ip = request.remote_addr or "127.0.0.1"
        for i in range(16):
            security_logger.log_event(
                event_type="MESSAGE_SENT",
                description=f"Simulated rapid messaging velocity {i+1}/16 (Length: 20 chars)",
                username=test_user["username"],
                user_id=test_user["user_id"],
                ip_address=test_ip,
                endpoint="/chat/send",
                http_method="POST",
                status="SUCCESS",
                severity="LOW"
            )
        flash("Simulated abnormal message velocity (16 messages/min). Automated spam bot alert generated!", "success")

    elif scenario == "endpoint_scan":
        # Simulate 5 404 scanning requests
        test_ip = "198.51.100.55"
        probed_paths = ["/wp-admin", "/.env", "/phpmyadmin", "/config.json", "/api/v1/debug"]
        for path in probed_paths:
            security_logger.log_event(
                event_type="INVALID_URL_REQUEST",
                description=f"Simulated 404 scan probe: {path}",
                username="scanner",
                user_id="unauthenticated",
                ip_address=test_ip,
                endpoint=path,
                http_method="GET",
                status="NOT_FOUND",
                severity="LOW"
            )
        flash("Simulated 5 vulnerability scan 404 requests from 198.51.100.55. Endpoint scanning alert generated!", "success")

    elif scenario == "session_anomaly":
        # Simulate session tampering
        test_ip = "192.0.2.77"
        security_logger.log_event(
            event_type="SESSION_TAMPERING",
            description=f"Simulated session hijack attempt: client IP changed abruptly to {test_ip}",
            username=session.get("username", "admin"),
            user_id=session.get("user_id", "admin"),
            ip_address=test_ip,
            endpoint="/chat",
            http_method="GET",
            status="SUSPICIOUS",
            severity="HIGH"
        )
        flash("Simulated session security tampering alert generated!", "success")

    elif scenario == "ai_unauth_request":
        # Simulate unauthorized request targeting admin route to trigger AI anomaly detection
        test_ip = "198.51.100.111"
        security_logger.log_event(
            event_type="UNAUTHORIZED_ACCESS",
            description="Malicious unauthenticated penetration probe against /admin/api/keys without authorization",
            username="anonymous",
            user_id="unauthenticated",
            ip_address=test_ip,
            endpoint="/admin/api/keys",
            http_method="POST",
            status="DENIED",
            severity="HIGH"
        )
        flash("Simulated unauthorized request. AI Engine flagged anomaly and dispatched a WARNING to the Admin Dashboard!", "success")

    elif scenario == "ai_unusual_logins":
        # Simulate unusual volume of login attempts in rapid succession
        test_ip = "203.0.113.199"
        for i in range(8):
            security_logger.log_event(
                event_type="LOGIN_FAILED",
                description=f"Automated credential stuffing probe attempt {i+1}/8",
                username=f"victim_account_{i%2}",
                user_id="unauthenticated",
                ip_address=test_ip,
                endpoint="/login",
                http_method="POST",
                status="FAILED",
                severity="MEDIUM"
            )
        flash("Simulated unusual login volume (8 rapid attempts from 203.0.113.199). AI Engine dispatched an UNUSUAL LOGIN WARNING to the Admin Dashboard!", "success")

    else:
        flash("Unknown simulation scenario.", "warning")

    return redirect(url_for("admin_dashboard"))

@app.route("/admin/ai_analysis")
@admin_required
def admin_ai_analysis():
    """AI Machine Learning Anomaly Detection console and log scoring inspector."""
    from modules.ai_detector import ai_detector
    all_logs = security_logger.get_all_logs(reverse=True)
    scored_logs = []
    for log in all_logs[:40]:
        score_info = ai_detector.score_log(log, all_logs)
        scored_logs.append({
            "log": log,
            "analysis": score_info
        })

    active_warnings = ai_detector.get_active_ai_warnings()
    all_ai_warnings = ai_detector.get_recent_ai_warnings()

    return render_template(
        "admin/ai_analysis.html",
        scored_logs=scored_logs,
        active_warnings=active_warnings,
        all_ai_warnings=all_ai_warnings,
        is_trained=ai_detector.is_trained,
        last_trained_at=ai_detector.last_trained_at,
        active_tab="ai_analysis"
    )

@app.route("/admin/ai_retrain", methods=["POST"])
@admin_required
def admin_ai_retrain():
    """Retrains the Machine Learning Isolation Forest model on current traffic baseline."""
    from modules.ai_detector import ai_detector
    ai_detector.train_baseline()
    flash("AI Isolation Forest Anomaly Detection model retrained successfully on latest baseline.", "success")
    return redirect(url_for("admin_ai_analysis"))

# ---------------------------------------------------------------------------
# Groq AI Critical Incident Reports Routes
# ---------------------------------------------------------------------------

@app.route("/admin/reports")
@admin_required
def admin_reports():
    """Displays list of all forensic Incident Investigation Reports generated by Groq AI for CRITICAL threats."""
    from modules.groq_detector import groq_analyzer
    reports = groq_analyzer.get_all_reports()
    return render_template("admin/reports.html", reports=reports, active_tab="reports")

@app.route("/admin/reports/<report_id>")
@admin_required
def admin_report_details(report_id):
    """Detailed forensic view of a specific Critical Incident Report."""
    from modules.groq_detector import groq_analyzer
    report = groq_analyzer.get_report_by_id(report_id)
    if not report:
        flash(f"Incident report '{report_id}' not found.", "warning")
        return redirect(url_for("admin_reports"))
    return render_template("admin/report_details.html", report=report, active_tab="reports")

@app.route("/admin/reports/<report_id>/export")
@admin_required
def admin_report_export(report_id):
    """Exports an incident investigation report as a downloadable JSON file."""
    from modules.groq_detector import groq_analyzer
    report = groq_analyzer.get_report_by_id(report_id)
    if not report:
        flash("Report not found.", "warning")
        return redirect(url_for("admin_reports"))

    response = app.response_class(
        response=json.dumps(report, indent=4),
        status=200,
        mimetype="application/json"
    )
    response.headers["Content-Disposition"] = f"attachment; filename={report_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
    return response

@app.route("/admin/groq_scan_now", methods=["POST"])
@admin_required
def admin_groq_scan_now():
    """Immediately triggers a Groq AI log batch analysis without waiting for the 5s timer."""
    from modules.groq_detector import groq_analyzer
    diagnosis = groq_analyzer.analyze_recent_batch()
    if diagnosis:
        if diagnosis.get("attack_detected"):
            flash(f"Groq AI Alert: {diagnosis.get('attack_type')} detected! ({diagnosis.get('summary')})", "danger")
        else:
            flash("Groq AI Scan Complete: No malicious activity detected in recent log batch.", "success")
    else:
        flash("Groq AI Scan Complete: No new unprocessed logs in the current batch window.", "info")
    return redirect(request.referrer or url_for("admin_dashboard"))

# ---------------------------------------------------------------------------
# Application Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("\n" + "="*70)
    print("🌌  Cosmic Connect – Astrological Messenger & Observatory SOC Online")
    print("="*70)
    print("🪐 Cosmic Chat Website:  http://127.0.0.1:5000/")
    print("🔭 Observatory SOC:     http://127.0.0.1:5000/admin/login")
    print("👤 Admin Credentials:   admin / Admin@SecureChat2026!")
    print("👥 Stargazer Accounts:  alice / Password123!  |  bob / Password123!")
    print("="*70 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=True)
