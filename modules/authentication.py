"""
Authentication Module for SecureChat.
Handles user registration, login credential verification, secure password hashing,
session lifecycle management, route protection decorators, and authentication audit logging.
"""

import re
import uuid
from datetime import datetime, timezone
from functools import wraps
from flask import session, redirect, url_for, flash, request
from werkzeug.security import generate_password_hash, check_password_hash
from config import Config
from modules.storage import load_json, save_json, append_json_item
from modules.logging_system import security_logger

# Validation regular expressions
USERNAME_REGEX = re.compile(r"^[a-zA-Z0-9_]{3,20}$")
EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$")

def get_all_users():
    """Retrieve list of all users from users.json."""
    return load_json(Config.USERS_FILE, default=[])

def get_user_by_id(user_id):
    """Find a user by unique user_id."""
    for user in get_all_users():
        if user.get("user_id") == user_id:
            return user
    return None

def get_user_by_username(username):
    """Find a user by username (case-insensitive)."""
    if not username:
        return None
    username_clean = username.strip().lower()
    for user in get_all_users():
        if user.get("username", "").lower() == username_clean:
            return user
    return None

def get_user_by_email(email):
    """Find a user by email (case-insensitive)."""
    if not email:
        return None
    email_clean = email.strip().lower()
    for user in get_all_users():
        if user.get("email", "").lower() == email_clean:
            return user
    return None

def get_user_by_identifier(identifier):
    """Find user by either username or email."""
    if not identifier:
        return None
    identifier_clean = identifier.strip().lower()
    for user in get_all_users():
        if (user.get("username", "").lower() == identifier_clean or
            user.get("email", "").lower() == identifier_clean):
            return user
    return None

def init_default_admin():
    """
    Ensures default admin account exists in users.json.
    Can be configured via environment variables.
    """
    admin = get_user_by_username(Config.DEFAULT_ADMIN_USERNAME)
    if not admin:
        admin_data = {
            "user_id": f"u-admin-{uuid.uuid4().hex[:6]}",
            "username": Config.DEFAULT_ADMIN_USERNAME,
            "email": Config.DEFAULT_ADMIN_EMAIL,
            "full_name": "System Administrator",
            "password_hash": generate_password_hash(Config.DEFAULT_ADMIN_PASSWORD),
            "role": "admin",
            "bio": "Lead Cybersecurity Auditor & System Administrator",
            "profile_picture": "default_avatar.png",
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True
        }
        append_json_item(Config.USERS_FILE, admin_data)
        security_logger.log_event(
            event_type="PROFILE_CREATED",
            description=f"System initialized default administrator account '{Config.DEFAULT_ADMIN_USERNAME}'",
            username=Config.DEFAULT_ADMIN_USERNAME,
            user_id=admin_data["user_id"],
            severity="LOW"
        )
        return admin_data
    return admin

def register_user(full_name, username, email, password, confirm_password, zodiac_sign=None):
    """
    Validates and registers a new standard user in Cosmic Connect.
    Returns (success_boolean, message_or_user_dict).
    """
    # 1. Input Sanitization
    full_name = (full_name or "").strip()
    username = (username or "").strip()
    email = (email or "").strip().lower()
    zodiac_sign = (zodiac_sign or "").strip() or "✨ Cosmic Seeker"

    # 2. Field Presence
    if not full_name or not username or not email or not password or not confirm_password:
        return False, "All fields are required."

    # 3. Input Validation
    if len(full_name) < 2 or len(full_name) > 60:
        return False, "Full name must be between 2 and 60 characters."

    if not USERNAME_REGEX.match(username):
        return False, "Username must be 3-20 characters long and contain only letters, numbers, and underscores."

    if not EMAIL_REGEX.match(email):
        return False, "Invalid email address format."

    if len(password) < 8:
        return False, "Password must be at least 8 characters long."

    if password != confirm_password:
        return False, "Passwords do not match."

    # 4. Duplicate checks
    if get_user_by_username(username):
        return False, f"Username '{username}' is already taken."

    if get_user_by_email(email):
        return False, f"Email address '{email}' is already registered."

    # 5. Create user record
    new_user = {
        "user_id": f"u-{uuid.uuid4().hex[:10]}",
        "username": username,
        "email": email,
        "full_name": full_name,
        "password_hash": generate_password_hash(password),
        "role": "user",
        "bio": "New stargazing member of Cosmic Connect.",
        "zodiac_sign": zodiac_sign,
        "profile_picture": "default_avatar.png",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "is_active": True
    }

    append_json_item(Config.USERS_FILE, new_user)

    # 6. Audit Logging
    security_logger.log_event(
        event_type="USER_REGISTER",
        description=f"New user registered: '{username}' ({email})",
        username=username,
        user_id=new_user["user_id"],
        status="SUCCESS",
        severity="LOW"
    )

    return True, new_user

def authenticate_user(identifier, password, require_admin=False):
    """
    Verifies user credentials.
    Logs successful or failed login attempts and triggers IDS.
    Returns (user_dict or None, error_message).
    """
    identifier_clean = (identifier or "").strip()
    if not identifier_clean or not password:
        security_logger.log_event(
            event_type="ADMIN_LOGIN_FAILED" if require_admin else "LOGIN_FAILED",
            description=f"Login attempted with missing identifier or password",
            username=identifier_clean or "unknown",
            status="FAILED",
            severity="MEDIUM"
        )
        return None, "Please provide both username/email and password."

    user = get_user_by_identifier(identifier_clean)

    if not user:
        # Invalid username/email
        security_logger.log_event(
            event_type="ADMIN_LOGIN_FAILED" if require_admin else "LOGIN_FAILED",
            description=f"Failed login attempt: non-existent identifier '{identifier_clean}'",
            username=identifier_clean,
            status="FAILED",
            severity="MEDIUM"
        )
        return None, "Invalid credentials."

    if not check_password_hash(user.get("password_hash", ""), password):
        # Invalid password
        security_logger.log_event(
            event_type="ADMIN_LOGIN_FAILED" if require_admin else "LOGIN_FAILED",
            description=f"Failed login attempt: incorrect password for user '{user['username']}'",
            username=user["username"],
            user_id=user["user_id"],
            status="FAILED",
            severity="MEDIUM"
        )
        return None, "Invalid credentials."

    if require_admin and user.get("role") != "admin":
        # Role mismatch
        security_logger.log_event(
            event_type="ADMIN_LOGIN_FAILED",
            description=f"Unauthorized admin access attempt: user '{user['username']}' lacks admin privileges",
            username=user["username"],
            user_id=user["user_id"],
            status="DENIED",
            severity="HIGH"
        )
        return None, "Access denied. Administrator privileges required."

    # Successful login
    event_type = "ADMIN_LOGIN_SUCCESS" if user.get("role") == "admin" else "LOGIN_SUCCESS"
    security_logger.log_event(
        event_type=event_type,
        description=f"User '{user['username']}' authenticated successfully (Role: {user.get('role', 'user')})",
        username=user["username"],
        user_id=user["user_id"],
        status="SUCCESS",
        severity="LOW"
    )

    return user, None

import secrets

def login_user_session(user):
    """Initializes user session variables securely."""
    session.clear()
    session["user_id"] = user["user_id"]
    session["username"] = user["username"]
    session["full_name"] = user["full_name"]
    session["role"] = user.get("role", "user")
    session["logged_in_at"] = datetime.now(timezone.utc).isoformat()
    session["client_ip"] = request.remote_addr or "127.0.0.1"
    session["csrf_token"] = secrets.token_hex(24)

def logout_user_session():
    """Terminates session and records logout event."""
    username = session.get("username", "anonymous")
    user_id = session.get("user_id", "unauthenticated")

    security_logger.log_event(
        event_type="USER_LOGOUT",
        description=f"User '{username}' logged out",
        username=username,
        user_id=user_id,
        status="SUCCESS",
        severity="LOW"
    )
    session.clear()

def login_required(f):
    """Route decorator requiring authenticated user."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            security_logger.log_event(
                event_type="UNAUTHORIZED_ACCESS",
                description=f"Unauthenticated access attempt to protected route '{request.path}'",
                status="DENIED",
                severity="MEDIUM"
            )
            flash("Please log in to access this page.", "warning")
            return redirect(url_for("login", next=request.path))

        # Check session IP match to detect potential session hijacking
        client_ip = request.remote_addr or "127.0.0.1"
        stored_ip = session.get("client_ip")
        if stored_ip and stored_ip != client_ip:
            security_logger.log_event(
                event_type="SESSION_TAMPERING",
                description=f"Session client IP mismatch for user '{session.get('username')}': was {stored_ip}, now {client_ip}",
                status="SUSPICIOUS",
                severity="HIGH"
            )

        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Route decorator requiring administrative role."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or session.get("role") != "admin":
            security_logger.log_event(
                event_type="UNAUTHORIZED_ACCESS",
                description=f"Unauthorized access attempt to admin route '{request.path}' by user '{session.get('username', 'unauthenticated')}'",
                status="DENIED",
                severity="HIGH"
            )
            flash("Administrator access required.", "danger")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated_function
