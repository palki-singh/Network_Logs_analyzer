"""
SecureChat Configuration
Defines application settings, file paths, security parameters, and intrusion detection thresholds.
"""

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent

class Config:
    # Flask Secret Key for session signing
    SECRET_KEY = os.environ.get("SECRET_KEY", "securechat-super-secret-cybersecurity-key-2026-xyz!")

    # Base directories
    DATA_DIR = os.path.join(BASE_DIR, "data")
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")

    # Data files
    USERS_FILE = os.path.join(DATA_DIR, "users.json")
    CHATS_FILE = os.path.join(DATA_DIR, "chats.json")
    LOGS_FILE = os.path.join(DATA_DIR, "security_logs.json")
    ALERTS_FILE = os.path.join(DATA_DIR, "security_alerts.json")
    CRITICAL_REPORTS_FILE = os.path.join(DATA_DIR, "critical_reports.json")

    # Groq AI Configuration
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "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")
    GROQ_MODEL = os.environ.get("GROQ_MODEL", "qwen/qwen3.8-27b")
    GROQ_FALLBACK_MODEL = "openai/gpt-oss-20b"
    AI_BATCH_INTERVAL_SECONDS = 5  # Analyze new log batches every 5 seconds

    # Upload restrictions
    MAX_CONTENT_LENGTH = 2 * 1024 * 1024  # 2 MB max file size
    ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

    # Cookie & Session Security
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = False  # Set to True in HTTPS production environments

    # Intrusion Detection Rule Thresholds
    # Rule 1: Brute-Force Login Detection
    BRUTE_FORCE_THRESHOLD = 5          # 5 failed attempts
    BRUTE_FORCE_WINDOW_SECONDS = 300    # within 5 minutes

    # Rule 2: Suspicious / Frequent Login Activity
    FREQUENT_LOGIN_THRESHOLD = 10       # 10 login attempts
    FREQUENT_LOGIN_WINDOW_SECONDS = 120  # within 2 minutes

    # Rule 3: Unauthorized Access Threshold
    UNAUTHORIZED_ACCESS_THRESHOLD = 3   # 3 attempts
    UNAUTHORIZED_ACCESS_WINDOW_SECONDS = 300

    # Rule 4: Abnormal Message Frequency
    ABNORMAL_MESSAGE_THRESHOLD = 15     # 15 messages
    ABNORMAL_MESSAGE_WINDOW_SECONDS = 60 # within 1 minute

    # Rule 5: Invalid Endpoint / 404 Scanning
    INVALID_ENDPOINT_THRESHOLD = 5      # 5 404 requests
    INVALID_ENDPOINT_WINDOW_SECONDS = 180 # within 3 minutes

    # Default Administrator Configuration
    DEFAULT_ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    DEFAULT_ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@securechat.local")
    DEFAULT_ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@SecureChat2026!")
