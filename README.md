# Cosmic Connect 🌌✨
### Universe & Astrology Chatting Website with Cybersecurity Log Monitoring & Intrusion Detection Dashboard

**Cosmic Connect** is a full-featured, universe- and astrology-themed private chatting website built with Python, Flask, HTML5, and CSS3. Users explore constellations, showcase their Zodiac signs (Aries through Pisces), find cosmic seekers, and exchange 1-on-1 private transmissions with a deep space aesthetic.

Beneath its celestial exterior operates an automated cybersecurity logging system, a rule-based Intrusion Detection System (IDS), and a dedicated Observatory SOC (Security Operations Center) cybersecurity dashboard that audits all user actions, preserves message privacy, flags anomalous behaviors in real time, and persists all records into structured local JSON files.

---

## 1. Technology Stack & Design Restrictions

This project strictly adheres to the requested technology constraints:

- **Backend**: Python 3.13+, Flask Framework, Flask secure sessions, Werkzeug password hashing.
- **Frontend**: HTML5, CSS3, Jinja2 templates, vanilla JavaScript (used strictly for optional chat auto-refresh polling without third-party frameworks).
- **Data Storage**: Local, thread-safe, atomic JSON files (`users.json`, `chats.json`, `security_logs.json`, `security_alerts.json`).
- **Forbidden Technologies Excluded**: No React, Angular, Vue, Node.js, PHP, JS frameworks, MySQL, MongoDB, SQLite, or non-Flask backends.

---

## 2. Project Folder Structure

```
SecureChat/
│
├── app.py                      # Main Flask application and routing
├── config.py                   # Application settings and IDS rule thresholds
├── requirements.txt            # Python dependencies (Flask, Werkzeug, python-dotenv)
├── test_app.py                 # Automated test suite covering all modules
├── README.md                   # Comprehensive system documentation
│
├── modules/
│   ├── __init__.py             # Python package marker
│   ├── authentication.py       # Registration, login, password hashing, session decorators
│   ├── profiles.py             # Profile viewing, updates, and secure avatar upload
│   ├── chat.py                 # Private messaging, conversation threading, unread counter
│   ├── logging_system.py       # Thread-safe JSON logger with privacy safeguards
│   ├── intrusion_detection.py  # Rule-based Intrusion Detection System (IDS)
│   ├── storage.py              # Atomic JSON read/write handlers with Windows locking defense
│   └── admin.py                # SOC metrics, log analytics, user monitoring telemetry
│
├── data/
│   ├── users.json              # Registered user accounts and password hashes
│   ├── chats.json              # Private messages and conversation timestamps
│   ├── security_logs.json      # Structured security activity logs
│   └── security_alerts.json    # Detected intrusion and anomaly alerts
│
├── templates/
│   ├── base.html               # Main website layout, navigation bar, and alerts
│   ├── index.html              # Landing page with system architecture overview
│   ├── register.html           # User registration form with input validation
│   ├── login.html              # User login form with session authentication
│   ├── profile.html            # Profile card view with account metrics
│   ├── edit_profile.html       # Profile modification and avatar upload form
│   ├── users.html              # User discovery directory with search filtering
│   ├── chat.html               # Private chat interface with message bubbles & polling
│   │
│   └── admin/
│       ├── base_admin.html     # Dark cybersecurity SOC layout with sidebar
│       ├── admin_login.html    # Dedicated administrator authentication portal
│       ├── dashboard.html      # Overview telemetry, metric cards, severity breakdown
│       ├── logs.html           # Live Activity Log stream with filters and search
│       ├── alerts.html         # Intrusion alerts table with triage resolution actions
│       ├── users.html          # User identity and security footprint monitoring
│       ├── log_details.html    # Single event inspector with parsed attributes and raw JSON
│       ├── json_viewer.html    # Direct interactive inspector for security_logs.json
│       └── simulator.html      # Threat simulator to safely trigger IDS rules for testing
│
└── static/
    ├── css/
    │   ├── style.css           # Modern, responsive design for chatting website
    │   ├── chat.css            # Split-screen messaging layout with bubble styling
    │   └── dashboard.css       # Dark cybersecurity SOC aesthetic with neon badges
    │
    ├── images/
    │   └── default_avatar.png  # Default user profile avatar
    └── uploads/
        └── default_avatar.png  # Uploaded avatar storage directory
```

---

## 3. Installation & Setup Instructions

### Prerequisites
- Python 3.10, 3.11, 3.12, or 3.13 installed.
- `pip` package manager.

### Step 1: Install Dependencies
Open your command terminal in the project directory (`d:\cybersecurity_project`) and run:

```bash
pip install -r requirements.txt
```

### Step 2: Start the SecureChat Server
Run the single start command:

```bash
python app.py
```

The server will start on port 5000:
- **Chatting Website URL**: `http://127.0.0.1:5000/`
- **Admin SOC Portal URL**: `http://127.0.0.1:5000/admin/login`

---

## 4. Default Test Credentials

For quick evaluation and testing, the application comes pre-configured with the following accounts:

| Portal | Role | Username / Identifier | Password | Notes & Astrological Sign |
|---|---|---|---|---|
| **Observatory SOC Portal** | Administrator | `admin` | `Admin@SecureChat2026!` | ♑ Capricorn &bull; Accesses Observatory SOC & IDS Alerts |
| **Cosmic Connect** | Stargazer 1 | `alice` | `Password123!` | ♏ Scorpio &bull; Active chat history with Bob |
| **Cosmic Connect** | Stargazer 2 | `bob` | `Password123!` | ♒ Aquarius &bull; Conversation partner of Alice |
| **Cosmic Connect** | Stargazer 3 | `charlie` | `Password123!` | ♐ Sagittarius &bull; Community directory member |

*You can also register any number of new users directly through `/register`.*

---

## 5. Cybersecurity Logging Module

The logging module (`modules/logging_system.py`) automatically captures every security-relevant event across the application and persists it directly into `data/security_logs.json`.

### Strict Privacy Guarantee
In accordance with security best practices:
- **Never Logged**: Passwords, plaintext credentials, session cookie IDs, and private chat text.
- **Message Auditing**: For message events, only metadata is recorded (e.g., sender, recipient, and message character count).

### JSON Log Structure
Each log entry conforms strictly to the schema:
```json
{
    "log_id": "log-7b686d6349c2",
    "timestamp": "2026-11-16T12:35:10.123456+00:00",
    "username": "alice",
    "user_id": "u-user-001",
    "event_type": "MESSAGE_SENT",
    "ip_address": "127.0.0.1",
    "endpoint": "/chat/u-user-002/send",
    "http_method": "POST",
    "status": "SUCCESS",
    "severity": "LOW",
    "description": "User 'alice' sent private message to 'bob' (Length: 78 chars)"
}
```

### Monitored Event Types
1. `USER_REGISTER` – User account creation.
2. `LOGIN_SUCCESS` – Successful user authentication.
3. `LOGIN_FAILED` – Failed user authentication.
4. `USER_LOGOUT` – User session termination.
5. `PROFILE_CREATED` – Initial profile initialization.
6. `PROFILE_UPDATED` – User profile modifications.
7. `PROFILE_PICTURE_UPLOAD` – Avatar image uploaded and validated.
8. `MESSAGE_SENT` – Private message sent (metadata only).
9. `UNAUTHORIZED_ACCESS` – Attempted access to protected pages without valid auth/role.
10. `INVALID_URL_REQUEST` – HTTP 404 nonexistent route request.
11. `SUSPICIOUS_ACTIVITY` – CSRF anomalies, rate threshold violations, or IDS triggers.
12. `SESSION_TAMPERING` – Session IP mismatch or tampering attempt.
13. `ADMIN_LOGIN_SUCCESS` – Successful administrator authentication.
14. `ADMIN_LOGIN_FAILED` – Failed administrator authentication.

---

## 6. Rule-Based Intrusion Detection System (IDS)

The IDS engine (`modules/intrusion_detection.py`) continuously evaluates incoming events against historical logs in sliding time windows to detect malicious patterns:

| Rule Name | Detection Criteria | Severity | Resulting Alert Type |
|---|---|---|---|
| **Rule 1: Brute-Force Login Detection** | ≥ 5 failed login attempts (`LOGIN_FAILED`) from the same IP or target user within 5 minutes. | **HIGH** | `BRUTE_FORCE` |
| **Rule 2: Suspicious Login Burst** | ≥ 10 login attempts within 2 minutes from the same IP address. | **MEDIUM** | `SUSPICIOUS_LOGIN_BURST` |
| **Rule 3: Unauthorized Admin Access** | Any unauthenticated or unauthorized attempt to access an administrative endpoint (`/admin/*`). | **HIGH** | `UNAUTHORIZED_ADMIN_ACCESS` |
| **Rule 4: Abnormal Message Velocity** | ≥ 15 messages sent by a single user within 60 seconds (spam / bot detection). | **HIGH** | `ABNORMAL_MESSAGE_ACTIVITY` |
| **Rule 5: Endpoint Reconnaissance Scan** | ≥ 5 requests to nonexistent endpoints (`INVALID_URL_REQUEST` 404s) from the same IP within 3 minutes. | **MEDIUM** | `ENDPOINT_SCANNING` |
| **Rule 6: Session Security Violation** | Detected divergence between stored session IP and client request IP, or session token tampering. | **HIGH** | `SESSION_SECURITY_VIOLATION` |

### Alert Storage
All alerts are persisted in `data/security_alerts.json` conforming to:
```json
{
    "alert_id": "alert-9a1b2c3d4e",
    "timestamp": "2026-11-16T12:52:45.000000+00:00",
    "alert_type": "BRUTE_FORCE",
    "source_ip": "198.51.100.22",
    "severity": "HIGH",
    "description": "Brute-force login attack detected: 5 failed login attempts from IP 198.51.100.22 within 5 minutes (Target username: alice).",
    "status": "UNRESOLVED"
}
```

---

## 7. AI Log Anomaly Detection System (Machine Learning)

In addition to traditional static detection rules, Cosmic Connect features an integrated **Machine Learning Anomaly Detection Engine** (`modules/ai_detector.py`):

### Core Architecture & Technologies:
- **ML Model**: **Isolation Forest** (`scikit-learn` with 100 ensemble decision trees) + statistical feature scoring.
- **10-Dimensional Behavioral Feature Space**:
  1. `endpoint_risk` – Risk weighting (admin/api/probes vs. public content)
  2. `method_code` – Encoded HTTP method
  3. `status_code` – Execution outcome (SUCCESS, FAILED, DENIED, ALERT)
  4. `severity_weight` – Threat level impact
  5. `ip_login_freq_3m` – Login attempt frequency within sliding 3-minute windows
  6. `ip_unauth_count_5m` – Unauthorized access count within 5-minute windows
  7. `ip_failed_login_ratio` – Failure proportion of credential attempts
  8. `time_hour_sin` / `time_hour_cos` – Periodic cyclical time-of-day features
  9. `request_velocity_1m` – Temporal request velocity per minute

### Targeted AI Threat Warning Triggers:
1. **Unauthorized Requests**: When unauthenticated or unauthorized users probe sensitive administrative endpoints (`/admin/*`) or attempt token bypass, the AI model computes an anomaly confidence > 85% and immediately dispatches an **`AI_UNAUTHORIZED_REQUEST_ANOMALY` Critical Warning** directly onto the Admin Dashboard banner.
2. **Unusual Amounts of Logins**: Analyzes the velocity and failure ratio of login attempts. If unusual bursts or rapid login volume exceeds baseline norms, the AI engine flags an **`AI_UNUSUAL_LOGIN_VOLUME` High Warning Alert**.

### Admin Dashboard AI Warning Display:
- **Top Warning Banner**: A prominent alert banner appears in the Admin Dashboard (`/admin/dashboard`) highlighting the active anomaly, source IP, confidence score, and one-click resolution.
- **AI Threat Scanner Console (`/admin/ai_analysis`)**: Displays live anomaly confidence percentages (0% - 100%) for recent requests with feature breakdowns and an option to retrain the ML baseline.

---

## 8. Admin Cybersecurity SOC Dashboard

The SOC dashboard (`/admin/dashboard`) provides a command center for security personnel:

### Key Sections:
1. **Overview**:
   - Total Registered Users, Total Login Attempts, Successful Logins, Failed Logins.
   - Total Messages Sent, Total Security Events, Total Suspicious Activities, Total Unresolved Alerts.
   - Severity Distribution Indicators (**LOW** = Green, **MEDIUM** = Amber, **HIGH** = Red, **CRITICAL** = Crimson).
   - Real-time preview of recent alerts and audit logs.
2. **Live Activity Logs (`/admin/logs`)**:
   - Filter logs by Event Type (e.g. `LOGIN_FAILED`, `MESSAGE_SENT`).
   - Filter logs by Severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - Keyword search across usernames, IP addresses, endpoints, and log descriptions.
   - Direct link to inspect individual log attributes and copy formatted JSON.
3. **Security Alerts (`/admin/alerts`)**:
   - Lists all IDS incidents with severity badges.
   - One-click **"Resolve"** button to triage and mark alerts as `RESOLVED` with administrator username and timestamp.
4. **User Monitoring (`/admin/users`)**:
   - Inspect user accounts, registration dates, login counts, failed login counts, message counts, last seen timestamps, and last known IP addresses.
5. **JSON Log Viewer (`/admin/logs_viewer`)**:
   - In-browser visual inspection of the raw `data/security_logs.json` file.
   - One-click button to download `security_logs.json` or `security_alerts.json`.
6. **Attack Simulator (`/admin/simulator`)**:
   - Control panel allowing administrators to safely simulate each attack vector (Brute Force, 404 Scanning, Unauthorized Admin Access, Spam Velocity, Session Tampering) and observe the alerts generate in real time.

---

## 8. Step-by-Step Testing & Verification Guide

### Test 1: Register and Log In
1. Navigate to `http://127.0.0.1:5000/register`.
2. Fill in Full Name, Username, Email, Password (`min 8 chars`), and Confirm Password.
3. Submit the form. Notice the success message and redirect to `/login`.
4. Check `data/security_logs.json`: observe the `USER_REGISTER` log entry.
5. Log in with the new credentials. Notice the `LOGIN_SUCCESS` event recorded in `security_logs.json`.

### Test 2: Test Private Messaging
1. Log in as `alice` (`Password123!`).
2. Go to **"Find Users"** (`/users`) and click **"Chat"** on user `bob`.
3. Type a message: `"Testing end-to-end private messaging"` and press Send.
4. Verify the message appears with a timestamp and sent checkmark.
5. Inspect `data/security_logs.json`: verify that the `MESSAGE_SENT` event was recorded with the recipient name and character count, but the message text itself is **NOT** present in the log.

### Test 3: Trigger Detection Rule 1 (Brute-Force Logins)
1. Navigate to `http://127.0.0.1:5000/login`.
2. Enter username `alice` and an incorrect password `WrongPassword!`.
3. Submit the login form 5 consecutive times.
4. Navigate to the Admin SOC portal at `http://127.0.0.1:5000/admin/login` and sign in (`admin` / `Admin@SecureChat2026!`).
5. Go to **"Security Alerts"** (`/admin/alerts`):
   - Notice the **HIGH** severity alert: `BRUTE_FORCE` generated automatically!

### Test 4: Trigger Detection Rule 5 (404 Reconnaissance Probing)
1. In your browser or terminal, enter 5 nonexistent URLs rapidly:
   - `http://127.0.0.1:5000/wp-admin`
   - `http://127.0.0.1:5000/.env`
   - `http://127.0.0.1:5000/phpmyadmin`
   - `http://127.0.0.1:5000/config.json`
   - `http://127.0.0.1:5000/api/v1/debug`
2. Open the Admin SOC Alerts page (`/admin/alerts`):
   - Notice the **MEDIUM** severity alert: `ENDPOINT_SCANNING` generated automatically!

### Test 5: Run Automated Unit Tests
The project includes an automated test suite (`test_app.py`) verifying all functional workflows:
```bash
python test_app.py
```
Expected output:
```
Ran 7 tests in 2.550s

OK
✓ Landing page loads successfully
✓ User registration and logging verified
✓ Successful and failed login audit logging verified
✓ Private messaging works and zero message content leakage in logs confirmed
✓ Profile update and file upload extension restriction verified
✓ Intrusion Detection System rules verified (Brute-Force, 404 Scanning, Abnormal Velocity)
✓ Admin SOC dashboard, alert resolution, and JSON export verified
```

---

## 9. Security Implementations & Hardening

- **Password Hashing**: Secure salted hashes using Werkzeug's default PBKDF2/scrypt implementation.
- **CSRF Defense**: Cryptographic session tokens generated per user session and validated on every state-changing POST request.
- **File Upload Security**:
  - File extension whitelist (`.png`, `.jpg`, `.jpeg`, `.gif`).
  - Size limitation (2MB maximum).
  - Sanitization with `secure_filename` and unique UUID renaming to prevent file collisions and directory traversal attacks.
- **Session Protection**:
  - `SESSION_COOKIE_HTTPONLY = True` to prevent XSS script access to session cookies.
  - `SESSION_COOKIE_SAMESITE = 'Lax'` to prevent cross-site request forgery.
  - Client IP tracking to detect session hijacking anomalies.
- **Security Headers**:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `X-XSS-Protection: 1; mode=block`
  - `Referrer-Policy: strict-origin-when-cross-origin`
- **Atomic Data Persistence**:
  - All JSON reads and writes are protected by Python re-entrant locks (`threading.RLock`) and atomic file replacement with retry logic to ensure zero data corruption during concurrent operations.
#   N e t w o r k _ L o g s _ a n a l y z e r  
 