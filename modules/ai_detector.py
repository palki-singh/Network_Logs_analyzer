"""
AI-Based Log Anomaly Detection System for Cosmic Connect / SecureChat.
Uses Machine Learning (Isolation Forest & Behavioral Feature Ensembles)
to detect unauthorized requests, unusual login volumes, and velocity anomalies in real time.
"""

import math
import uuid
from datetime import datetime, timezone, timedelta
import numpy as np
try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

from config import Config
from modules.storage import load_json, append_json_item
from modules.intrusion_detection import ids_engine

class AILogDetector:
    def __init__(self, logs_file=None, alerts_file=None):
        self.logs_file = logs_file or Config.LOGS_FILE
        self.alerts_file = alerts_file or Config.ALERTS_FILE
        self.model = None
        self.is_trained = False
        self.last_trained_at = None
        self._init_model()

    def _init_model(self):
        """Initializes the Isolation Forest ML model."""
        if SKLEARN_AVAILABLE:
            self.model = IsolationForest(
                n_estimators=100,
                contamination=0.08,
                random_state=42,
                warm_start=False
            )
        self.train_baseline()

    def _parse_time(self, ts_str):
        try:
            return datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        except Exception:
            return datetime.min.replace(tzinfo=timezone.utc)

    def extract_features(self, log, recent_logs):
        """
        Extracts multi-dimensional numerical feature vectors from a log event.
        Features:
        1. endpoint_risk: Risk weight of the requested route (admin, secret, probe = high)
        2. method_code: HTTP method encoded
        3. status_code: Execution outcome (SUCCESS=0, FAILED=1, DENIED=2, ALERT=3)
        4. severity_weight: LOW=1, MEDIUM=2, HIGH=3, CRITICAL=4
        5. ip_login_freq_3m: Logins from same IP within 3 minutes
        6. ip_unauth_count_5m: Unauthorized access attempts from same IP within 5 minutes
        7. ip_failed_login_ratio: Ratio of failed attempts for this IP
        8. time_hour_sin: Periodic time of day sine
        9. time_hour_cos: Periodic time of day cosine
        10. request_velocity_1m: Total events from this IP in the past 60 seconds
        """
        endpoint = log.get("endpoint", "")
        ip = log.get("ip_address", "127.0.0.1")
        status = log.get("status", "SUCCESS")
        severity = log.get("severity", "LOW")
        http_method = log.get("http_method", "GET")
        ts = self._parse_time(log.get("timestamp", ""))

        # 1. Endpoint Risk
        endpoint_risk = 0.1
        if endpoint.startswith("/admin"):
            endpoint_risk = 0.95
        elif any(probe in endpoint for probe in [".env", "wp-admin", "config", "debug", "phpmyadmin", "shell"]):
            endpoint_risk = 1.0
        elif endpoint.startswith("/chat") or endpoint.startswith("/api/chat"):
            endpoint_risk = 0.2
        elif endpoint in ["/login", "/register"]:
            endpoint_risk = 0.35

        # 2. Method Code
        method_map = {"GET": 0.1, "POST": 0.5, "PUT": 0.7, "DELETE": 0.9, "SYSTEM": 0.2}
        method_code = method_map.get(http_method.upper(), 0.3)

        # 3. Status Code
        status_map = {"SUCCESS": 0.0, "NOT_FOUND": 0.3, "FAILED": 0.7, "DENIED": 0.95, "ALERT_TRIGGERED": 1.0, "SUSPICIOUS": 0.9}
        status_code = status_map.get(status, 0.4)

        # 4. Severity Weight
        sev_map = {"LOW": 1.0, "MEDIUM": 2.5, "HIGH": 4.0, "CRITICAL": 5.0}
        severity_weight = sev_map.get(severity, 1.0)

        # Sliding window aggregations from recent logs
        window_3m = ts - timedelta(minutes=3)
        window_5m = ts - timedelta(minutes=5)
        window_1m = ts - timedelta(minutes=1)

        logs_3m = [l for l in recent_logs if l.get("ip_address") == ip and self._parse_time(l.get("timestamp", "")) >= window_3m]
        logs_5m = [l for l in recent_logs if l.get("ip_address") == ip and self._parse_time(l.get("timestamp", "")) >= window_5m]
        logs_1m = [l for l in recent_logs if l.get("ip_address") == ip and self._parse_time(l.get("timestamp", "")) >= window_1m]

        # 5. IP Login Frequency
        login_events = [l for l in logs_3m if "LOGIN" in l.get("event_type", "")]
        ip_login_freq_3m = float(len(login_events))

        # 6. IP Unauthorized Count
        unauth_events = [l for l in logs_5m if l.get("event_type") == "UNAUTHORIZED_ACCESS" or l.get("status") == "DENIED"]
        ip_unauth_count_5m = float(len(unauth_events))

        # 7. Failed Login Ratio
        if login_events:
            failed_logins = [l for l in login_events if "FAILED" in l.get("event_type", "") or l.get("status") == "FAILED"]
            ip_failed_login_ratio = float(len(failed_logins)) / float(len(login_events))
        else:
            ip_failed_login_ratio = 0.0

        # 8 & 9. Cyclical Time
        hour = ts.hour if hasattr(ts, "hour") else 12
        time_hour_sin = math.sin(2 * math.pi * hour / 24)
        time_hour_cos = math.cos(2 * math.pi * hour / 24)

        # 10. Request Velocity
        request_velocity_1m = float(len(logs_1m))

        return np.array([
            endpoint_risk,
            method_code,
            status_code,
            severity_weight,
            ip_login_freq_3m,
            ip_unauth_count_5m,
            ip_failed_login_ratio,
            time_hour_sin,
            time_hour_cos,
            request_velocity_1m
        ], dtype=np.float64)

    def train_baseline(self):
        """
        Trains or updates the Isolation Forest ML model using historical logs
        and synthetic baseline application events.
        """
        logs = load_json(self.logs_file, default=[])
        feature_matrix = []

        # Extract features from historical logs
        for log in logs:
            feats = self.extract_features(log, logs)
            feature_matrix.append(feats)

        # Augment with baseline normal and known anomaly samples if logs are sparse
        if len(feature_matrix) < 40:
            # Synthetic normal browsing samples
            for _ in range(30):
                normal = np.array([0.15, 0.1, 0.0, 1.0, 0.0, 0.0, 0.0, 0.5, 0.5, 1.0])
                feature_matrix.append(normal + np.random.normal(0, 0.05, 10))
            # Synthetic login samples
            for _ in range(15):
                normal_login = np.array([0.35, 0.5, 0.0, 1.0, 1.0, 0.0, 0.0, 0.2, 0.8, 2.0])
                feature_matrix.append(normal_login + np.random.normal(0, 0.05, 10))

        X = np.array(feature_matrix)

        if SKLEARN_AVAILABLE and self.model is not None:
            try:
                self.model.fit(X)
                self.is_trained = True
                self.last_trained_at = datetime.now(timezone.utc).isoformat()
            except Exception:
                self.is_trained = False
        else:
            self.is_trained = True
            self.last_trained_at = datetime.now(timezone.utc).isoformat()

    def score_log(self, log, all_logs=None):
        """
        Evaluates a log entry and returns:
        (is_anomaly, anomaly_score_percentage, threat_category, explanation)
        """
        if all_logs is None:
            all_logs = load_json(self.logs_file, default=[])

        feats = self.extract_features(log, all_logs)
        features_2d = feats.reshape(1, -1)

        # Baseline heuristic scores
        endpoint_risk = feats[0]
        status_code = feats[2]
        ip_login_freq = feats[4]
        ip_unauth_count = feats[5]
        ip_failed_ratio = feats[6]
        request_velocity = feats[9]

        ml_score = 0.5
        is_ml_anomaly = False

        if SKLEARN_AVAILABLE and self.is_trained and self.model is not None:
            try:
                # decision_function: lower means more anomalous
                decision = self.model.decision_function(features_2d)[0]
                pred = self.model.predict(features_2d)[0]  # -1 for anomaly, 1 for normal
                is_ml_anomaly = (pred == -1)

                # Normalize decision function into 0.0 - 1.0 anomaly confidence
                # Typically decision ranges between -0.3 and 0.3
                norm_score = 1.0 / (1.0 + math.exp(decision * 10))
                ml_score = float(np.clip(norm_score, 0.05, 0.99))
            except Exception:
                ml_score = 0.5
                is_ml_anomaly = False

        # Statistical heuristic boost for targeted criteria
        heuristic_score = 0.1
        threat_type = "NORMAL"
        explanations = []

        # 1. Unusual Amount of Logins
        if ip_login_freq >= 5:
            heuristic_score = max(heuristic_score, 0.88 if ip_login_freq >= 8 else 0.72)
            threat_type = "AI_UNUSUAL_LOGIN_VOLUME"
            explanations.append(f"AI Detected Unusual Login Velocity: {int(ip_login_freq)} login requests detected from IP {log.get('ip_address')} within 3 minutes (Failed ratio: {int(ip_failed_ratio*100)}%).")

        # 2. Unauthorized Requests
        if ip_unauth_count >= 1 or status_code >= 0.9 or (endpoint_risk >= 0.9 and log.get("username") in ["anonymous", "unauthenticated"]):
            heuristic_score = max(heuristic_score, 0.92)
            threat_type = "AI_UNAUTHORIZED_REQUEST_ANOMALY"
            explanations.append(f"AI Detected Unauthorized Request: Attempted breach on protected endpoint '{log.get('endpoint')}' by user '{log.get('username')}' from IP {log.get('ip_address')}.")

        # 3. High Request Velocity
        if request_velocity >= 12:
            heuristic_score = max(heuristic_score, 0.78)
            threat_type = "AI_VELOCITY_SPIKE"
            explanations.append(f"AI Detected Traffic Burst: {int(request_velocity)} requests/min from IP {log.get('ip_address')}.")

        # Blend ML Isolation Forest score and heuristic feature score
        final_score = (0.45 * ml_score) + (0.55 * heuristic_score)
        confidence_pct = round(final_score * 100, 1)

        is_anomaly = (final_score >= 0.65) or is_ml_anomaly and (final_score >= 0.5)

        explanation_str = " | ".join(explanations) if explanations else "Normal telemetry pattern matching baseline behavior."

        return {
            "is_anomaly": is_anomaly,
            "confidence_pct": confidence_pct,
            "threat_type": threat_type,
            "explanation": explanation_str,
            "ml_model": "IsolationForest (scikit-learn)" if SKLEARN_AVAILABLE else "Statistical Feature Ensemble",
            "features": {
                "endpoint_risk": round(endpoint_risk, 2),
                "login_frequency": int(ip_login_freq),
                "unauthorized_count": int(ip_unauth_count),
                "request_velocity": int(request_velocity)
            }
        }

    def analyze_and_dispatch_warning(self, log):
        """
        Evaluates a newly arrived log with AI.
        If an unauthorized request or unusual amount of logins is detected,
        creates an AI Warning Alert in security_alerts.json for the admin dashboard.
        """
        analysis = self.score_log(log)

        if analysis["is_anomaly"] and analysis["threat_type"] != "NORMAL":
            alert_type = analysis["threat_type"]
            source_ip = log.get("ip_address", "127.0.0.1")
            severity = "CRITICAL" if analysis["confidence_pct"] >= 85 else "HIGH"

            description = f"[AI Warning - {analysis['confidence_pct']}% Confidence] {analysis['explanation']}"

            # Create IDS alert using existing deduplication engine
            alert = ids_engine.create_alert(
                alert_type=alert_type,
                source_ip=source_ip,
                severity=severity,
                description=description
            )
            return alert, analysis

        return None, analysis

    def get_recent_ai_warnings(self, limit=10):
        """Retrieves recent alerts generated by the AI detection system."""
        alerts = ids_engine.get_all_alerts()
        ai_alerts = [a for a in alerts if a.get("alert_type", "").startswith("AI_")]
        return ai_alerts[:limit]

    def get_active_ai_warnings(self):
        """Retrieves currently UNRESOLVED alerts generated by the AI detection system."""
        unresolved = ids_engine.get_unresolved_alerts()
        return [a for a in unresolved if a.get("alert_type", "").startswith("AI_")]

# Global AI Detector instance
ai_detector = AILogDetector()
