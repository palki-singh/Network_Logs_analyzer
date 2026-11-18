"""
Groq AI Log Monitoring & Intrusion Detection Module.
Runs a background analyzer every 5 seconds to inspect new security logs using Groq AI.
Identifies attack types, assesses threat severity, and generates forensic incident reports for CRITICAL events.
"""

import os
import json
import uuid
import time
import threading
import requests
from datetime import datetime, timezone
from config import Config
from modules.storage import load_json, append_json_item, save_json
from modules.intrusion_detection import ids_engine

_groq_lock = threading.RLock()

class GroqLogAnalyzer:
    def __init__(self):
        self.api_key = Config.GROQ_API_KEY
        self.api_url = "https://api.groq.com/openai/v1/chat/completions"
        self.model = Config.GROQ_MODEL
        self.fallback_model = Config.GROQ_FALLBACK_MODEL
        self.reports_file = Config.CRITICAL_REPORTS_FILE
        self.logs_file = Config.LOGS_FILE
        self.alerts_file = Config.ALERTS_FILE
        self.processed_log_ids = set()
        self.is_running = False
        self.worker_thread = None
        self.last_analysis_time = None
        self.latest_ai_diagnosis = None

    def start_background_analyzer(self):
        """Starts the 5-second interval background analyzer thread."""
        with _groq_lock:
            if self.is_running:
                return
            self.is_running = True
            self.worker_thread = threading.Thread(target=self._run_loop, daemon=True, name="GroqAILogAnalyzer")
            self.worker_thread.start()

    def _run_loop(self):
        """Main loop that executes every 5 seconds."""
        # Initial wait to let app initialize
        time.sleep(2)
        while self.is_running:
            try:
                self.analyze_recent_batch()
            except Exception as e:
                # Never crash the daemon
                pass
            time.sleep(Config.AI_BATCH_INTERVAL_SECONDS)

    def get_unprocessed_logs(self):
        """Retrieves logs that haven't been analyzed yet."""
        all_logs = load_json(self.logs_file, default=[])
        unprocessed = []
        for log in all_logs:
            log_id = log.get("log_id")
            if log_id and log_id not in self.processed_log_ids:
                # Exclude purely internal AI alerts to avoid loops
                if log.get("event_type") == "SUSPICIOUS_ACTIVITY" and "AI" in log.get("description", ""):
                    self.processed_log_ids.add(log_id)
                    continue
                unprocessed.append(log)
        return unprocessed

    def analyze_recent_batch(self):
        """
        Gathers logs from the last 5-second interval, queries Groq AI,
        detects attack types, and creates alerts + critical reports.
        """
        unprocessed = self.get_unprocessed_logs()
        if not unprocessed:
            return None

        # Take up to 25 recent unprocessed logs
        batch = unprocessed[-25:]
        batch_ids = [l.get("log_id") for l in batch]

        # Call Groq AI
        diagnosis = self._query_groq_ai(batch)

        # Mark logs as processed
        with _groq_lock:
            for lid in batch_ids:
                self.processed_log_ids.add(lid)
            self.last_analysis_time = datetime.now(timezone.utc).isoformat()
            if diagnosis:
                self.latest_ai_diagnosis = diagnosis

        if not diagnosis:
            return None

        # If Groq AI detected an attack
        if diagnosis.get("attack_detected"):
            attack_type = diagnosis.get("attack_type", "ANOMALY")
            severity = diagnosis.get("severity", "HIGH").upper()
            summary = diagnosis.get("summary", "Suspicious attack pattern detected by Groq AI.")
            attacker_ip = diagnosis.get("attacker_ip") or (batch[-1].get("ip_address") if batch else "127.0.0.1")

            # 1. Create Security Alert
            alert_id = f"ai-alert-{uuid.uuid4().hex[:8]}"
            alert_entry = {
                "alert_id": alert_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "alert_type": f"AI_{attack_type}",
                "source_ip": attacker_ip,
                "severity": severity,
                "description": f"[Groq AI Detection] {summary} (Reason: {diagnosis.get('explanation', '')[:200]})",
                "status": "UNRESOLVED",
                "ai_detected": True,
                "ai_model": self.model
            }
            append_json_item(self.alerts_file, alert_entry)

            # 2. If CRITICAL, Generate and Store Forensic Incident Report
            if severity == "CRITICAL" or diagnosis.get("generate_critical_report"):
                report_data = self._generate_critical_report(diagnosis, batch, alert_entry)
                append_json_item(self.reports_file, report_data)

        return diagnosis

    def _query_groq_ai(self, logs_batch):
        """Sends the log batch to Groq AI for cybersecurity attack classification."""
        if not self.api_key:
            return None

        # Format logs cleanly
        formatted_logs = []
        for l in logs_batch:
            formatted_logs.append({
                "timestamp": l.get("timestamp"),
                "ip": l.get("ip_address"),
                "user": l.get("username"),
                "event": l.get("event_type"),
                "route": f"{l.get('http_method', 'GET')} {l.get('endpoint', '/')}",
                "status": l.get("status"),
                "severity": l.get("severity"),
                "desc": l.get("description")
            })

        system_prompt = (
            "You are an elite Autonomous SOC Cybersecurity AI Analyst monitoring web application telemetry. "
            "Analyze the provided JSON logs (collected over the last 5 seconds) to determine if any cyber attack or unauthorized activity is occurring. "
            "Detect attacks such as: UNAUTHORIZED_ACCESS, BRUTE_FORCE, DIRECTORY_TRAVERSAL, RECONNAISSANCE_PROBING, SESSION_HIJACK, PRIVILEGE_ESCALATION, CREDENTIAL_STUFFING, or NONE. "
            "If someone attempts to access /admin or protected routes without credentials, classify attack_type as UNAUTHORIZED_ACCESS and severity as CRITICAL or HIGH. "
            "If rapid failed logins occur, classify as BRUTE_FORCE. "
            "Respond STRICTLY in valid JSON with this exact schema:\n"
            "{\n"
            '  "attack_detected": true,\n'
            '  "attack_type": "UNAUTHORIZED_ACCESS",\n'
            '  "severity": "CRITICAL",\n'
            '  "attacker_ip": "127.0.0.1",\n'
            '  "summary": "Short 1-sentence summary",\n'
            '  "explanation": "Detailed explanation of what the attacker is doing and why it is dangerous",\n'
            '  "generate_critical_report": true,\n'
            '  "remediation": "Recommended immediate actions"\n'
            "}\n"
            "If traffic is benign, set attack_detected=false, attack_type='NONE', severity='LOW'."
        )

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Logs collected in the last 5 seconds:\n{json.dumps(formatted_logs, indent=2)}"}
            ],
            "temperature": 0.1,
            "max_tokens": 600,
            "response_format": {"type": "json_object"}
        }

        for chosen_model in [self.model, self.fallback_model]:
            payload["model"] = chosen_model
            try:
                response = requests.post(self.api_url, headers=headers, json=payload, timeout=8)
                if response.status_code == 200:
                    data = response.json()
                    content = data["choices"][0]["message"].get("content", "").strip()
                    if content:
                        parsed = json.loads(content)
                        parsed["ai_model_used"] = chosen_model
                        return parsed
            except Exception:
                continue

        # Rule-based fallback if Groq is temporarily unreachable
        return self._fallback_local_detector(logs_batch)

    def _fallback_local_detector(self, logs_batch):
        """Fallback heuristics if Groq API is network-constrained."""
        for log in logs_batch:
            endpoint = log.get("endpoint", "")
            status = log.get("status", "")
            event_type = log.get("event_type", "")
            ip = log.get("ip_address", "127.0.0.1")

            # Check unauthorized access to admin
            if endpoint.startswith("/admin") and (status in ["DENIED", "FAILED"] or event_type == "UNAUTHORIZED_ACCESS"):
                return {
                    "attack_detected": True,
                    "attack_type": "UNAUTHORIZED_ADMIN_ACCESS",
                    "severity": "CRITICAL",
                    "attacker_ip": ip,
                    "summary": f"Unauthorized access attempt detected targeting admin route '{endpoint}' from IP {ip}.",
                    "explanation": f"An unauthenticated user or intruder attempted to penetrate the administrative boundary at {endpoint}.",
                    "generate_critical_report": True,
                    "remediation": "Immediately verify IP address and enforce firewall / rate-limiting rules."
                }

            if event_type == "LOGIN_FAILED":
                failed_count = sum(1 for l in logs_batch if l.get("event_type") == "LOGIN_FAILED" and l.get("ip_address") == ip)
                if failed_count >= 3:
                    return {
                        "attack_detected": True,
                        "attack_type": "BRUTE_FORCE",
                        "severity": "CRITICAL" if failed_count >= 5 else "HIGH",
                        "attacker_ip": ip,
                        "summary": f"Rapid authentication failure burst ({failed_count} attempts) from IP {ip}.",
                        "explanation": f"Attacker is rapidly attempting credentials on /login, indicating password guessing or automated brute force.",
                        "generate_critical_report": (failed_count >= 5),
                        "remediation": "Lock account temporarily and challenge IP with progressive rate limiting."
                    }

        return None

    def _generate_critical_report(self, diagnosis, raw_logs, alert_entry):
        """Generates a structured forensic incident report for CRITICAL threat detections."""
        report_id = f"REP-CRIT-{uuid.uuid4().hex[:6].upper()}"
        attacker_ip = diagnosis.get("attacker_ip") or (raw_logs[-1].get("ip_address") if raw_logs else "127.0.0.1")
        attack_type = diagnosis.get("attack_type", "CRITICAL_SECURITY_BREACH")

        report = {
            "report_id": report_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "alert_id": alert_entry.get("alert_id"),
            "incident_title": f"CRITICAL INCIDENT: {attack_type.replace('_', ' ').title()}",
            "threat_level": "CRITICAL",
            "attack_type": attack_type,
            "attacker_ip": attacker_ip,
            "ai_engine": f"Groq AI ({diagnosis.get('ai_model_used', self.model)})",
            "executive_summary": diagnosis.get("summary", "Critical unauthorized activity detected by autonomous AI monitor."),
            "threat_details": diagnosis.get("explanation", "The AI system detected behavior violating security access controls."),
            "targeted_resources": list(set([l.get("endpoint") for l in raw_logs if l.get("endpoint")])),
            "remediation_actions": diagnosis.get("remediation", "Block offending IP, revoke compromised sessions, and inspect access logs."),
            "indicators_of_compromise": [
                f"Source IP: {attacker_ip}",
                f"Attack Signature: {attack_type}",
                f"Detection Timestamp: {datetime.now(timezone.utc).isoformat()}"
            ],
            "evidence_logs_count": len(raw_logs),
            "evidence_logs_sample": raw_logs[-8:]
        }
        return report

    def get_all_reports(self):
        """Loads all critical forensic reports, newest first."""
        reports = load_json(self.reports_file, default=[])
        return sorted(reports, key=lambda r: r.get("timestamp", ""), reverse=True)

    def get_report_by_id(self, report_id):
        """Finds a specific critical report by ID."""
        for r in self.get_all_reports():
            if r.get("report_id") == report_id:
                return r
        return None

# Global instance
groq_analyzer = GroqLogAnalyzer()
