import os
import sys
from flask import Flask, jsonify, render_template

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)

from log_parser import get_structured_events
from modules.detection_engine.ai_anomaly_detector import generate_ai_alert
from modules.reporting.incident_report_generator import save_incident_report

app = Flask(__name__)
LOG_FILE = os.path.join(BASE_DIR, "logs", "security_events.log")


@app.route("/")
def home():
    return jsonify({
        "message": "AI SOC Detection System Backend is running"
    })


@app.route("/dashboard")
def dashboard():
    return render_template("dashboard.html")


@app.route("/status")
def status():
    return jsonify({
        "system": "AI SOC Detection System",
        "status": "running"
    })


@app.route("/events")
def get_events():
    events = get_structured_events()

    return jsonify({
        "total_events": len(events),
        "events": events
    })


@app.route("/alerts")
def get_alerts():
    events = get_structured_events()
    alerts = []

    for event in events:
        if event["type"] == "file_integrity_changed":
            alerts.append({
                "timestamp": event["timestamp"],
                "type": "File Integrity Change",
                "severity": "HIGH",
                "details": event["message"],
                "file_path": event["file_path"]
            })

        elif event["type"] == "file_deleted":
            alerts.append({
                "timestamp": event["timestamp"],
                "type": "File Deleted",
                "severity": "MEDIUM",
                "details": event["message"],
                "file_path": event["file_path"]
            })

        elif event["type"] == "bruteforce_login_attempt":
            alerts.append({
                "timestamp": event["timestamp"],
                "type": "Brute Force Login Attempt",
                "severity": "HIGH",
                "details": event["message"],
                "file_path": event["file_path"]
            })

        elif event["type"] == "vt_malicious":
            alerts.append({
                "timestamp": event["timestamp"],
                "type": "Malicious File Reputation",
                "severity": "CRITICAL",
                "details": event["message"],
                "file_path": event["file_path"]
            })

    return jsonify({
        "total_alerts": len(alerts),
        "alerts": alerts
    })


@app.route("/system_health")
def system_health():
    events = get_structured_events()
    alerts = []

    for event in events:
        if event["type"] == "file_integrity_changed":
            alerts.append(event)
        elif event["type"] == "file_deleted":
            alerts.append(event)
        elif event["type"] == "bruteforce_login_attempt":
            alerts.append(event)
        elif event["type"] == "vt_malicious":
            alerts.append(event)

    return jsonify({
        "status": "healthy",
        "log_file": "available" if os.path.exists(LOG_FILE) else "missing",
        "total_events": len(events),
        "total_alerts": len(alerts)
    })


@app.route("/ai_alert")
def get_ai_alert():
    ai_alert = generate_ai_alert()
    return jsonify(ai_alert)

@app.route("/incident_report")
def incident_report():
    events = get_structured_events()
    alerts = []

    for event in events:
        if event["type"] == "file_integrity_changed":
            alerts.append({
                "timestamp": event["timestamp"],
                "type": "File Integrity Change",
                "severity": "HIGH",
                "details": event["message"],
                "file_path": event["file_path"]
            })

        elif event["type"] == "file_deleted":
            alerts.append({
                "timestamp": event["timestamp"],
                "type": "File Deleted",
                "severity": "MEDIUM",
                "details": event["message"],
                "file_path": event["file_path"]
            })

        elif event["type"] == "bruteforce_login_attempt":
            alerts.append({
                "timestamp": event["timestamp"],
                "type": "Brute Force Login Attempt",
                "severity": "HIGH",
                "details": event["message"],
                "file_path": event["file_path"]
            })

        elif event["type"] == "vt_malicious":
            alerts.append({
                "timestamp": event["timestamp"],
                "type": "Malicious File Reputation",
                "severity": "CRITICAL",
                "details": event["message"],
                "file_path": event["file_path"]
            })

    ai_alert = generate_ai_alert()
    report_data = save_incident_report(alerts, ai_alert)

    return jsonify({
        "message": "Incident report generated successfully",
        "incident_id": report_data["incident_id"],
        "filename": report_data["filename"],
        "filepath": report_data["filepath"],
        "report_text": report_data["report_text"]
    })


if __name__ == "__main__":
    app.run(debug=True)