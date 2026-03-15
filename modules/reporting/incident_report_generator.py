import os
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
REPORTS_DIR = os.path.join(BASE_DIR, "reports")


def ensure_reports_dir():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)


def generate_incident_id():
    now = datetime.now()
    return f"SOC-{now.strftime('%Y%m%d-%H%M%S')}"


def build_incident_report(alerts, ai_alert):
    """
    Build SOC incident report text from current alerts and AI analysis.
    """
    incident_id = generate_incident_id()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    latest_alert = alerts[-1] if alerts else None

    threat_type = latest_alert["type"] if latest_alert else "No active alert"
    severity = latest_alert["severity"] if latest_alert else "LOW"
    details = latest_alert["details"] if latest_alert else "No suspicious activity detected."

    risk_score = ai_alert.get("risk_score", "N/A")
    incident_status = ai_alert.get("incident_status", "N/A")
    confidence = ai_alert.get("confidence", "N/A")
    explanation = ai_alert.get("explanation", [])
    recommended_action = ai_alert.get("recommended_action", "Continue monitoring.")

    report_lines = [
        "SOC INCIDENT REPORT",
        "=" * 60,
        f"Incident ID       : {incident_id}",
        f"Generated At      : {timestamp}",
        "",
        "INCIDENT SUMMARY",
        "-" * 60,
        f"Threat Type       : {threat_type}",
        f"Severity          : {severity}",
        f"Incident Status   : {incident_status}",
        f"Confidence        : {confidence}",
        f"AI Risk Score     : {risk_score}",
        "",
        "ALERT DETAILS",
        "-" * 60,
        f"Summary           : {details}",
        "",
        "AI EXPLANATION",
        "-" * 60,
    ]

    if explanation:
        for reason in explanation:
            report_lines.append(f"- {reason}")
    else:
        report_lines.append("- No explanation available")

    report_lines.extend([
        "",
        "RECENT ALERT EVIDENCE",
        "-" * 60,
    ])

    if alerts:
        for alert in alerts[-10:]:
            report_lines.append(
                f"[{alert.get('timestamp', 'Unknown')}] "
                f"{alert.get('type', 'Unknown')} | "
                f"{alert.get('severity', 'Unknown')} | "
                f"{alert.get('details', '')}"
            )
    else:
        report_lines.append("No alert evidence found.")

    report_lines.extend([
        "",
        "RECOMMENDED RESPONSE",
        "-" * 60,
        recommended_action,
        "",
        "=" * 60,
        "End of Report"
    ])

    return incident_id, "\n".join(report_lines)


def save_incident_report(alerts, ai_alert):
    ensure_reports_dir()
    incident_id, report_text = build_incident_report(alerts, ai_alert)

    filename = f"{incident_id}.txt"
    filepath = os.path.join(REPORTS_DIR, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(report_text)

    return {
        "incident_id": incident_id,
        "filename": filename,
        "filepath": filepath,
        "report_text": report_text
    }