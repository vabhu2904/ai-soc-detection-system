import os
import sys
from datetime import datetime, timedelta

# Add project root to Python path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.append(BASE_DIR)

from models.anomaly_model import train_anomaly_model

LOG_FILE = os.path.join(BASE_DIR, "logs", "security_events.log")


def parse_log_timestamp(line):
    """
    Extract timestamp from log line.
    Example:
    2026-03-12 15:43:18,123 WARNING File integrity changed: ...
    """
    try:
        timestamp_str = line[:19]
        return datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def get_recent_log_lines(minutes=5):
    """
    Return only log lines from the last `minutes`.
    """
    if not os.path.exists(LOG_FILE):
        return []

    now = datetime.now()
    cutoff = now - timedelta(minutes=minutes)

    recent_lines = []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            log_time = parse_log_timestamp(line)

            if log_time and log_time >= cutoff:
                recent_lines.append(line)

    return recent_lines


def extract_features_from_logs(minutes=5):
    """
    Extract behavior features from recent SOC logs only.
    Returns:
        file_changes, file_deletions, failed_logins, event_rate
    """
    lines = get_recent_log_lines(minutes)

    file_changes = 0
    file_deletions = 0
    failed_logins = 0
    event_rate = len(lines)

    for line in lines:
        if "File integrity changed" in line:
            file_changes += 1
        elif "File deleted" in line:
            file_deletions += 1
        elif "Failed login attempt detected" in line:
            failed_logins += 1

    return file_changes, file_deletions, failed_logins, event_rate


def detect_anomaly(file_changes, file_deletions, failed_logins, event_rate):
    """
    Use Isolation Forest to detect abnormal recent behavior.
    """
    model = train_anomaly_model()
    sample = [[file_changes, file_deletions, event_rate]]
    prediction = model.predict(sample)[0]

    # add rule-based override for brute-force and mixed attack behavior
    if failed_logins >= 10:
        return -1

    if (file_changes >= 8 and file_deletions >= 3) or event_rate >= 20:
        return -1

    return prediction


def calculate_risk_score(file_changes, file_deletions, failed_logins, event_rate):
    """
    Calculate simple SOC risk score out of 100.
    """
    score = 0

    # File integrity changes
    if file_changes >= 10:
        score += 30
    elif file_changes >= 5:
        score += 15
    elif file_changes > 0:
        score += 5

    # File deletions
    if file_deletions >= 5:
        score += 25
    elif file_deletions >= 2:
        score += 15
    elif file_deletions > 0:
        score += 5

    # Failed logins
    if failed_logins >= 15:
        score += 30
    elif failed_logins >= 10:
        score += 20
    elif failed_logins >= 5:
        score += 10

    # Event rate
    if event_rate >= 30:
        score += 15
    elif event_rate >= 20:
        score += 10
    elif event_rate >= 10:
        score += 5

    return min(score, 100)


def get_confidence_from_score(score):
    if score >= 70:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"


def get_severity_from_score(score, is_anomaly):
    if score >= 70:
        return "CRITICAL"
    elif score >= 35:
        return "HIGH"
    elif is_anomaly:
        return "MEDIUM"
    return "LOW"


def build_explanation(file_changes, file_deletions, failed_logins, event_rate, minutes=5):
    reasons = []

    if file_changes >= 5:
        reasons.append(f"high number of file integrity changes detected in last {minutes} minutes")

    if file_deletions >= 2:
        reasons.append(f"multiple file deletions observed in last {minutes} minutes")

    if failed_logins >= 5:
        reasons.append(f"multiple failed login attempts observed in last {minutes} minutes")

    if event_rate >= 20:
        reasons.append(f"overall event rate is unusually high in last {minutes} minutes")

    if not reasons:
        reasons.append(f"recent activity in last {minutes} minutes is within expected behavior range")

    return reasons


def get_incident_status(severity):
    if severity in ["CRITICAL", "HIGH"]:
        return "OPEN"
    elif severity == "MEDIUM":
        return "INVESTIGATING"
    return "RESOLVED"


def get_recommended_action(severity):
    if severity == "CRITICAL":
        return "Investigate immediately, review recent activity, and consider isolating the host."
    elif severity == "HIGH":
        return "Review suspicious events, validate affected files or accounts, and monitor closely."
    elif severity == "MEDIUM":
        return "Investigate the recent activity window and continue active monitoring."
    return "Continue monitoring. No immediate analyst action required."


def generate_ai_alert(minutes=5):
    """
    Generate structured AI alert from recent SOC log behavior.
    """
    file_changes, file_deletions, failed_logins, event_rate = extract_features_from_logs(minutes)
    result = detect_anomaly(file_changes, file_deletions, failed_logins, event_rate)
    is_anomaly = result == -1

    risk_score = calculate_risk_score(file_changes, file_deletions, failed_logins, event_rate)
    confidence = get_confidence_from_score(risk_score)
    severity = get_severity_from_score(risk_score, is_anomaly)
    reasons = build_explanation(file_changes, file_deletions, failed_logins, event_rate, minutes)

    if severity == "LOW":
        details = (
            f"Recent behavior appears normal: "
            f"file_changes={file_changes}, "
            f"file_deletions={file_deletions}, "
            f"failed_logins={failed_logins}, "
            f"event_rate={event_rate}, "
            f"window={minutes}min, "
            f"risk_score={risk_score}"
        )
    else:
        details = (
            f"Abnormal recent behavior detected: "
            f"file_changes={file_changes}, "
            f"file_deletions={file_deletions}, "
            f"failed_logins={failed_logins}, "
            f"event_rate={event_rate}, "
            f"window={minutes}min, "
            f"risk_score={risk_score}"
        )

    return {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "AI Anomaly Detection",
        "severity": severity,
        "incident_status": get_incident_status(severity),
        "confidence": confidence,
        "risk_score": risk_score,
        "details": details,
        "explanation": reasons,
        "recommended_action": get_recommended_action(severity)
    }


if __name__ == "__main__":
    alert = generate_ai_alert(minutes=5)

    print("=== AI Anomaly Detection Alert ===")
    print(f"Timestamp: {alert['timestamp']}")
    print(f"Type: {alert['type']}")
    print(f"Severity: {alert['severity']}")
    print(f"Incident Status: {alert['incident_status']}")
    print(f"Confidence: {alert['confidence']}")
    print(f"Risk Score: {alert['risk_score']}")
    print(f"Details: {alert['details']}")
    print("Explanation:")
    for reason in alert["explanation"]:
        print(f"- {reason}")
    print(f"Recommended Action: {alert['recommended_action']}")