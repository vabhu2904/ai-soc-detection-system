import os
from collections import Counter

LOG_FILE = "../../logs/security_events.log"


def read_logs():
    """Read all lines from the security log file."""
    if not os.path.exists(LOG_FILE):
        print("[ERROR] Log file not found.")
        return []

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        return file.readlines()


def analyze_events(log_lines):
    """Count different security events."""
    event_counter = Counter()

    for line in log_lines:
        if "File created" in line:
            event_counter["file_created"] += 1
        elif "File integrity changed" in line:
            event_counter["file_integrity_changed"] += 1
        elif "File deleted" in line:
            event_counter["file_deleted"] += 1
        elif "Failed login attempt" in line:
            event_counter["failed_login_attempt"] += 1

    return event_counter


def detect_bruteforce(events, threshold=10):
    """
    Detect brute force login attempts from failed login events.
    """
    failed_logins = [e for e in events if "Failed login attempt" in e]

    if len(failed_logins) >= threshold:
        return {
            "type": "Brute Force Login Attempt",
            "severity": "HIGH",
            "details": f"{len(failed_logins)} failed login attempts detected",
            "explanation": "Multiple failed authentication attempts detected in short time window",
            "recommended_action": "Investigate source IP and consider blocking repeated login attempts."
        }

    return None


def print_summary(event_counter):
    """Print summary of detected events."""
    print("\n=== Security Event Summary ===")
    print(f"Files Created           : {event_counter['file_created']}")
    print(f"Integrity Changes       : {event_counter['file_integrity_changed']}")
    print(f"Files Deleted           : {event_counter['file_deleted']}")
    print(f"Failed Login Attempts   : {event_counter['failed_login_attempt']}")


if __name__ == "__main__":
    logs = read_logs()
    summary = analyze_events(logs)
    print_summary(summary)

    bruteforce_alert = detect_bruteforce(logs)

    if bruteforce_alert:
        print("\n=== Brute Force Alert ===")
        print(f"Type               : {bruteforce_alert['type']}")
        print(f"Severity           : {bruteforce_alert['severity']}")
        print(f"Details            : {bruteforce_alert['details']}")
        print(f"Explanation        : {bruteforce_alert['explanation']}")
        print(f"Recommended Action : {bruteforce_alert['recommended_action']}")