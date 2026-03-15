import os

LOG_FILE = "../../logs/security_events.log"
THRESHOLD = 3   # number of integrity changes to trigger alert


def read_logs():
    """Read all lines from the security log file."""
    if not os.path.exists(LOG_FILE):
        print("[ERROR] Log file not found.")
        return []

    with open(LOG_FILE, "r") as file:
        return file.readlines()


def detect_ransomware(log_lines):
    """Detect possible ransomware behavior based on repeated integrity changes."""
    integrity_change_count = 0

    for line in log_lines:
        if "File integrity changed" in line:
            integrity_change_count += 1

    print("\n=== Ransomware Detection Report ===")
    print(f"Integrity Change Events: {integrity_change_count}")

    if integrity_change_count >= THRESHOLD:
        print("[CRITICAL ALERT] Possible ransomware behavior detected!")
    else:
        print("[OK] No ransomware pattern detected.")


if __name__ == "__main__":
    logs = read_logs()
    detect_ransomware(logs)