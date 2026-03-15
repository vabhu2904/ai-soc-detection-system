import os
import re

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILE = os.path.join(BASE_DIR, "logs", "security_events.log")


def read_log_lines():
    if not os.path.exists(LOG_FILE):
        return []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        return [line.strip() for line in f.readlines()]


def parse_event_line(line):
    """
    Parse raw log line into structured event object.
    Example:
    2026-03-11 23:06:48,113 WARNING File integrity changed: C:\\Users\\...\\test.txt
    """
    pattern = r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}),\d+\s+(\w+)\s+(.*)$"
    match = re.match(pattern, line)

    if not match:
        return {
            "timestamp": "Unknown",
            "level": "INFO",
            "type": "unknown",
            "message": line,
            "file_path": None,
            "raw": line
        }

    timestamp, level, message = match.groups()

    event_type = "unknown"
    file_path = None

    if "File created:" in message:
        event_type = "file_created"
        file_path = message.split("File created:")[-1].strip()

    elif "File integrity changed:" in message:
        event_type = "file_integrity_changed"
        file_path = message.split("File integrity changed:")[-1].strip()

    elif "File deleted:" in message:
        event_type = "file_deleted"
        file_path = message.split("File deleted:")[-1].strip()

    elif "Failed login attempt detected:" in message:
        event_type = "bruteforce_login_attempt"

    elif "Old Hash:" in message:
        event_type = "old_hash"

    elif "New Hash:" in message:
        event_type = "new_hash"

    elif "File hash not found in VirusTotal database:" in message:
        event_type = "vt_hash_not_found"

    elif "File hash appears safe:" in message:
        event_type = "vt_hash_safe"

    elif "Malicious file reputation detected" in message:
        event_type = "vt_malicious"

    return {
        "timestamp": timestamp,
        "level": level,
        "type": event_type,
        "message": message,
        "file_path": file_path,
        "raw": line
    }


def get_structured_events():
    lines = read_log_lines()
    return [parse_event_line(line) for line in lines]