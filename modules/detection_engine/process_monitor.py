import psutil

# Suspicious keywords attackers often use
SUSPICIOUS_KEYWORDS = [
    "powershell",
    "cmd.exe",
    "netcat",
    "nc",
    "ncat",
    "mimikatz"
]


def monitor_processes():
    print("\n=== Suspicious Process Detection ===")

    for process in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            process_name = process.info['name']
            cmdline = " ".join(process.info['cmdline']) if process.info['cmdline'] else ""

            for keyword in SUSPICIOUS_KEYWORDS:
                if keyword.lower() in process_name.lower() or keyword.lower() in cmdline.lower():
                    print(f"[ALERT] Suspicious process detected")
                    print(f"PID: {process.info['pid']}")
                    print(f"Process: {process_name}")
                    print(f"Command: {cmdline}\n")

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue


if __name__ == "__main__":
    monitor_processes()