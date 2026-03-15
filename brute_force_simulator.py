import os
import time
from datetime import datetime

LOG_FILE = os.path.join("logs", "security_events.log")


def log_failed_login(username, ip_address):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
    message = f"{timestamp} WARNING Failed login attempt detected: username={username}, ip={ip_address}"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")
    print(f"[BRUTE FORCE] {message}")


def brute_force_login_simulation(username="admin", ip_address="192.168.1.50", attempts=15):
    """
    Simulate repeated failed login attempts.
    """
    print("\n=== Brute-force Login Attempt Simulation ===\n")

    for _ in range(attempts):
        log_failed_login(username, ip_address)
        time.sleep(0.2)

    print("\nBrute-force simulation completed.\n")


if __name__ == "__main__":
    brute_force_login_simulation()