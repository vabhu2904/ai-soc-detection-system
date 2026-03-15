import threading
import subprocess
import time


def start_file_monitor():
    print("[SYSTEM] Starting File Monitor...")
    subprocess.run(["python", "modules/file_monitor/file_monitor.py"])


def start_backend():
    print("[SYSTEM] Starting Backend API...")
    subprocess.run(["python", "backend/app.py"])


if __name__ == "__main__":

    print("=================================")
    print("   AI SOC Detection System")
    print("=================================")

    # start file monitor in separate thread
    monitor_thread = threading.Thread(target=start_file_monitor)
    monitor_thread.start()

    # small delay before backend starts
    time.sleep(2)

    # start backend
    start_backend()