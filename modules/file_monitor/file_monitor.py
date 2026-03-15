import time
import logging
import os
import sys
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LOG_FILE = os.path.join(BASE_DIR, "logs", "security_events.log")
DATA_DIR = os.path.join(BASE_DIR, "data")

# Add project root to Python path
sys.path.append(BASE_DIR)

from utils.hash_utils import calculate_sha256

API_KEY = "5e5d1db77ccc4010ace78f0a3b9357be9d85e707bec3f37b18aad0fd0dea89b4"

# Configure logging
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

file_hashes = {}


def check_hash_virustotal(file_hash):
    """Check file hash reputation on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)

            print("\n=== VirusTotal Threat Intelligence ===")
            print(f"SHA256: {file_hash}")
            print(f"Malicious detections : {malicious}")
            print(f"Suspicious detections: {suspicious}")
            print(f"Harmless detections  : {harmless}")

            if malicious > 0 or suspicious > 0:
                vt_message = f"Malicious file reputation detected for hash: {file_hash}"
                print("[CRITICAL] File appears malicious or suspicious!")
                logging.critical(vt_message)
            else:
                print("[OK] File appears safe.")
                logging.info(f"File hash appears safe: {file_hash}")

        elif response.status_code == 404:
            print("\n=== VirusTotal Threat Intelligence ===")
            print(f"SHA256: {file_hash}")
            print("[INFO] File hash not found in VirusTotal database.")
            logging.info(f"File hash not found in VirusTotal database: {file_hash}")

        else:
            print(f"[ERROR] VirusTotal API error: {response.status_code}")
            logging.error(f"VirusTotal API error: {response.status_code}")

    except Exception as e:
        print(f"[ERROR] Threat intelligence check failed: {e}")
        logging.error(f"Threat intelligence check failed: {e}")


def build_initial_baseline():
    """Create baseline hashes for all existing files before monitoring starts."""
    print("[SYSTEM] Building baseline for existing files...")

    for root, _, files in os.walk(DATA_DIR):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            file_hash = calculate_sha256(file_path)

            if file_hash:
                file_hashes[file_path] = file_hash
                print(f"[BASELINE] {file_path}")
                logging.info(f"Baseline hash stored for: {file_path}")


class FileMonitorHandler(FileSystemEventHandler):

    def on_created(self, event):
        if not event.is_directory:
            file_hash = calculate_sha256(event.src_path)
            file_hashes[event.src_path] = file_hash

            message = f"File created: {event.src_path}"
            print(f"[INFO] {message}")
            logging.info(message)

            if file_hash:
                print(f"[HASH] {file_hash}")
                logging.info(f"SHA256 generated: {file_hash}")
                check_hash_virustotal(file_hash)

    def on_modified(self, event):
        if not event.is_directory:
            new_hash = calculate_sha256(event.src_path)
            old_hash = file_hashes.get(event.src_path)

            if old_hash is None:
                # file existed before but was not in baseline for some reason
                file_hashes[event.src_path] = new_hash
                logging.info(f"Hash initialized on first seen modification: {event.src_path}")
                return

            if new_hash != old_hash:
                message = f"File integrity changed: {event.src_path}"
                print(f"[ALERT] {message}")
                logging.warning(message)

                print(f"Old Hash: {old_hash}")
                print(f"New Hash: {new_hash}")
                logging.info(f"Old Hash: {old_hash}")
                logging.info(f"New Hash: {new_hash}")

                if new_hash:
                    check_hash_virustotal(new_hash)

            file_hashes[event.src_path] = new_hash

    def on_deleted(self, event):
        if not event.is_directory:
            file_hashes.pop(event.src_path, None)

            message = f"File deleted: {event.src_path}"
            print(f"[WARNING] {message}")
            logging.warning(message)


if __name__ == "__main__":
    path = DATA_DIR

    build_initial_baseline()

    event_handler = FileMonitorHandler()

    observer = Observer()
    observer.schedule(event_handler, path, recursive=True)
    observer.start()

    print("AI SOC Monitoring with Threat Intelligence Started...")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()