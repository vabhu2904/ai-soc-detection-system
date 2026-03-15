import requests
import os
import sys

# Add project root to Python path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from utils.hash_utils import calculate_sha256

API_KEY = "5e5d1db77ccc4010ace78f0a3b9357be9d85e707bec3f37b18aad0fd0dea89b4"


def check_hash_virustotal(file_hash):
    """Check file hash reputation on VirusTotal."""
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats.get("malicious", 0)
        harmless = stats.get("harmless", 0)
        suspicious = stats.get("suspicious", 0)

        print("\n=== VirusTotal File Reputation Report ===")
        print(f"SHA256: {file_hash}")
        print(f"Malicious detections : {malicious}")
        print(f"Suspicious detections: {suspicious}")
        print(f"Harmless detections  : {harmless}")

        if malicious > 0 or suspicious > 0:
            print("[CRITICAL] File appears malicious or suspicious!")
        else:
            print("[OK] File appears safe.")

    elif response.status_code == 404:
        print("\n=== VirusTotal File Reputation Report ===")
        print(f"SHA256: {file_hash}")
        print("[INFO] File hash not found in VirusTotal database.")
    else:
        print(f"[ERROR] VirusTotal API error: {response.status_code}")
        print(response.text)


if __name__ == "__main__":
    file_path = input("Enter file path to scan: ").strip()

    if os.path.exists(file_path):
        file_hash = calculate_sha256(file_path)

        if file_hash:
            check_hash_virustotal(file_hash)
    else:
        print("[ERROR] Invalid file path.")