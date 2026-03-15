import requests

API_KEY = "5e5d1db77ccc4010ace78f0a3b9357be9d85e707bec3f37b18aad0fd0dea89b4"

def check_file_hash(file_hash):

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"

    headers = {
        "x-apikey": API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:

        data = response.json()

        stats = data["data"]["attributes"]["last_analysis_stats"]

        malicious = stats["malicious"]
        harmless = stats["harmless"]

        print("\n=== VirusTotal Threat Intelligence ===")
        print(f"Malicious detections: {malicious}")
        print(f"Harmless detections: {harmless}")

        if malicious > 0:
            print("[CRITICAL] Malware detected!")
        else:
            print("[OK] File appears safe")

    else:
        print("Error querying VirusTotal API")


if __name__ == "__main__":

    # Example known malware hash (test)
    test_hash = "44d88612fea8a8f36de82e1278abb02f"

    check_file_hash(test_hash)