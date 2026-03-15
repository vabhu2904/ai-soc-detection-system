import requests

VT_API_KEY = "5e5d1db77ccc4010ace78f0a3b9357be9d85e707bec3f37b18aad0fd0dea89b4"
ABUSEIPDB_API_KEY = "fdc6a88058e98d4fb974ad938d3ce13855d87d9c0fd6a5538b12f424b50c29457af1d6a23abb3b45"


def check_file_hash_virustotal(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)

            return {
                "malicious": malicious,
                "suspicious": suspicious
            }

        elif response.status_code == 404:
            return {
                "malicious": 0,
                "suspicious": 0
            }

        else:
            print(f"[ERROR] VirusTotal API error: {response.status_code}")
            return None

    except Exception as e:
        print(f"[ERROR] VirusTotal check failed: {e}")
        return None


def check_ip_abuse(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(url, headers=headers, params=params)

        if response.status_code == 200:
            data = response.json()["data"]

            return {
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0)
            }

        else:
            print(f"[ERROR] AbuseIPDB API error: {response.status_code}")
            return None

    except Exception as e:
        print(f"[ERROR] AbuseIPDB check failed: {e}")
        return None


def correlate_threats(file_hash, ip_address):
    vt_result = check_file_hash_virustotal(file_hash)
    ip_result = check_ip_abuse(ip_address)

    if vt_result is None or ip_result is None:
        print("[ERROR] Could not complete threat correlation.")
        return

    print("\n=== Threat Intelligence Correlation Report ===")
    print(f"File Hash Malicious Detections : {vt_result['malicious']}")
    print(f"File Hash Suspicious Detections: {vt_result['suspicious']}")
    print(f"IP Abuse Score                : {ip_result['abuse_score']}")
    print(f"IP Total Reports             : {ip_result['total_reports']}")

    if vt_result["malicious"] > 0 and ip_result["abuse_score"] >= 75:
        print("[CRITICAL] Malicious file + malicious IP detected!")
    elif vt_result["malicious"] > 0 or ip_result["abuse_score"] >= 75:
        print("[WARNING] One strong threat indicator detected.")
    elif vt_result["suspicious"] > 0 or ip_result["abuse_score"] >= 25:
        print("[WARNING] Suspicious indicators detected.")
    else:
        print("[OK] No strong threat indicators detected.")


if __name__ == "__main__":
    file_hash = input("Enter file hash to analyze: ").strip()
    ip_address = input("Enter IP address to analyze: ").strip()

    correlate_threats(file_hash, ip_address)