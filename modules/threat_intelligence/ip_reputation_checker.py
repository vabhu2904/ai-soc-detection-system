import requests

API_KEY = "fdc6a88058e98d4fb974ad938d3ce13855d87d9c0fd6a5538b12f424b50c29457af1d6a23abb3b45"


def check_ip_reputation(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"

    headers = {
        "Key": API_KEY,
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

            abuse_score = data.get("abuseConfidenceScore", 0)
            country = data.get("countryCode", "Unknown")
            isp = data.get("isp", "Unknown")
            usage_type = data.get("usageType", "Unknown")
            total_reports = data.get("totalReports", 0)

            print("\n=== AbuseIPDB Reputation Report ===")
            print(f"IP Address      : {ip_address}")
            print(f"Abuse Score     : {abuse_score}")
            print(f"Country         : {country}")
            print(f"ISP             : {isp}")
            print(f"Usage Type      : {usage_type}")
            print(f"Total Reports   : {total_reports}")

            if abuse_score >= 75:
                print("[CRITICAL] IP is highly malicious!")
            elif abuse_score >= 25:
                print("[WARNING] IP is suspicious.")
            else:
                print("[OK] IP appears safe.")

        else:
            print(f"[ERROR] AbuseIPDB API error: {response.status_code}")
            print(response.text)

    except Exception as e:
        print(f"[ERROR] Failed to check IP reputation: {e}")


if __name__ == "__main__":
    ip_address = input("Enter IP address to check: ").strip()
    check_ip_reputation(ip_address)