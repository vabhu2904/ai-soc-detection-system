import datetime

alerts = []


def create_alert(alert_type, severity, source, description):

    alert = {
        "time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": alert_type,
        "severity": severity,
        "source": source,
        "description": description
    }

    alerts.append(alert)

    print("\n===== SOC ALERT =====")
    print(f"Time: {alert['time']}")
    print(f"Type: {alert['type']}")
    print(f"Severity: {alert['severity']}")
    print(f"Source: {alert['source']}")
    print(f"Description: {alert['description']}")
    print("=====================\n")


if __name__ == "__main__":

    # Simulating alerts coming from different modules

    create_alert(
        "File Integrity Change",
        "MEDIUM",
        "File Monitor",
        "Important file modified in monitored directory"
    )

    create_alert(
        "Suspicious Process",
        "HIGH",
        "Process Monitor",
        "Powershell suspicious command detected"
    )

    create_alert(
        "Possible Ransomware",
        "CRITICAL",
        "Ransomware Detector",
        "Multiple file modifications detected rapidly"
    )