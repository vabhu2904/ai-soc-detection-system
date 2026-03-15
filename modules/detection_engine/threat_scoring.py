# Threat scoring engine

risk_score = 0


def file_modification():
    global risk_score
    risk_score += 2
    print("[EVENT] File modification detected")


def suspicious_process():
    global risk_score
    risk_score += 3
    print("[EVENT] Suspicious process detected")


def ransomware_behavior():
    global risk_score
    risk_score += 5
    print("[EVENT] Possible ransomware activity")


def evaluate_threat():
    print(f"\nCurrent Risk Score: {risk_score}")

    if risk_score >= 7:
        print("[CRITICAL] High probability of attack!")
    elif risk_score >= 4:
        print("[WARNING] Suspicious activity detected")
    else:
        print("[INFO] System normal")


if __name__ == "__main__":

    # Simulating events
    file_modification()
    suspicious_process()

    evaluate_threat()