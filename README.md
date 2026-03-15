![Python](https://img.shields.io/badge/Python-3.12-blue)
![Security](https://img.shields.io/badge/Cybersecurity-SOC-red)
![AI](https://img.shields.io/badge/AI-Anomaly%20Detection-green)
# AI SOC Detection System


An AI-powered Security Operations Center (SOC) simulation platform that detects suspicious behavior, analyzes security events, and generates professional incident reports.

This project simulates real-world SOC monitoring environments by combining attack simulation, anomaly detection, threat intelligence, and automated reporting.

---

## Key Features

- Real-time security event monitoring
- AI-based anomaly detection engine
- Brute-force login attack detection
- File integrity monitoring
- Ransomware behavior simulation
- Threat intelligence integration
- Automated SOC incident report generation
- Interactive SOC dashboard

---

## Project Architecture

AI SOC Detection System includes multiple security modules:

File Monitoring Engine  
Detects file creation, modification, and deletion events.

Detection Engine  
Analyzes security events and detects suspicious activity.

AI Anomaly Detection  
Uses behavior analysis to identify abnormal activity patterns.

Threat Intelligence Module  
Checks IP reputation and file hash reputation.

Attack Simulator  
Simulates security attacks such as brute force and ransomware behavior.

SOC Dashboard  
Visual interface for monitoring alerts, security events, and AI threat analysis.

Incident Report Generator  
Automatically generates professional SOC investigation reports.

---

## Technologies Used

Python  
Flask  
JavaScript  
HTML / CSS  
Security Event Logging  
Threat Intelligence APIs  
AI-based Behavioral Analysis

---

## Project Structure

```
ai-soc-detection-system
│
├── backend
│   ├── app.py
│   ├── log_parser.py
│   └── templates
│       └── dashboard.html
│
├── modules
│   ├── detection_engine
│   ├── threat_intelligence
│   ├── file_monitor
│   └── reporting
│
├── models
│   └── anomaly_model.py
│
├── utils
│   └── hash_utils.py
│
├── logs
├── reports
├── data
│
├── brute_force_simulator.py
├── lab_simulator.py
├── main.py
└── requirements.txt
```

## Dashboard Capabilities

The SOC dashboard provides:

- Real-time security event monitoring
- Alert severity distribution
- AI threat detection summary
- Event rate monitoring
- Alert timelines
- Top attack categories

---

## Example Detected Attacks

Brute Force Login Attempts  
Mass File Modification  
Mass File Deletion  
Ransomware-style File Encryption

---

## SOC Incident Report Generation

The system automatically generates structured incident reports including:

Incident summary  
Threat classification  
Severity assessment  
AI explanation of behavior  
Evidence logs  
Recommended response actions

Example output:

---

## Dashboard Capabilities

The SOC dashboard provides:

- Real-time security event monitoring
- Alert severity distribution
- AI threat detection summary
- Event rate monitoring
- Alert timelines
- Top attack categories

---

## Example Detected Attacks

Brute Force Login Attempts  
Mass File Modification  
Mass File Deletion  
Ransomware-style File Encryption

---

## SOC Incident Report Generation

The system automatically generates structured incident reports including:

Incident summary  
Threat classification  
Severity assessment  
AI explanation of behavior  
Evidence logs  
Recommended response actions

Example output:
SOC INCIDENT REPORT

Threat Type : Brute Force Login Attempt
Severity : HIGH
Confidence : LOW
Recommended Action : Investigate suspicious login activity


---

## How to Run the Project

Install dependencies
pip install -r requirements.txt


Run the backend server
python backend/app.py


Open dashboard
http://127.0.0.1:5000/dashboard


---

## Future Improvements

Attack replay simulation  
Advanced AI behavioral models  
User authentication monitoring  
Integration with SIEM systems  
Cloud deployment

---

## Author

Vaibhav Kant Nawani

Cybersecurity Enthusiast focused on SOC automation, AI-driven threat detection, and security analytics.
