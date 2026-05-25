# Linux Network Security Monitor V14

A real-time cybersecurity monitoring and threat detection system built with Python.

This project monitors active network connections, detects suspicious behavior, generates alerts, logs security events, and creates a live HTML dashboard for SOC-style monitoring and analysis.

---

## Features

- Real-time network connection monitoring
- Suspicious external IP detection
- Suspicious port detection
- Process monitoring
- Machine Learning threat scoring simulation
- Live security event logging
- Auto-generated HTML dashboard
- JSON and TXT reporting
- Geo-IP simulation
- Severity classification system
- SOC-style terminal alerts
- Auto-refresh dashboard analytics

---

## Technologies Used

- Python 3
- psutil
- HTML/CSS
- JSON
- Cybersecurity event analysis
- Network socket inspection

---

## Project Structure

```bash
linux-network-security-monitor/
│
├── logs/
│   └── network_logs.txt
│
├── reports/
│   └── dashboard.html
│
├── screenshots/
│   ├── dashboard_v14.png
│   └── live_terminal_monitoring.png
│
├── config.py
├── detector.py
├── monitor.py
├── parser.py
├── reporter.py
├── requirements.txt
├── README.md
└── .gitignore
---

# Screenshots

## Dashboard

![Web based security dashboard with dark blue layout showing network threat metrics and alert summaries in a browser style report page. Visible text includes Total Events 200, External 76, Suspicious 86, Critical 0, High 0, the severity summary table listing LOW 200, the geo IP simulation table listing Country Unknown and Events 200, and a network events table with timestamped connections and alerts such as External network connection detected](./screenshots/dashboard_v14.png)

## Live Monitoring

![Terminal screenshot with real time network security alerts on a dark background, showing green and red status lines, repeated alert text including ALERT External network connection detected, and a scan summary at the bottom](screenshots/live_terminal_monitoring.png)