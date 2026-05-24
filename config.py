MONITOR_INTERVAL = 5

SUSPICIOUS_PORTS = [
    21,
    22,
    23,
    25,
    53,
    135,
    139,
    445,
    3389,
    4444,
    5555,
    8080
]

BLACKLISTED_IPS = [
    "185.220.101.45",
    "91.200.12.77",
    "45.133.1.1"
]

SUSPICIOUS_PROCESSES = [
    "nmap",
    "wireshark",
    "metasploit",
    "nc",
    "netcat",
    "hydra",
    "powershell",
    "cmd"
]

REPORT_HTML = "reports/dashboard.html"

REPORT_JSON = "reports/network_report.json"

REPORT_TXT = "reports/network_report.txt"

NETWORK_LOG = "logs/network_logs.txt"

EMAIL_ALERT_LOG = "logs/email_alerts_simulated.txt"