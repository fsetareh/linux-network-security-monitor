from config import SUSPICIOUS_PORTS, BLACKLISTED_IPS, SUSPICIOUS_PROCESSES


COUNTRY_MAP = {
    "185.220.101.45": "Germany",
    "91.200.12.77": "Russia",
    "45.133.1.1": "Unknown",
}


def is_suspicious_process(process_name):
    process_name = process_name.lower()

    for suspicious_process in SUSPICIOUS_PROCESSES:
        if suspicious_process in process_name:
            return True

    return False


def calculate_ml_threat_score(local_port, remote_ip, external, process_name):
    score = 0

    if local_port in SUSPICIOUS_PORTS:
        score += 25

    if remote_ip in BLACKLISTED_IPS:
        score += 35

    if external:
        score += 15

    if is_suspicious_process(process_name):
        score += 25

    return min(score, 100)


def classify_severity(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def detect_suspicious_activity(local_port, remote_ip, external, process_name):
    alerts = []

    if local_port in SUSPICIOUS_PORTS:
        alerts.append(f"Suspicious port detected: {local_port}")

    if remote_ip in BLACKLISTED_IPS:
        alerts.append(f"Blacklisted IP detected: {remote_ip}")

    if external:
        alerts.append("External network connection detected")

    if is_suspicious_process(process_name):
        alerts.append(f"Suspicious process detected: {process_name}")

    score = calculate_ml_threat_score(local_port, remote_ip, external, process_name)
    severity = classify_severity(score)

    country = COUNTRY_MAP.get(remote_ip, "Unknown")

    return alerts, score, severity, country