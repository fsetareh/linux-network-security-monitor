from colorama import Fore
from config import SUSPICIOUS_PORTS, BLACKLISTED_IPS


def detect_suspicious_activity(local_port, remote_ip):

    alerts = []

    if local_port in SUSPICIOUS_PORTS:
        alerts.append(
            Fore.RED +
            f"[ALERT] Suspicious port detected: {local_port}"
        )

    if remote_ip in BLACKLISTED_IPS:
        alerts.append(
            Fore.MAGENTA +
            f"[THREAT] Blacklisted IP detected: {remote_ip}"
        )

    return alerts