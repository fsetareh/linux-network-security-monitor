from colorama import Fore

from config import (
    SUSPICIOUS_PORTS,
    BLACKLISTED_IPS,
    SUSPICIOUS_PROCESSES
)


def detect_suspicious_activity(
    local_port,
    remote_ip,
    process_name=None
):

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

    if process_name:

        process_name = process_name.lower()

        if process_name in SUSPICIOUS_PROCESSES:

            alerts.append(
                Fore.YELLOW +
                f"[PROCESS ALERT] Suspicious process detected: {process_name}"
            )

    return alerts