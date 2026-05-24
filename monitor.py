import psutil
import time
import ipaddress
from datetime import datetime

from colorama import Fore, init

from config import MONITOR_INTERVAL
from detector import detect_suspicious_activity

init(autoreset=True)

LOG_FILE = "logs/network_logs.txt"


def is_external_ip(ip):

    try:
        ip_obj = ipaddress.ip_address(ip)

        return not (
            ip_obj.is_private or
            ip_obj.is_loopback or
            ip_obj.is_reserved or
            ip_obj.is_link_local or
            ip_obj.is_multicast
        )

    except Exception:
        return False


def write_log(message):

    with open(LOG_FILE, "a", encoding="utf-8") as file:
        file.write(message + "\n")


print(Fore.CYAN + "\n=== Linux Network Security Monitor V5 ===")
print(Fore.CYAN + "Monitoring active network traffic...")
print(Fore.CYAN + "Logging security events...\n")


while True:

    print(Fore.YELLOW + "\n=== ACTIVE CONNECTIONS ===\n")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        connections = psutil.net_connections(kind="inet")

    except psutil.AccessDenied:
        print(Fore.RED + "Access denied.")
        connections = []

    suspicious_count = 0
    external_count = 0

    for conn in connections[:40]:

        try:
            local_ip = conn.laddr.ip if conn.laddr else "N/A"
            local_port = conn.laddr.port if conn.laddr else "N/A"

            remote_ip = "N/A"
            remote_port = "N/A"

            if conn.raddr:
                remote_ip = conn.raddr.ip
                remote_port = conn.raddr.port

            status = conn.status

            external_connection = (
                remote_ip != "N/A" and
                is_external_ip(remote_ip)
            )

            if external_connection:
                external_count += 1

            alerts = detect_suspicious_activity(
                local_port,
                remote_ip
            )

            if alerts:
                suspicious_count += 1

            color = Fore.GREEN

            if alerts:
                color = Fore.RED

            elif external_connection:
                color = Fore.CYAN

            connection_message = (
                f"[{timestamp}] "
                f"LOCAL: {local_ip}:{local_port} | "
                f"REMOTE: {remote_ip}:{remote_port} | "
                f"STATUS: {status}"
            )

            print(color + connection_message)

            write_log(connection_message)

            for alert in alerts:

                alert_message = (
                    f"[{timestamp}] "
                    f"{alert}"
                )

                print(alert)

                write_log(alert_message)

        except Exception:
            continue

    summary = (
        f"\n[{timestamp}] "
        f"Connections checked: {len(connections)} | "
        f"External: {external_count} | "
        f"Suspicious: {suspicious_count}\n"
    )

    print(Fore.CYAN + "\n=== Scan Summary ===")
    print(Fore.CYAN + f"Connections checked: {len(connections)}")
    print(Fore.CYAN + f"External connections: {external_count}")
    print(Fore.RED + f"Suspicious connections: {suspicious_count}")

    write_log(summary)

    time.sleep(MONITOR_INTERVAL)