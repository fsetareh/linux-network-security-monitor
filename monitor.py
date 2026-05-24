import psutil
import time
import ipaddress

from colorama import Fore, init

from config import MONITOR_INTERVAL
from detector import detect_suspicious_activity

init(autoreset=True)


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


print(Fore.CYAN + "\n=== Linux Network Security Monitor V4 ===")
print(Fore.CYAN + "Monitoring active network traffic...")
print(Fore.CYAN + "Detecting suspicious connections...\n")


while True:

    print(Fore.YELLOW + "\n=== ACTIVE CONNECTIONS ===\n")

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

            print(
                color +
                f"LOCAL: {local_ip}:{local_port} | "
                f"REMOTE: {remote_ip}:{remote_port} | "
                f"STATUS: {status}"
            )

            for alert in alerts:
                print(alert)

        except Exception:
            continue

    print(Fore.CYAN + "\n=== Scan Summary ===")
    print(Fore.CYAN + f"Connections checked: {len(connections)}")
    print(Fore.CYAN + f"External connections: {external_count}")
    print(Fore.RED + f"Suspicious connections: {suspicious_count}")

    time.sleep(MONITOR_INTERVAL) 