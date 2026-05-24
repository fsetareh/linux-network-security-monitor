import psutil
import time
import ipaddress
from datetime import datetime
from colorama import Fore, init

from config import MONITOR_INTERVAL, NETWORK_LOG
from detector import detect_suspicious_activity
from reporter import generate_reports

init(autoreset=True)

events = []


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


def get_process_name(pid):
    try:
        if pid is None:
            return "unknown"

        process = psutil.Process(pid)
        return process.name()

    except Exception:
        return "unknown"


def write_log(message):
    with open(NETWORK_LOG, "a", encoding="utf-8") as file:
        file.write(message + "\n")


print(Fore.CYAN + "\n=== Linux Network Security Monitor V14 ===")
print(Fore.CYAN + "Real-time monitoring started...")
print(Fore.CYAN + "HTML dashboard auto-refresh enabled.")
print(Fore.CYAN + "Press Ctrl + C to stop.\n")


while True:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        connections = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        print(Fore.RED + "Access denied.")
        connections = []

    print(Fore.YELLOW + "\n=== ACTIVE CONNECTIONS ===\n")

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
            process_name = get_process_name(conn.pid)

            external = remote_ip != "N/A" and is_external_ip(remote_ip)

            alerts, ml_score, severity, country = detect_suspicious_activity(
                local_port,
                remote_ip,
                external,
                process_name
            )

            event = {
                "timestamp": timestamp,
                "local": f"{local_ip}:{local_port}",
                "remote": f"{remote_ip}:{remote_port}",
                "status": status,
                "process": process_name,
                "external": external,
                "country": country,
                "alerts": alerts,
                "ml_score": ml_score,
                "severity": severity
            }

            events.append(event)

            color = Fore.GREEN

            if severity in ["HIGH", "CRITICAL"]:
                color = Fore.RED
            elif severity == "MEDIUM":
                color = Fore.YELLOW
            elif external:
                color = Fore.CYAN

            message = (
                f"[{timestamp}] "
                f"{event['local']} -> {event['remote']} | "
                f"STATUS: {status} | "
                f"PROCESS: {process_name} | "
                f"SEVERITY: {severity} | "
                f"ML SCORE: {ml_score}"
            )

            print(color + message)
            write_log(message)

            for alert in alerts:
                print(Fore.RED + f"[ALERT] {alert}")
                write_log(f"[{timestamp}] [ALERT] {alert}")

        except Exception:
            continue

    generate_reports(events[-200:])

    print(Fore.CYAN + "\n=== Scan Summary ===")
    print(Fore.CYAN + f"Connections checked: {len(connections)}")
    print(Fore.CYAN + f"Events stored: {len(events)}")
    print(Fore.CYAN + "Dashboard updated: reports/dashboard.html")
    print(Fore.CYAN + "Reports updated.\n")

    time.sleep(MONITOR_INTERVAL)