import json
import os
from collections import Counter
from config import REPORT_HTML, REPORT_JSON, REPORT_TXT, EMAIL_ALERT_LOG

os.makedirs("reports", exist_ok=True)
os.makedirs("logs", exist_ok=True)


def generate_reports(events):
    total_events = len(events)
    external_count = len([e for e in events if e["external"]])
    suspicious_count = len([e for e in events if e["alerts"]])
    critical_count = len([e for e in events if e["severity"] == "CRITICAL"])
    high_count = len([e for e in events if e["severity"] == "HIGH"])

    severity_counts = Counter(e["severity"] for e in events)
    country_counts = Counter(e["country"] for e in events)

    summary = {
        "total_events": total_events,
        "external_connections": external_count,
        "suspicious_events": suspicious_count,
        "critical_events": critical_count,
        "high_events": high_count
    }

    with open(REPORT_JSON, "w", encoding="utf-8") as file:
        json.dump(
            {
                "summary": summary,
                "events": events
            },
            file,
            indent=4
        )

    with open(REPORT_TXT, "w", encoding="utf-8") as report:
        report.write("=== Linux Network Security Monitor Report V14 ===\n\n")
        for key, value in summary.items():
            report.write(f"{key}: {value}\n")

        report.write("\n=== Events ===\n\n")

        for event in events:
            report.write(
                f"{event['timestamp']} | "
                f"{event['local']} -> {event['remote']} | "
                f"Process: {event['process']} | "
                f"Severity: {event['severity']} | "
                f"ML Score: {event['ml_score']} | "
                f"Country: {event['country']} | "
                f"Alerts: {', '.join(event['alerts']) if event['alerts'] else 'None'}\n"
            )

    with open(EMAIL_ALERT_LOG, "w", encoding="utf-8") as email_log:
        email_log.write("=== Simulated Email Alerts ===\n\n")

        for event in events:
            if event["severity"] in ["HIGH", "CRITICAL"]:
                email_log.write(
                    f"EMAIL ALERT SIMULATION: {event['severity']} threat detected | "
                    f"{event['local']} -> {event['remote']} | "
                    f"ML Score: {event['ml_score']}\n"
                )

    html = f"""
<!DOCTYPE html>
<html>
<head>
<title>Linux Network Security Monitor V14</title>
<meta http-equiv="refresh" content="5">
<style>
body {{
    font-family: Arial, sans-serif;
    background-color: #111827;
    color: white;
    padding: 20px;
}}
h1, h2 {{
    color: #38bdf8;
}}
.grid {{
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 15px;
    margin-bottom: 25px;
}}
.card {{
    background-color: #1f2937;
    padding: 18px;
    border-radius: 12px;
}}
.card p {{
    font-size: 26px;
    font-weight: bold;
}}
table {{
    width: 100%;
    border-collapse: collapse;
    background-color: #1f2937;
}}
th, td {{
    border: 1px solid #374151;
    padding: 8px;
}}
th {{
    background-color: #0f172a;
}}
.CRITICAL {{
    color: #fb7185;
    font-weight: bold;
}}
.HIGH {{
    color: #f87171;
    font-weight: bold;
}}
.MEDIUM {{
    color: #facc15;
    font-weight: bold;
}}
.LOW {{
    color: #4ade80;
    font-weight: bold;
}}
</style>
</head>
<body>

<h1>Linux Network Security Monitor V14</h1>

<div class="grid">
    <div class="card"><h3>Total Events</h3><p>{total_events}</p></div>
    <div class="card"><h3>External</h3><p>{external_count}</p></div>
    <div class="card"><h3>Suspicious</h3><p>{suspicious_count}</p></div>
    <div class="card"><h3>Critical</h3><p>{critical_count}</p></div>
    <div class="card"><h3>High</h3><p>{high_count}</p></div>
</div>

<h2>Severity Summary</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
"""

    for severity, count in severity_counts.items():
        html += f"""
<tr>
<td class="{severity}">{severity}</td>
<td>{count}</td>
</tr>
"""

    html += """
</table>

<h2>Geo-IP Simulation</h2>
<table>
<tr><th>Country</th><th>Events</th></tr>
"""

    for country, count in country_counts.items():
        html += f"""
<tr>
<td>{country}</td>
<td>{count}</td>
</tr>
"""

    html += """
</table>

<h2>Network Events</h2>
<table>
<tr>
<th>Timestamp</th>
<th>Local</th>
<th>Remote</th>
<th>Status</th>
<th>Process</th>
<th>External</th>
<th>Country</th>
<th>ML Score</th>
<th>Severity</th>
<th>Alerts</th>
</tr>
"""

    for event in events:
        html += f"""
<tr>
<td>{event["timestamp"]}</td>
<td>{event["local"]}</td>
<td>{event["remote"]}</td>
<td>{event["status"]}</td>
<td>{event["process"]}</td>
<td>{event["external"]}</td>
<td>{event["country"]}</td>
<td>{event["ml_score"]}/100</td>
<td class="{event["severity"]}">{event["severity"]}</td>
<td>{", ".join(event["alerts"]) if event["alerts"] else "None"}</td>
</tr>
"""

    html += """
</table>

</body>
</html>
"""

    with open(REPORT_HTML, "w", encoding="utf-8") as file:
        file.write(html)