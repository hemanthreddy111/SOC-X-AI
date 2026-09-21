from collections import Counter
from datetime import datetime, timedelta, timezone

MITRE = {
    "BRUTE_FORCE_SUCCESS": ("T1110", "Brute Force"),
    "SUSPICIOUS_POWERSHELL": ("T1059.001", "PowerShell"),
    "PORT_SCAN": ("T1046", "Network Service Scanning"),
    "DNS_ANOMALY": ("T1071.004", "DNS"),
    "PRIVILEGE_CHANGE": ("T1098", "Account Manipulation"),
}

def severity(score: int) -> str:
    if score >= 80: return "Critical"
    if score >= 60: return "High"
    if score >= 30: return "Medium"
    return "Low"

def detect(events):
    alerts = []
    failed = Counter()
    successes = {}
    for e in events:
        if e.event_type in ("login_failed", "4625"):
            failed[(e.source_ip, e.username)] += 1
        if e.event_type in ("login_success", "4624"):
            successes[(e.source_ip, e.username)] = e
    for (ip, user), count in failed.items():
        if count >= 5 and (ip, user) in successes:
            score = 50 + min(count * 2, 30)
            alerts.append({
                "rule": "BRUTE_FORCE_SUCCESS",
                "title": "Possible brute-force followed by successful login",
                "score": score, "severity": severity(score),
                "source_ip": ip, "username": user,
                "mitre_technique": "T1110", "mitre_name": "Brute Force",
                "evidence": [f"{count} failed logins", "Successful login from same source"]
            })
    for e in events:
        cmd = (e.command or "").lower()
        proc = (e.process or "").lower()
        if e.event_type == "process_start" and "powershell" in proc and ("-enc" in cmd or "encodedcommand" in cmd):
            score = 75
            alerts.append({
                "rule": "SUSPICIOUS_POWERSHELL", "title": "Suspicious encoded PowerShell execution",
                "score": score, "severity": severity(score),
                "source_ip": e.source_ip, "username": e.username,
                "mitre_technique": "T1059.001", "mitre_name": "PowerShell",
                "evidence": ["PowerShell process observed", "Encoded command indicator"]
            })
    destinations = Counter()
    for e in events:
        if e.event_type in ("connection", "network_connection") and e.source_ip and e.destination_ip:
            destinations[e.source_ip] += 1
    for ip, count in destinations.items():
        if count >= 5:
            score = 65
            alerts.append({
                "rule": "PORT_SCAN", "title": "Possible network service scanning",
                "score": score, "severity": severity(score),
                "source_ip": ip, "username": None,
                "mitre_technique": "T1046", "mitre_name": "Network Service Scanning",
                "evidence": [f"{count} distinct connection events from source"]
            })
    dns_counts = Counter(e.source_ip for e in events if e.event_type == "dns_query" and e.source_ip)
    for ip, count in dns_counts.items():
        if count >= 10:
            score = 60
            alerts.append({
                "rule": "DNS_ANOMALY", "title": "High-volume DNS activity",
                "score": score, "severity": severity(score),
                "source_ip": ip, "username": None,
                "mitre_technique": "T1071.004", "mitre_name": "DNS",
                "evidence": [f"{count} DNS queries in supplied dataset"]
            })
    return alerts
