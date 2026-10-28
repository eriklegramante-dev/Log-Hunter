import re
import json
import ipaddress
from collections import Counter
from typing import Dict, Any, Iterable, Optional

IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
HTTP_STATUS_REGEX = re.compile(r'\s([1-5]\d{2})\s')
HTTP_METHOD_REGEX = re.compile(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s')
ENDPOINT_REGEX = re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s\?"]*)')
LOG_LEVEL_REGEX = re.compile(r'\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b', re.IGNORECASE)
USER_AGENT_REGEX = re.compile(r'"\s+"([^"]+)"$')
DATE_REGEX = re.compile(
    r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}|\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)

SUSPICIOUS_PATTERNS = {
    "Path Traversal": re.compile(r'(\.\./|\.\.\\|/etc/passwd|win\.ini)', re.IGNORECASE),
    "SQL Injection": re.compile(r'(\bUNION\b|\bSELECT\b|\bOR\b\s+["\']?1["\']?\s*=\s*["\']?1|\bSLEEP\()', re.IGNORECASE),
    "XSS Injection": re.compile(r'(<script|%3Cscript|alert\(|onerror=)', re.IGNORECASE),
    "Security Scanner": re.compile(r'(sqlmap|nikto|nmap|masscan|gobuster|dirbuster|wpscan)', re.IGNORECASE)
}

def detect_format(sample_line: str) -> str:
    """Detects basic log format from a single line."""
    if sample_line.startswith('{') and sample_line.endswith('}'):
        try:
            json.loads(sample_line)
            return "JSON Format"
        except Exception:
            pass
    if "GET " in sample_line or "POST " in sample_line or "HTTP/" in sample_line:
        return "Web Server Log (Nginx/Apache)"
    if "syslog" in sample_line.lower() or re.match(r'^[A-Za-z]{3}\s+\d{1,2}', sample_line):
        return "Syslog / System Log"
    return "Generic Text Log"

def classify_ip(ip_str: str) -> str:
    """Classifies an IP as Private (LAN) or Public using standard ipaddress library."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return "Private" if ip_obj.is_private else "Public"
    except ValueError:
        return "Invalid"

def analyze_logs(
    log_lines: Iterable[str],
    filter_ip: Optional[str] = None,
    filter_status: Optional[str] = None,
    filter_grep: Optional[str] = None
) -> Dict[str, Any]:
    """
    Processes log lines and extracts metrics, threats, and applied filters.
    """
    ip_counter = Counter()
    status_counter = Counter()
    method_counter = Counter()
    endpoint_counter = Counter()
    level_counter = Counter()
    ua_counter = Counter()
    error_counter = Counter()
    threats_detected = Counter()
    dates_found = []
    detected_format = "Unknown"
    processed_count = 0

    for i, line in enumerate(log_lines):
        if filter_ip and filter_ip not in line:
            continue
        if filter_status and f" {filter_status} " not in line:
            continue
        if filter_grep and filter_grep.lower() not in line.lower():
            continue

        processed_count += 1

        if detected_format == "Unknown":
            detected_format = detect_format(line)

        ips = IPV4_REGEX.findall(line)
        for ip in ips:
            ip_counter[ip] += 1

        statuses = HTTP_STATUS_REGEX.findall(line)
        for code in statuses:
            status_counter[code] += 1

        methods = HTTP_METHOD_REGEX.findall(line)
        for method in methods:
            method_counter[method] += 1

        endpoints = ENDPOINT_REGEX.findall(line)
        for ep in endpoints:
            endpoint_counter[ep] += 1

        levels = LOG_LEVEL_REGEX.findall(line)
        for lvl in levels:
            level_counter[lvl.upper()] += 1

        ua_match = USER_AGENT_REGEX.search(line)
        if ua_match:
            ua_counter[ua_match.group(1)] += 1

        dates = DATE_REGEX.findall(line)
        if dates:
            dates_found.extend(dates)

        for threat_type, threat_regex in SUSPICIOUS_PATTERNS.items():
            if threat_regex.search(line):
                threats_detected[threat_type] += 1

        line_lower = line.lower()
        if "fail" in line_lower or "error" in line_lower or "unauthorized" in line_lower or " 500 " in line:
            error_counter[line[:90]] += 1

    formatted_top_ips = [
        (ip, count, classify_ip(ip))
        for ip, count in ip_counter.most_common(5)
    ]

    return {
        "processed_lines": processed_count,
        "format": detected_format,
        "top_ips": formatted_top_ips,
        "total_ips_unique": len(ip_counter),
        "status_codes": dict(status_counter),
        "methods": dict(method_counter),
        "top_endpoints": endpoint_counter.most_common(5),
        "log_levels": dict(level_counter),
        "top_user_agents": ua_counter.most_common(3),
        "threats": dict(threats_detected),
        "start_date": dates_found[0] if dates_found else "N/A",
        "end_date": dates_found[-1] if dates_found else "N/A",
        "top_errors": error_counter.most_common(3)
    }