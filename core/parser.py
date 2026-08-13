import re
import json
from collections import Counter
from typing import Dict, Any, Iterable

IPV4_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
HTTP_STATUS_REGEX = re.compile(r'\s([1-5]\d{2})\s')
HTTP_METHOD_REGEX = re.compile(r'"(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s')
ENDPOINT_REGEX = re.compile(r'"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s\?"]*)')
LOG_LEVEL_REGEX = re.compile(r'\b(DEBUG|INFO|WARN|WARNING|ERROR|CRITICAL|FATAL)\b', re.IGNORECASE)
USER_AGENT_REGEX = re.compile(r'"\s+"([^"]+)"$')
DATE_REGEX = re.compile(
    r'(\d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}|\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}|[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)

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

def analyze_logs(log_lines: Iterable[str]) -> Dict[str, Any]:
    """
    Processes log lines and extracts key metrics.
    """
    ip_counter = Counter()
    status_counter = Counter()
    method_counter = Counter()
    endpoint_counter = Counter()
    level_counter = Counter()
    ua_counter = Counter()
    error_counter = Counter()
    dates_found = []
    detected_format = "Unknown"

    for i, line in enumerate(log_lines):
        if i == 0:
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

        line_lower = line.lower()
        if "fail" in line_lower or "error" in line_lower or "unauthorized" in line_lower or " 500 " in line:
            error_counter[line[:90]] += 1

    return {
        "format": detected_format,
        "top_ips": ip_counter.most_common(5),
        "total_ips_unique": len(ip_counter),
        "status_codes": dict(status_counter),
        "methods": dict(method_counter),
        "top_endpoints": endpoint_counter.most_common(5),
        "log_levels": dict(level_counter),
        "top_user_agents": ua_counter.most_common(3),
        "start_date": dates_found[0] if dates_found else "N/A",
        "end_date": dates_found[-1] if dates_found else "N/A",
        "top_errors": error_counter.most_common(3)
    }