import os
import gzip
import json
import random
from datetime import datetime, timedelta

os.makedirs("dataset", exist_ok=True)
base_time = datetime(2026, 8, 17, 9, 0, 0)
ips = ["192.168.1.15", "10.0.0.52", "203.0.113.195", "198.51.100.4", "45.33.32.156"]

# -------------------------------------------------------------
# 1. Nginx/Apache Web Log (dataset/access.log)
# -------------------------------------------------------------
methods = ["GET", "POST", "PUT", "DELETE"]
endpoints = ["/api/v1/users", "/login", "/dashboard", "/checkout", "/health"]
statuses = [200, 200, 200, 302, 401, 404, 500]
user_agents = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "python-requests/2.31.0",
    "curl/7.88.1"
]

with open("dataset/access.log", "w", encoding="utf-8") as f:
    for i in range(300):
        t = base_time + timedelta(seconds=i * 3)
        formatted_date = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(ips)
        m = random.choice(methods)
        ep = random.choice(endpoints)
        st = random.choice(statuses)
        ua = random.choice(user_agents)
        f.write(f'{ip} - - [{formatted_date}] "{m} {ep} HTTP/1.1" {st} {random.randint(100, 4000)} "-" "{ua}"\n')

print("\033[92m[✓] dataset/access.log criado (Nginx/Apache Web Log)\033[0m")

# -------------------------------------------------------------
# 2. Linux Syslog / Auth Log (dataset/syslog.log)
# -------------------------------------------------------------
syslog_events = [
    ("sshd", "Failed password for root from {ip} port 49212 ssh2"),
    ("sshd", "Accepted publickey for ubuntu from {ip} port 51230 ssh2"),
    ("sudo", "ubuntu : TTY=pts/0 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash"),
    ("kernel", "[UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.1 PROTO=TCP SPT=4444 DPT=22"),
    ("cron", "(root) CMD (/usr/local/bin/backup.sh > /dev/null 2>&1)")
]

with open("dataset/syslog.log", "w", encoding="utf-8") as f:
    for i in range(300):
        t = base_time + timedelta(seconds=i * 2)
        formatted_date = t.strftime("%b %d %H:%M:%S")
        ip = random.choice(ips)
        service, template = random.choice(syslog_events)
        msg = template.format(ip=ip)
        f.write(f"{formatted_date} server-prod-01 {service}[{random.randint(1000, 9999)}]: {msg}\n")

print("\033[92m[✓] dataset/syslog.log criado (Linux Syslog/Auth)\033[0m")

# -------------------------------------------------------------
# 3. JSONL Application Log (dataset/app.json)
# -------------------------------------------------------------
levels = ["INFO", "INFO", "WARN", "ERROR", "CRITICAL"]
json_messages = [
    "User authentication success",
    "Database connection pool exhausted",
    "Payment gateway timeout",
    "Order created successfully",
    "Unauthorized API access attempt"
]

with open("dataset/app.json", "w", encoding="utf-8") as f:
    for i in range(300):
        t = base_time + timedelta(seconds=i * 4)
        entry = {
            "timestamp": t.isoformat() + "Z",
            "level": random.choice(levels),
            "service": "order-service",
            "client_ip": random.choice(ips),
            "message": random.choice(json_messages),
            "status_code": random.choice([200, 400, 401, 500, 503])
        }
        f.write(json.dumps(entry) + "\n")

print("\033[92m[✓] dataset/app.json criado (JSON Microservice Log)\033[0m")

# -------------------------------------------------------------
# 4. Rotated Compressed Log (dataset/archive.log.gz)
# -------------------------------------------------------------
with gzip.open("dataset/archive.log.gz", "wt", encoding="utf-8") as f:
    for i in range(500):
        t = base_time + timedelta(seconds=i)
        formatted_date = t.strftime("%d/%b/%Y:%H:%M:%S +0000")
        f.write(f'{random.choice(ips)} - - [{formatted_date}] "GET /archive/data HTTP/1.1" 200 1280 "-" "curl/7.88.1"\n')

print("\033[92m[✓] dataset/archive.log.gz criado (Compressed Gzip Log)\033[0m")