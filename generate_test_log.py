import os
import random
from datetime import datetime, timedelta

# Garante que a pasta dataset existe
os.makedirs("dataset", exist_ok=True)

ips = ["1.9.2.28", "222.169.224.226", "217.23.14.61", "188.138.40.166", "88.12.32.208"]
methods = ["GET", "POST", "PUT", "DELETE"]
endpoints = ["/cart/error.do", "/api/v1/products", "/login", "/admin/dashboard", "/checkout"]
statuses = [200, 200, 200, 301, 404, 500]
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "python-requests/2.28.1",
    "curl/7.68.0"
]

start_time = datetime(2026, 8, 13, 10, 0, 0)

with open("dataset/access.log", "w", encoding="utf-8") as f:
    for i in range(500):
        current_time = start_time + timedelta(seconds=i * 2)
        formatted_date = current_time.strftime("%d/%b/%Y:%H:%M:%S +0000")
        ip = random.choice(ips)
        method = random.choice(methods)
        endpoint = random.choice(endpoints)
        status = random.choice(statuses)
        ua = random.choice(user_agents)
        bytes_sent = random.randint(200, 5000)

        log_line = f'{ip} - - [{formatted_date}] "{method} {endpoint} HTTP/1.1" {status} {bytes_sent} "-" "{ua}"\n'
        f.write(log_line)

print("\033[92m[SUCCESS] Archivo dataset/access.log gerado com 500 linhas de teste!\033[0m")