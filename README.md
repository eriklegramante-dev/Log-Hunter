# 🔍 LogHunter

LogHunter is a lightweight, high-speed CLI tool written in Python designed to analyze, parse, and extract critical security metrics (IPs, HTTP status codes, timestamps, and error messages) from any log file without consuming heavy RAM.

![LogHunter Terminal]No image yet.

## 🚀 Features

- **Lazy Loading Processing:** Reads files line-by-line (using generators) to handle gigabyte-sized logs seamlessly on low-spec hardware.
- **Transparent `.gz` Support:** Processes compressed logs (`.log.gz`) on the fly.
- **Log Format Auto-Detection:** Identifies Nginx/Apache, Syslog, and JSON formats.
- **Quick Metrics Extraction:** Extracts Top IPs, HTTP Status Code distribution, Time Ranges, and Errors/Warnings.
- **Structured Exporting:** Export scan reports to `.json` or `.csv`.

## 🛠️ Installation & Usage

Clone the repository:
```bash
git clone [https://github.com/eriklegramante-dev/Log-Hunter.git](https://github.com/eriklegramante-dev/Log-Hunter.git)
cd loghunter