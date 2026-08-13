<div align="center">

# 🔍 LogHunter

**An ultra-fast, lightweight CLI log analysis and extraction tool built in pure Python.**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](#-key-features)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](#)

</div>

> LogHunter is designed for Incident Responders, SysAdmins, and DevOps engineers who need to inspect, parse, and summarize gigabyte-sized log files instantly on high-end servers or resource-constrained environments.

---

## 🎨 Preview

```text
               .-+...-+#+-.
             ###+-###+---. +#.
          .#############+.   ++
           +#+.---+#####+. -+ .+
                   #-   +##- + -.
                   ++.  -#+-++.--
                   -#+   ##. #+#.
                   -+    +#- +#+
                   +-    ##. ##
                   -    +#+ .#.
                  +    +#+ .#
                 +    +#+ .+
                -   .+#+ +      -+++-
               .+   .+###    .++.
              --   .###.    .#+
             --   .##+      .##-
             ..    +#+        .###++-
             + .--+##+           -+########+.
       -+-+-#-....+###--+.#++++-.      -#####--#-
     #-   +###-   +# +####+#-.#. +..##.   .##++###+
    +#- --###+     ##++############. .+#   .##+---++
    -##--+ -.+.    .#+--####-  .+##+.-+#+-+###- +-++
      +###+++##. .   ###++#+-++###+##+#++# -+ ++.##
         -+######-.   -+###+##+#- -+  +..#--#-##+.
                  ++. -. -####################-
                      .-+-.+-  .-+#++++--.

  _                _   _             _
 | |    ___   __ _| | | |_   _ _ __ | |_ ___ _ __
 | |   / _ \ / _` | |_| | | | | '_ \| __/ _ \ '__|
 | |__| (_) | (_| |  _  | |_| | | | | ||  __/ |
 |_____\___/ \__, |_| |_|\__,_|_| |_|\__\___|_|
             |___/
```

### Example Output

```text
[*] Mode: Default Standard Scan
[*] Scanning target: dataset/access.log (Limited to first 1000 lines)

[+] Log Format Detected: Web Server Log (Nginx/Apache)
    [RANGE] 13/Aug/2026:10:00:00  ->  13/Aug/2026:10:16:38

[+] Potential IPs Found (Top 5):
    [IP] 188.138.40.166 (118 occurrences)
    [IP] 1.9.2.28 (99 occurrences)

[+] Traffic & Endpoints:
    [METHODS] GET: 130 | DELETE: 100 | PUT: 133 | POST: 137
    [TOP ENDPOINTS]
        -> /checkout (115x)
        -> /admin/dashboard (108x)

[+] HTTP Status Code Distribution:
    [HTTP 200] -> 245 requests
    [HTTP 404] -> 87 requests
    [HTTP 500] -> 87 requests

[!] High Occurrence Warnings/Errors:
    [MSG] (1x) 188.138.40.166 - - [13/Aug/2026:10:00:12 +0000] "GET /login HTTP/1.1" 500...
```

---

## ✨ Key Features

- ⚡ **Zero External Dependencies**  
  Built 100% with standard Python libraries. No `pip install` bloat required.

- 🚀 **Memory Efficient — Lazy Stream Loading**  
  Uses Python generators (`yield`) to process logs line-by-line, keeping memory usage minimal regardless of file size.

- 📦 **Transparent `.gz` Support**  
  Natively decompresses and analyzes `.gz` / `.log.gz` archives on the fly.

- 🧩 **Smart Format Detection**  
  Auto-detects Nginx/Apache, Syslog, and JSON log structures.

- 📊 **Comprehensive Metrics Extraction**
  - **Network:** Top origin IP addresses (IPv4/IPv6).
  - **Web Activity:** HTTP methods (`GET`, `POST`, etc.), top requested endpoints, and User-Agents to help spot bots/scanners.
  - **Diagnostics:** HTTP status code distribution (`2xx`, `3xx`, `4xx`, `5xx`) and log levels (`INFO`, `WARN`, `ERROR`).
  - **Time Range:** First and last timestamp boundary detection.

- 📄 **Structured Output Exporting**  
  Export complete analysis reports to structured `.json` or `.csv` files.

---

## 🛠️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/your-username/loghunter.git
cd loghunter
```

### 2. Optional: Make the script executable system-wide

```bash
chmod +x loghunter.py
sudo ln -s "$(pwd)/loghunter.py" /usr/local/bin/loghunter
```

---

## 🚀 Usage & Examples

### 1. Standard Default Scan

Run a standard analysis over the target log file:

```bash
python3 loghunter.py dataset/access.log -d
```

### 2. Custom Line Limit

Specify how many lines to inspect. This is useful for instantly previewing massive log files:

```bash
python3 loghunter.py /var/log/nginx/access.log -d -l 5000
```

### 3. Analyze Compressed Logs

Directly scan compressed rotated logs without manual extraction:

```bash
python3 loghunter.py /var/log/syslog.1.gz -d
```

### 4. Export Reports

Save scan results into a formatted `.json` or `.csv` report for documentation or SIEM integration:

```bash
# Export to JSON
python3 loghunter.py dataset/access.log -d -o report.json

# Export to CSV
python3 loghunter.py dataset/access.log -d -o report.csv
```

---

## ⚙️ CLI Options Reference

| Option | Short | Type | Description |
|---|---|---|---|
| `file` | — | string | **Required.** Path to the target log file (`.log`, `.txt`, `.gz`). |
| `--default` | `-d` | flag | Executes standard full log analysis mode. |
| `--limit` | `-l` | int | Maximum number of lines to scan. Default: `1000`. |
| `--output` | `-o` | string | Exports results to the target filepath (`.json` or `.csv`). |
| `--help` | `-h` | flag | Displays CLI argument documentation. |

---

## 📂 Project Architecture

```text
loghunter/
│
├── ascii/
│   └── ascii.py              # Terminal banner & ASCII styling
│
├── core/
│   ├── reader.py             # Stream reading generator (.log & .gz)
│   ├── parser.py             # High-speed Regex & metric extraction logic
│   └── exporter.py           # JSON & CSV export functionality
│
├── dataset->test/                  # Sample logs directory for testing
│   └── access.log
│
├── loghunter.py               # Main CLI entry point
├── generate_test_log.py       # Utility script to generate mock log data
├── .gitignore
├── LICENSE
└── README.md
```

---

## 🤝 Contributing

Contributions are welcome!

Feel free to open an **Issue** or submit a **Pull Request** for:

- Performance improvements
- New regex parsers
- UI enhancements
- Additional log format support

### Contribution Workflow

```bash
# Fork the project

# Create your feature branch
git checkout -b feature/NewFeature

# Commit your changes
git commit -m "Add NewFeature"

# Push to the branch
git push origin feature/NewFeature
```

Then open a Pull Request.

---

## 📜 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
