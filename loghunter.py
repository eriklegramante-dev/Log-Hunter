import argparse
from ascii.ascii import show_banner
from core.reader import read_log_file
from core.parser import analyze_logs
from core.exporter import export_results

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def main():
    show_banner()

    parser = argparse.ArgumentParser(description="LogHunter - Fast log analysis tool for terminal")
    parser.add_argument("file", help="Path to target log file (.log, .txt, .gz)")
    parser.add_argument("-d", "--default", action="store_true", help="Run standard default analysis (IPs, Status Codes, Errors, Dates)")
    parser.add_argument("-l", "--limit", type=int, default=1000, help="Limit number of lines analyzed (Default: 1000)")
    parser.add_argument("-o", "--output", type=str, help="Export results to file (.json or .csv)")
    
    args = parser.parse_args()

    mode_str = "Default Standard Scan" if args.default else "Quick Scan"
    print(f"{YELLOW}[*]{RESET} Mode: {CYAN}{mode_str}{RESET}")
    print(f"{YELLOW}[*]{RESET} Scanning target: {BOLD}{args.file}{RESET} (Limited to first {args.limit} lines)\n")

    log_stream = read_log_file(args.file, max_lines=args.limit)
    results = analyze_logs(log_stream)

    print(f"{GREEN}[+]{RESET} Log Format Detected: {BOLD}{results['format']}{RESET}")

    print(f"\n{GREEN}[+]{RESET} Potential IPs Found (Top 5):")
    if results["top_ips"]:
        for ip, count in results["top_ips"]:
            print(f"    [IP] {ip} ({count} occurrences)")
    else:
        print("    No IP addresses identified.")

    # Status Codes
    if results["status_codes"]:
        print(f"\n{GREEN}[+]{RESET} HTTP Status Code Distribution:")
        for code, count in sorted(results["status_codes"].items()):
            color = GREEN if code.startswith('2') else (YELLOW if code.startswith('3') else RED)
            print(f"    {color}[HTTP {code}]{RESET} -> {count} requests")

    print(f"\n{GREEN}[+]{RESET} Extracted Time Range:")
    print(f"    [START] {results['start_date']}")
    print(f"    [END]   {results['end_date']}")

    if results["top_errors"]:
        print(f"\n{RED}[!]{RESET} High Occurrence Warnings/Errors:")
        for err, count in results["top_errors"]:
            print(f"    [MSG] ({count}x) {err}...")

    if args.output:
        print("")
        export_results(results, args.output)

    print(f"\n{GREEN}[SUCCESS]{RESET} LogHunter scan complete. Exiting.")

if __name__ == "__main__":
    main()