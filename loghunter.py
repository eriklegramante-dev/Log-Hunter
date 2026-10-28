import sys
import argparse
from ascii.ascii import show_banner
from core.reader import read_log_stream
from core.parser import analyze_logs
from core.exporter import export_results

GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"
BOLD = "\033[1m"

def main():
    parser = argparse.ArgumentParser(
        description="LogHunter - Fast log analysis tool for terminal",
        usage="%(prog)s [file|-] [options]"
    )
    parser.add_argument("file", nargs="?", default=None, help="Path to log file or '-' for STDIN")
    parser.add_argument("-d", "--default", action="store_true", help="Run standard default analysis")
    parser.add_argument("-l", "--limit", type=int, default=1000, help="Limit number of lines analyzed (Default: 1000)")
    parser.add_argument("-o", "--output", type=str, help="Export results to file (.json or .csv)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Disable banner (useful for Unix scripts)")
    
    parser.add_argument("--ip", type=str, help="Filter lines by specific IP address")
    parser.add_argument("--status", type=str, help="Filter lines by HTTP status code (e.g., 500, 404)")
    parser.add_argument("--grep", type=str, help="Filter lines by keyword/string")
    
    args = parser.parse_args()

    if args.file is None and sys.stdin.isatty():
        parser.print_help()
        sys.exit(1)

    target_name = "STDIN (Pipeline)" if (args.file in [None, "-"] and not sys.stdin.isatty()) else args.file

    if not args.quiet:
        show_banner()

    mode_str = "Default Standard Scan" if args.default else "Quick Scan"
    print(f"{YELLOW}[*]{RESET} Mode: {CYAN}{mode_str}{RESET}")
    print(f"{YELLOW}[*]{RESET} Scanning target: {BOLD}{target_name}{RESET} (Limited to {args.limit} lines)")
    
    active_filters = []
    if args.ip: active_filters.append(f"IP={args.ip}")
    if args.status: active_filters.append(f"Status={args.status}")
    if args.grep: active_filters.append(f"Grep='{args.grep}'")
    if active_filters:
        print(f"{YELLOW}[*]{RESET} Active Filters: {CYAN}{', '.join(active_filters)}{RESET}")
    print("")

    log_stream = read_log_stream(args.file, max_lines=args.limit)
    results = analyze_logs(
        log_stream,
        filter_ip=args.ip,
        filter_status=args.status,
        filter_grep=args.grep
    )

    print(f"{GREEN}[+]{RESET} Log Format Detected: {BOLD}{results['format']}{RESET} ({results['processed_lines']} lines matched)")
    print(f"    [RANGE] {results['start_date']}  ->  {results['end_date']}")

    if results["log_levels"]:
        levels_str = " | ".join([f"{lvl}: {count}" for lvl, count in results["log_levels"].items()])
        print(f"    [LEVELS] {levels_str}")

    print(f"\n{GREEN}[+]{RESET} Potential IPs Found (Top 5):")
    if results["top_ips"]:
        for ip, count, ip_type in results["top_ips"]:
            type_color = CYAN if ip_type == "Private" else YELLOW
            print(f"    [IP] {ip} ({count} occurrences) {type_color}[{ip_type}]{RESET}")
    else:
        print("    No IP addresses identified.")

    if results["methods"] or results["top_endpoints"]:
        print(f"\n{GREEN}[+]{RESET} Traffic & Endpoints:")
        if results["methods"]:
            methods_str = " | ".join([f"{m}: {c}" for m, c in results["methods"].items()])
            print(f"    [METHODS] {methods_str}")
        if results["top_endpoints"]:
            print(f"    [TOP ENDPOINTS]")
            for ep, count in results["top_endpoints"]:
                print(f"        -> {ep} ({count}x)")

    if results["status_codes"]:
        print(f"\n{GREEN}[+]{RESET} HTTP Status Code Distribution:")
        for code, count in sorted(results["status_codes"].items()):
            color = GREEN if code.startswith('2') else (YELLOW if code.startswith('3') else RED)
            print(f"    {color}[HTTP {code}]{RESET} -> {count} requests")

    if results["top_user_agents"]:
        print(f"\n{GREEN}[+]{RESET} Top User-Agents Detected:")
        for ua, count in results["top_user_agents"]:
            print(f"    [UA] {ua[:70]}... ({count}x)")

    if results["threats"]:
        print(f"\n{MAGENTA}[!] Suspicious Activity / Threats Detected:{RESET}")
        for threat, count in results["threats"].items():
            print(f"    {RED}[ALERT]{RESET} {threat}: {count} event(s) detected")

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