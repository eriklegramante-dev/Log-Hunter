import json
import csv
from typing import Dict, Any

def export_results(results: Dict[str, Any], output_path: str):
    """Exports scan results to JSON or CSV format."""
    try:
        if output_path.endswith('.json'):
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=4)
            print(f"\033[92m[+] Results exported to JSON: {output_path}\033[0m")
            
        elif output_path.endswith('.csv'):
            with open(output_path, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Metric", "Value"])
                writer.writerow(["Detected Format", results.get("format")])
                writer.writerow(["Start Date", results.get("start_date")])
                writer.writerow(["End Date", results.get("end_date")])
                writer.writerow(["Top IPs", str(results.get("top_ips"))])
                writer.writerow(["Status Codes", str(results.get("status_codes"))])
            print(f"\033[92m[+] Results exported to CSV: {output_path}\033[0m")
        else:
            print(f"\033[91m[!] Unsupported output format. Use .json or .csv\033[0m")
    except Exception as e:
        print(f"\033[91m[ERROR] Failed to export file: {e}\033[0m")