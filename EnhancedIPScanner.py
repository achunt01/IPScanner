"""Command-line interface for IP Scanner."""

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from tqdm import tqdm

from ip_scanner import build_target, discover_hosts, export_results, scan_host


def main():
    parser = argparse.ArgumentParser(description="Discover hosts and open services.")
    parser.add_argument("--output", default="scan_results.csv", help="CSV output path")
    parser.add_argument(
        "--workers", type=int, default=20,
        help="maximum concurrent host scans (default: 20)",
    )
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be at least 1")

    print("Target Options\n--------------\n1. CIDR\n2. Start/End IP")
    choice = input("\nSelect option: ").strip()
    try:
        if choice == "1":
            target = build_target(cidr=input("Enter CIDR: ").strip())
        elif choice == "2":
            target = build_target(
                start_ip=input("Start IP: ").strip(),
                end_ip=input("End IP: ").strip(),
            )
        else:
            raise ValueError("Select 1 for CIDR or 2 for an IP range.")

        print(f"\n[*] Discovering live hosts in {target}...")
        hosts = discover_hosts(target)
    except (ValueError, RuntimeError) as exc:
        parser.exit(2, f"Error: {exc}\n")

    print(f"[*] Found {len(hosts)} live host(s)")
    if not hosts:
        return

    results = []
    print("[*] Starting service scans...")
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(scan_host, host): host for host in hosts}
        for future in tqdm(as_completed(futures), total=len(futures), desc="Scanning hosts"):
            host = futures[future]
            try:
                results.extend(future.result())
            except Exception as exc:
                print(f"\n[!] Failed to scan {host}: {exc}")

    try:
        output = export_results(args.output, results)
    except OSError as exc:
        parser.exit(2, f"Could not write CSV: {exc}\n")
    print(f"[+] Results exported to {output}")
    print(f"[+] Scan complete. {len(results)} record(s) exported.")


if __name__ == "__main__":
    main()
