import csv
import ipaddress
import socket
import nmap

from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_THREADS = 20
OUTPUT_FILE = "scan_results.csv"


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def discover_hosts(target):
    """
    Ping sweep using Nmap.
    Supports CIDR or single IP.
    """
    scanner = nmap.PortScanner()

    print(f"\n[*] Discovering live hosts in {target}...")

    scanner.scan(
        hosts=target,
        arguments="-sn"
    )

    hosts = scanner.all_hosts()

    print(f"[*] Found {len(hosts)} live hosts\n")

    return hosts


def scan_host(ip):
    """
    Full port scan of discovered host.
    """

    scanner = nmap.PortScanner()

    try:
        scanner.scan(
            hosts=ip,
            arguments="-sV --open"
        )

        hostname = resolve_hostname(ip)

        results = []

        if ip not in scanner.all_hosts():
            return []

        for proto in scanner[ip].all_protocols():

            ports = sorted(scanner[ip][proto].keys())

            for port in ports:

                service = scanner[ip][proto][port].get(
                    "name",
                    "unknown"
                )

                product = scanner[ip][proto][port].get(
                    "product",
                    ""
                )

                version = scanner[ip][proto][port].get(
                    "version",
                    ""
                )

                results.append({
                    "ip": ip,
                    "hostname": hostname,
                    "protocol": proto,
                    "port": port,
                    "service": service,
                    "product": product,
                    "version": version
                })

        return results

    except Exception as e:

        return [{
            "ip": ip,
            "hostname": "",
            "protocol": "",
            "port": "",
            "service": f"ERROR: {e}",
            "product": "",
            "version": ""
        }]


def save_csv(results):
    fields = [
        "ip",
        "hostname",
        "protocol",
        "port",
        "service",
        "product",
        "version"
    ]

    with open(
        OUTPUT_FILE,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields
        )

        writer.writeheader()

        for row in results:
            writer.writerow(row)

    print(f"\n[+] Results exported to {OUTPUT_FILE}")


def build_target():
    print("Target Options")
    print("--------------")
    print("1. CIDR")
    print("2. Start/End IP")

    choice = input("\nSelect option: ").strip()

    if choice == "1":

        cidr = input(
            "Enter CIDR (example: 192.168.1.0/24): "
        ).strip()

        ipaddress.ip_network(cidr)

        return cidr

    elif choice == "2":

        start_ip = input("Start IP: ").strip()
        end_ip = input("End IP: ").strip()

        start = int(ipaddress.IPv4Address(start_ip))
        end = int(ipaddress.IPv4Address(end_ip))

        if start > end:
            raise ValueError(
                "Start IP must be lower than End IP"
            )

        return ",".join([
            str(ipaddress.IPv4Address(ip))
            for ip in range(start, end + 1)
        ])

    raise ValueError("Invalid selection")


def main():

    target = build_target()

    live_hosts = discover_hosts(target)

    if not live_hosts:
        print("No live hosts found.")
        return

    print("[*] Starting port scans...\n")

    scan_results = []

    with ThreadPoolExecutor(
        max_workers=MAX_THREADS
    ) as executor:

        futures = {
            executor.submit(scan_host, ip): ip
            for ip in live_hosts
        }

        with tqdm(
            total=len(futures),
            desc="Scanning Hosts"
        ) as progress:

            for future in as_completed(futures):

                try:
                    results = future.result()

                    scan_results.extend(results)

                except Exception as e:
                    print(f"Error: {e}")

                progress.update(1)

    save_csv(scan_results)

    print(
        f"[+] Scan complete. "
        f"{len(scan_results)} records exported."
    )


if __name__ == "__main__":
    main()
