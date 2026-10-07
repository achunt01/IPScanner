"""Reusable scan and export operations for IP Scanner."""

import csv
import ipaddress
import socket
from pathlib import Path


CSV_FIELDS = (
    "ip",
    "hostname",
    "protocol",
    "port",
    "service",
    "product",
    "version",
)


def build_target(cidr="", start_ip="", end_ip=""):
    """Validate a CIDR or IPv4 range and return an Nmap target string."""
    if cidr:
        return str(ipaddress.ip_network(cidr, strict=False))

    if not start_ip or not end_ip:
        raise ValueError("Enter a CIDR network or both a start and end IP address.")

    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)
    if int(start) > int(end):
        raise ValueError("Start IP must not be greater than end IP.")

    networks = ipaddress.summarize_address_range(start, end)
    return ",".join(str(network) for network in networks)


def _port_scanner():
    try:
        import nmap
    except ImportError as exc:
        raise RuntimeError(
            "The python-nmap package is missing. Install the application "
            "requirements and try again."
        ) from exc

    try:
        return nmap.PortScanner()
    except nmap.PortScannerError as exc:
        raise RuntimeError(
            "Nmap was not found. Install Nmap and make sure it is available "
            "on your system PATH."
        ) from exc


def discover_hosts(target):
    """Return responsive hosts found by Nmap's ping scan."""
    scanner = _port_scanner()
    scanner.scan(hosts=target, arguments="-sn")
    return scanner.all_hosts()


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


def scan_host(ip):
    """Return open port and service records for one host."""
    scanner = _port_scanner()
    scanner.scan(hosts=ip, arguments="-sV --open")
    if ip not in scanner.all_hosts():
        return []

    hostname = resolve_hostname(ip)
    results = []
    for protocol in scanner[ip].all_protocols():
        for port in sorted(scanner[ip][protocol]):
            service = scanner[ip][protocol][port]
            results.append({
                "ip": ip,
                "hostname": hostname,
                "protocol": protocol,
                "port": port,
                "service": service.get("name", "unknown"),
                "product": service.get("product", ""),
                "version": service.get("version", ""),
            })
    return results


def export_results(path, results):
    """Write scan records to a UTF-8 CSV file."""
    output_path = Path(path)
    with output_path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(results)
    return output_path
