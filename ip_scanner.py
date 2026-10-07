"""Reusable scan and export operations for IP Scanner."""

import csv
import ipaddress
import re
import shlex
import socket
from pathlib import Path


CSV_FIELDS = (
    "ip",
    "hostname",
    "protocol",
    "port",
    "state",
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


def discover_hosts(target, assume_up=False):
    """Return responsive hosts found by Nmap's ping scan."""
    scanner = _port_scanner()
    arguments = "-sn -Pn" if assume_up else "-sn"
    scanner.scan(hosts=target, arguments=arguments)
    return scanner.all_hosts()


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""


def build_scan_arguments(
    *,
    tcp_scan="default",
    scan_udp=False,
    ports="",
    service_detection=True,
    os_detection=False,
    default_scripts=False,
    timing="default",
    show_all_ports=False,
    extra_arguments="",
):
    """Build Nmap arguments from common controls and advanced options."""
    if tcp_scan not in {"default", "syn", "connect", "none"}:
        raise ValueError("Choose a valid TCP scan type.")
    if tcp_scan == "none" and not scan_udp:
        raise ValueError("Select a TCP scan, a UDP scan, or both.")
    if timing not in {"default", "0", "1", "2", "3", "4", "5"}:
        raise ValueError("Choose an Nmap timing template from 0 to 5.")

    arguments = []
    if tcp_scan == "syn":
        arguments.append("-sS")
    elif tcp_scan == "connect":
        arguments.append("-sT")
    if scan_udp:
        arguments.append("-sU")

    if ports.strip():
        port_spec = ports.strip()
        if not re.fullmatch(r"[0-9A-Za-z,:-]+", port_spec):
            raise ValueError("Ports must use Nmap port-list syntax (for example 22,80,443).")
        arguments.extend(("-p", port_spec))
    if service_detection:
        arguments.append("-sV")
    if os_detection:
        arguments.append("-O")
    if default_scripts:
        arguments.append("-sC")
    if timing != "default":
        arguments.append(f"-T{timing}")
    if not show_all_ports:
        arguments.append("--open")

    try:
        extra = shlex.split(extra_arguments)
    except ValueError as exc:
        raise ValueError(f"Invalid advanced Nmap arguments: {exc}") from exc
    managed_options = (
        "-iL", "--exclude", "--excludefile", "-iR",
        "-oA", "-oN", "-oG", "-oS", "-oX", "--append-output", "--resume",
        "--stylesheet",
    )
    if any(
        token == option or token.startswith(option + "=")
        or (
            (option.startswith("-o") or option in {"-iL", "-iR"})
            and token.startswith(option)
        )
        for token in extra
        for option in managed_options
    ):
        raise ValueError(
            "Target-list and output options are managed by IP Scanner and cannot be overridden."
        )
    value_options = {
        "-b", "-D", "-e", "-g", "-p", "-S", "-sI",
        "--data-length", "--decoy", "--dns-servers", "--exclude-ports",
        "--host-timeout", "--interface", "--max-hostgroup", "--max-parallelism",
        "--max-rate", "--max-retries", "--max-scan-delay", "--min-hostgroup",
        "--min-parallelism", "--min-rate", "--min-rtt-timeout",
        "--max-rtt-timeout", "--initial-rtt-timeout", "--ip-options", "--mtu",
        "--proxies", "--scan-delay", "--scanflags", "--script", "--script-args",
        "--script-args-file", "--script-timeout", "--servicedb", "--source-port",
        "--source-ip", "--spoof-mac", "--top-ports", "--ttl",
        "--versiondb", "--version-intensity",
    }
    expects_value = False
    for token in extra:
        if expects_value:
            expects_value = False
            continue
        if not token.startswith("-"):
            raise ValueError(
                "Advanced arguments cannot add targets; enter values after Nmap options."
            )
        expects_value = token in value_options
    if expects_value:
        raise ValueError("An advanced Nmap option is missing its value.")
    arguments.extend(extra)
    return shlex.join(arguments)


def scan_host(ip, arguments="-sV --open"):
    """Return open port and service records for one host."""
    scanner = _port_scanner()
    scanner.scan(hosts=ip, arguments=arguments)
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
                "state": service.get("state", "unknown"),
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
