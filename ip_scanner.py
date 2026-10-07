"""Reusable scan and export operations for IP Scanner."""

import csv
import ipaddress
import re
import queue
import os
import shlex
import socket
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from pathlib import Path
from shutil import which


CSV_FIELDS = (
    "ip",
    "hostname",
    "protocol",
    "port",
    "state",
    "service",
    "product",
    "version",
    "os",
)
HOST_FIELDS = (
    "ip", "hostname", "status", "reason", "open_ports", "protocols",
    "os", "os_accuracy",
)

SCAN_PROFILES = {
    "Quick": {
        "tcp_scan": "connect",
        "ports": "22,53,80,443,445,3389,8080,8443",
        "service_detection": False,
        "os_detection": False,
        "default_scripts": False,
        "timing": "4",
        "show_all_ports": False,
    },
    "Standard": {
        "tcp_scan": "default",
        "ports": "",
        "service_detection": True,
        "os_detection": False,
        "default_scripts": False,
        "timing": "default",
        "show_all_ports": False,
    },
    "Thorough": {
        "tcp_scan": "syn",
        "ports": "1-65535",
        "service_detection": True,
        "os_detection": True,
        "default_scripts": False,
        "timing": "3",
        "show_all_ports": False,
    },
}

_PROGRESS_PATTERN = re.compile(r"(?P<percent>\d+(?:\.\d+)?)%\s+done", re.IGNORECASE)


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
            "Nmap was not found. Install Nmap, then restart IP Scanner so it "
            "can find Nmap on your system PATH."
        ) from exc


def find_nmap():
    """Return the Nmap executable path or a user-facing installation hint."""
    executable = which("nmap")
    if executable:
        return executable
    if sys.platform == "darwin":
        candidates = ("/opt/homebrew/bin/nmap", "/usr/local/bin/nmap", "/usr/bin/nmap")
    elif os.name == "nt":
        program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")
        candidates = (
            str(Path(program_files) / "Nmap" / "nmap.exe"),
            str(Path(program_files_x86) / "Nmap" / "nmap.exe"),
        )
    else:
        candidates = ("/usr/bin/nmap", "/usr/local/bin/nmap")
    for candidate in candidates:
        if Path(candidate).is_file():
            return candidate
    raise RuntimeError(
        "Nmap is not installed or is missing from PATH. Install Nmap and "
        "restart IP Scanner. On macOS with Homebrew, run `brew install nmap`; "
        "on Windows, install it from https://nmap.org/download.html and "
        "include Nmap in PATH."
    )


def nmap_version(executable=None):
    """Run Nmap's version check and return its first output line."""
    executable = executable or find_nmap()
    try:
        completed = subprocess.run(
            [executable, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"Could not start Nmap: {exc}") from exc
    output = completed.stdout or completed.stderr
    if completed.returncode != 0 or not output.strip():
        raise RuntimeError(f"Nmap version check failed: {output.strip() or 'no output'}")
    return output.splitlines()[0].strip()


def build_nmap_command(target, arguments, assume_up=False, executable=None):
    """Build the exact argument vector used for one whole-network Nmap scan."""
    executable = executable or find_nmap()
    try:
        scan_arguments = shlex.split(arguments)
    except ValueError as exc:
        raise ValueError(f"Invalid Nmap arguments: {exc}") from exc
    command = [executable, *scan_arguments]
    if assume_up and "-Pn" not in scan_arguments:
        command.append("-Pn")
    command.extend(("--stats-every", "1s", "-oX", "-", target))
    return command


def format_nmap_command(command):
    """Format a command for review using the current platform's quoting rules."""
    if os.name == "nt":
        return subprocess.list2cmdline(command)
    return shlex.join(command)


def parse_nmap_host(element):
    """Convert one completed Nmap XML host element to inventory and port rows."""
    addresses = element.findall("address")
    address = next(
        (item.get("addr") for item in addresses if item.get("addrtype") in ("ipv4", "ipv6")),
        None,
    )
    if not address:
        return None

    hostname = next(
        (item.get("name", "") for item in element.findall("./hostnames/hostname")),
        "",
    )
    host_state = element.find("status")
    status = host_state.get("state", "unknown") if host_state is not None else "unknown"
    reason = host_state.get("reason", "") if host_state is not None else ""
    inventory = {
        "ip": address,
        "hostname": hostname,
        "status": status,
        "reason": reason,
        "open_ports": 0,
        "protocols": "",
        "os": "",
        "os_accuracy": "",
    }
    os_match = element.find("./os/osmatch")
    if os_match is not None:
        inventory["os"] = os_match.get("name", "")
        inventory["os_accuracy"] = os_match.get("accuracy", "")
    records = []
    protocols = set()
    for port_element in element.findall("./ports/port"):
        state_element = port_element.find("state")
        port_state = (
            state_element.get("state", "unknown")
            if state_element is not None else "unknown"
        )
        port_id = int(port_element.get("portid", "0"))
        protocol = port_element.get("protocol", "unknown")
        service = port_element.find("service")
        record = {
            "ip": address,
            "hostname": hostname,
            "protocol": protocol,
            "port": port_id,
            "state": port_state,
            "service": service.get("name", "unknown") if service is not None else "unknown",
            "product": service.get("product", "") if service is not None else "",
            "version": service.get("version", "") if service is not None else "",
            "os": inventory["os"],
        }
        records.append(record)
        if port_state == "open":
            inventory["open_ports"] += 1
            protocols.add(protocol)
    inventory["protocols"] = ",".join(sorted(protocols))
    return inventory, records


def _read_pipe(pipe, event_name, events):
    try:
        if event_name == "stdout":
            while True:
                chunk = pipe.read1(4096)
                if not chunk:
                    break
                events.put((event_name, chunk))
        else:
            for line in iter(pipe.readline, b""):
                events.put((event_name, line.decode(errors="replace").strip()))
    finally:
        events.put((f"{event_name}_eof", None))


def run_nmap_scan(
    target,
    arguments,
    *,
    assume_up=False,
    executable=None,
    cancel_event=None,
    on_host=None,
    on_host_hint=None,
    on_progress=None,
):
    """Run one Nmap process and stream each host and progress update as it completes."""
    command = build_nmap_command(
        target, arguments, assume_up=assume_up, executable=executable,
    )
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=4096,
        )
    except OSError as exc:
        raise RuntimeError(f"Could not launch Nmap: {exc}") from exc

    events = queue.Queue()
    readers = [
        threading.Thread(
            target=_read_pipe, args=(process.stdout, "stdout", events), daemon=True,
        ),
        threading.Thread(
            target=_read_pipe, args=(process.stderr, "stderr", events), daemon=True,
        ),
    ]
    for reader in readers:
        reader.start()

    parser = ET.XMLPullParser(events=("start", "end"))
    element_stack = []
    stdout_eof = False
    stderr_eof = False
    stderr_lines = []
    percent = 0
    cancelled = False
    termination_sent = False
    host_hints = {}
    seen_addresses = set()
    try:
        while not (stdout_eof and stderr_eof):
            if (
                cancel_event and cancel_event.is_set()
                and process.poll() is None and not termination_sent
            ):
                cancelled = True
                termination_sent = True
                process.terminate()

            try:
                event, payload = events.get(timeout=0.2)
            except queue.Empty:
                if process.poll() is not None and stdout_eof and stderr_eof:
                    break
                continue

            if event == "stdout":
                parser.feed(payload.decode("utf-8", errors="replace"))
                for xml_event, element in parser.read_events():
                    if xml_event == "start":
                        element_stack.append(element)
                        continue

                    if element.tag == "hosthint":
                        parsed = parse_nmap_host(element)
                        if parsed:
                            inventory, records = parsed
                            host_hints[inventory["ip"]] = inventory
                            seen_addresses.add(inventory["ip"])
                            if on_host_hint:
                                on_host_hint(inventory)
                    elif element.tag == "host":
                        parsed = parse_nmap_host(element)
                        if parsed:
                            inventory, records = parsed
                            seen_addresses.add(inventory["ip"])
                            host_hints.pop(inventory["ip"], None)
                            if on_host:
                                on_host(inventory, records)

                    if element.tag in {"host", "hosthint"}:
                        if len(element_stack) > 1:
                            element_stack[-2].remove(element)
                        element.clear()
                    element_stack.pop()
            elif event == "stderr":
                stderr_lines.append(payload)
                del stderr_lines[:-20]
                match = _PROGRESS_PATTERN.search(payload)
                if match:
                    percent = max(percent, min(100, int(float(match.group("percent")))))
                    if on_progress:
                        on_progress(percent, payload)
                elif payload and on_progress:
                    on_progress(None, payload)
            elif event == "stdout_eof":
                stdout_eof = True
            elif event == "stderr_eof":
                stderr_eof = True

        xml_error = None
        try:
            parser.close()
        except ET.ParseError as exc:
            if not cancelled:
                xml_error = exc

        try:
            return_code = process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            return_code = process.wait()
        if cancelled:
            for inventory in host_hints.values():
                inventory["status"] = "cancelled"
                if on_host:
                    on_host(inventory, [])
            return "cancelled"
        if return_code != 0:
            for inventory in host_hints.values():
                inventory["status"] = "scan failed"
                if on_host:
                    on_host(inventory, [])
            raise RuntimeError(
                f"Nmap exited with code {return_code}: "
                f"{' | '.join(stderr_lines) or 'see Nmap output'}"
            )
        if xml_error:
            raise RuntimeError(
                f"Nmap returned invalid or incomplete XML: {xml_error}"
            ) from xml_error
        for inventory in host_hints.values():
            if on_host:
                on_host(inventory, [])
        if not seen_addresses:
            return "empty"
        if on_progress:
            on_progress(100, "Scan complete")
        return "complete"
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for pipe in (process.stdout, process.stderr):
            if pipe:
                pipe.close()
        for reader in readers:
            reader.join(timeout=1)


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
        "--stats-every",
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


def export_hosts(path, hosts):
    """Write the host inventory, including discovered hosts without open ports."""
    output_path = Path(path)
    with output_path.open("w", newline="", encoding="utf-8") as output:
        writer = csv.DictWriter(output, fieldnames=HOST_FIELDS)
        writer.writeheader()
        writer.writerows(hosts)
    return output_path
