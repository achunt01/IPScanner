import csv
import io
import queue
import shlex
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import IPScannerApp
from ip_scanner import (
    CSV_FIELDS,
    HOST_FIELDS,
    SCAN_PROFILES,
    build_scan_arguments,
    build_nmap_command,
    build_target,
    discover_hosts,
    export_hosts,
    export_results,
    parse_nmap_host,
    run_nmap_scan,
    scan_host,
)


class BuildTargetTests(unittest.TestCase):
    def test_normalizes_cidr(self):
        self.assertEqual(build_target(cidr="192.168.1.42/24"), "192.168.1.0/24")

    def test_summarizes_inclusive_address_range(self):
        self.assertEqual(
            build_target(start_ip="10.0.0.1", end_ip="10.0.0.4"),
            "10.0.0.1/32,10.0.0.2/31,10.0.0.4/32",
        )

    def test_rejects_reversed_range(self):
        with self.assertRaisesRegex(ValueError, "greater"):
            build_target(start_ip="10.0.0.2", end_ip="10.0.0.1")

    def test_rejects_missing_range_endpoint(self):
        with self.assertRaisesRegex(ValueError, "both"):
            build_target(start_ip="10.0.0.1")


class BuildScanArgumentsTests(unittest.TestCase):
    def test_default_options_preserve_current_scan(self):
        self.assertEqual(
            build_scan_arguments(),
            "-sV --open",
        )

    def test_combines_common_options_and_advanced_values(self):
        arguments = build_scan_arguments(
            tcp_scan="connect",
            scan_udp=True,
            ports="22,80,443",
            service_detection=False,
            os_detection=True,
            default_scripts=True,
            timing="4",
            show_all_ports=True,
            extra_arguments='--script-args user="scan value"',
        )
        self.assertEqual(shlex.split(arguments), [
            "-sT", "-sU", "-p", "22,80,443", "-O", "-sC", "-T4",
            "--script-args", "user=scan value",
        ])

    def test_rejects_missing_scan_mode(self):
        with self.assertRaisesRegex(ValueError, "Select a TCP scan"):
            build_scan_arguments(tcp_scan="none")

    def test_rejects_extra_target(self):
        with self.assertRaisesRegex(ValueError, "cannot add targets"):
            build_scan_arguments(extra_arguments="192.168.1.20")

    def test_rejects_managed_output_options(self):
        with self.assertRaisesRegex(ValueError, "managed"):
            build_scan_arguments(extra_arguments="-oN results.txt")

    def test_rejects_unclosed_advanced_argument_quote(self):
        with self.assertRaisesRegex(ValueError, "Invalid advanced"):
            build_scan_arguments(extra_arguments='"unterminated')

    def test_advanced_option_can_take_a_dash_prefixed_value(self):
        arguments = build_scan_arguments(
            extra_arguments="--script-args=-user=scan",
        )
        self.assertIn("--script-args=-user=scan", shlex.split(arguments))


class NmapCommandTests(unittest.TestCase):
    def test_builds_safe_command_with_target_last(self):
        command = build_nmap_command(
            "192.168.1.0/24", "-sV --open", assume_up=True, executable="/usr/bin/nmap",
        )
        self.assertEqual(command, [
            "/usr/bin/nmap", "-sV", "--open", "-Pn", "--stats-every", "1s",
            "-oX", "-", "192.168.1.0/24",
        ])

    def test_scan_profiles_offer_distinct_tradeoffs(self):
        self.assertEqual(set(SCAN_PROFILES), {"Quick", "Standard", "Thorough"})
        self.assertNotEqual(
            SCAN_PROFILES["Quick"]["ports"],
            SCAN_PROFILES["Thorough"]["ports"],
        )


class NmapXmlTests(unittest.TestCase):
    def test_parses_host_inventory_and_port_services(self):
        xml = """<host>
          <status state="up" reason="arp-response"/>
          <address addr="192.168.1.5" addrtype="ipv4"/>
          <hostnames><hostname name="router.local" type="PTR"/></hostnames>
          <os><osmatch name="Example OS" accuracy="98"/></os>
          <ports>
            <port protocol="tcp" portid="443">
              <state state="open" reason="syn-ack"/>
              <service name="https" product="nginx" version="1.24"/>
            </port>
            <port protocol="tcp" portid="22">
              <state state="closed" reason="reset"/>
              <service name="ssh"/>
            </port>
          </ports>
        </host>"""
        import xml.etree.ElementTree as ET

        inventory, ports = parse_nmap_host(ET.fromstring(xml))
        self.assertEqual(inventory, {
            "ip": "192.168.1.5",
            "hostname": "router.local",
            "status": "up",
            "reason": "arp-response",
            "open_ports": 1,
            "protocols": "tcp",
            "os": "Example OS",
            "os_accuracy": "98",
        })
        self.assertEqual(ports[0]["service"], "https")
        self.assertEqual(ports[0]["product"], "nginx")
        self.assertEqual(ports[1]["state"], "closed")

    def test_scan_process_streams_host_xml_and_progress(self):
        xml = b"""<?xml version="1.0"?>
        <nmaprun><hosthint><status state="up" reason="arp-response"/>
        <address addr="192.168.1.9" addrtype="ipv4"/></hosthint>
        <host><status state="up" reason="arp-response"/>
        <address addr="192.168.1.9" addrtype="ipv4"/>
        <ports><port protocol="tcp" portid="80"><state state="open"/>
        <service name="http"/></port></ports></host></nmaprun>"""
        process = type("FakeProcess", (), {
            "stdout": io.BytesIO(xml),
            "stderr": io.BytesIO(b"About 65.0% done; ETC: 00:01\n"),
            "poll": lambda _self: 0,
            "wait": lambda _self, timeout=None: 0,
            "terminate": lambda _self: None,
            "kill": lambda _self: None,
        })()
        hosts = []
        hints = []
        progress = []
        with patch("ip_scanner.subprocess.Popen", return_value=process) as popen:
            outcome = run_nmap_scan(
                "192.168.1.0/24",
                "-sV --open",
                executable="/usr/bin/nmap",
                on_host=lambda inventory, ports: hosts.append((inventory, ports)),
                on_host_hint=hints.append,
                on_progress=lambda percent, text: progress.append((percent, text)),
            )

        command = popen.call_args.args[0]
        self.assertEqual(command[-3:], ["-oX", "-", "192.168.1.0/24"])
        self.assertEqual(outcome, "complete")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hints[0]["ip"], "192.168.1.9")
        self.assertEqual(hosts[0][0]["ip"], "192.168.1.9")
        self.assertEqual(hosts[0][0]["open_ports"], 1)
        self.assertEqual(hosts[0][1][0]["port"], 80)
        self.assertTrue(any(item[0] == 65 for item in progress))

    def test_host_hint_without_host_element_is_exported_as_zero_open_ports(self):
        xml = b"""<?xml version="1.0"?>
        <nmaprun><hosthint><status state="up" reason="arp-response"/>
        <address addr="192.168.1.9" addrtype="ipv4"/></hosthint></nmaprun>"""
        process = type("FakeProcess", (), {
            "stdout": io.BytesIO(xml),
            "stderr": io.BytesIO(),
            "poll": lambda _self: 0,
            "wait": lambda _self, timeout=None: 0,
            "terminate": lambda _self: None,
            "kill": lambda _self: None,
        })()
        hosts = []
        with patch("ip_scanner.subprocess.Popen", return_value=process):
            outcome = run_nmap_scan(
                "192.168.1.0/24", "--open", executable="/usr/bin/nmap",
                on_host=lambda inventory, ports: hosts.append((inventory, ports)),
            )

        self.assertEqual(outcome, "complete")
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0][0]["open_ports"], 0)
        self.assertEqual(hosts[0][1], [])

    def test_scan_with_no_reported_hosts_returns_empty(self):
        process = type("FakeProcess", (), {
            "stdout": io.BytesIO(b"<?xml version='1.0'?><nmaprun></nmaprun>"),
            "stderr": io.BytesIO(),
            "poll": lambda _self: 0,
            "wait": lambda _self, timeout=None: 0,
            "terminate": lambda _self: None,
            "kill": lambda _self: None,
        })()
        with patch("ip_scanner.subprocess.Popen", return_value=process):
            outcome = run_nmap_scan(
                "192.168.1.0/24", "--open", executable="/usr/bin/nmap",
            )
        self.assertEqual(outcome, "empty")

    def test_nonzero_exit_reports_nmap_stderr(self):
        process = type("FakeProcess", (), {
            "stdout": io.BytesIO(b"<?xml version='1.0'?><nmaprun></nmaprun>"),
            "stderr": io.BytesIO(b"permission denied\n"),
            "poll": lambda _self: 1,
            "wait": lambda _self, timeout=None: 1,
            "terminate": lambda _self: None,
            "kill": lambda _self: None,
        })()
        with patch("ip_scanner.subprocess.Popen", return_value=process):
            with self.assertRaisesRegex(RuntimeError, "permission denied"):
                run_nmap_scan(
                    "192.168.1.0/24", "--open", executable="/usr/bin/nmap",
                )


class ExportResultsTests(unittest.TestCase):
    def test_writes_header_and_rows(self):
        record = {
            "ip": "192.168.1.5",
            "hostname": "host",
            "protocol": "tcp",
            "port": 443,
            "state": "open",
            "service": "https",
            "product": "nginx",
            "version": "1.24",
            "os": "",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.csv"
            self.assertEqual(export_results(path, [record]), path)

            with path.open(newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

        self.assertEqual(tuple(rows[0]), CSV_FIELDS)
        self.assertEqual(rows[0]["ip"], record["ip"])
        self.assertEqual(rows[0]["port"], "443")
        self.assertEqual(rows[0]["state"], "open")

    def test_exports_host_inventory_including_no_open_ports(self):
        hosts = [{
            "ip": "192.168.1.8",
            "hostname": "",
            "status": "up",
            "reason": "arp-response",
            "open_ports": 0,
            "protocols": "",
            "os": "",
            "os_accuracy": "",
        }]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "hosts.csv"
            export_hosts(path, hosts)
            with path.open(newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))
        self.assertEqual(tuple(rows[0]), HOST_FIELDS)
        self.assertEqual(rows[0]["ip"], "192.168.1.8")
        self.assertEqual(rows[0]["open_ports"], "0")


class ScanOperationTests(unittest.TestCase):
    def test_discovery_uses_nmap_ping_scan(self):
        scanner = MagicMock()
        scanner.all_hosts.return_value = ["192.168.1.5"]
        with patch("ip_scanner._port_scanner", return_value=scanner):
            hosts = discover_hosts("192.168.1.0/24")

        scanner.scan.assert_called_once_with(
            hosts="192.168.1.0/24", arguments="-sn",
        )
        self.assertEqual(hosts, ["192.168.1.5"])

    def test_discovery_can_assume_hosts_are_up(self):
        scanner = MagicMock()
        scanner.all_hosts.return_value = ["192.168.1.5", "192.168.1.6"]
        with patch("ip_scanner._port_scanner", return_value=scanner):
            hosts = discover_hosts("192.168.1.0/24", assume_up=True)

        scanner.scan.assert_called_once_with(
            hosts="192.168.1.0/24", arguments="-sn -Pn",
        )
        self.assertEqual(len(hosts), 2)

    def test_scan_host_extracts_sorted_service_records(self):
        host_data = MagicMock()
        host_data.all_protocols.return_value = ["tcp"]
        host_data.__getitem__.return_value = {
            443: {
                "name": "https", "product": "nginx", "version": "1.24",
                "state": "open",
            },
            80: {"name": "http"},
        }
        scanner = MagicMock()
        scanner.all_hosts.return_value = ["192.168.1.5"]
        scanner.__getitem__.return_value = host_data
        with patch("ip_scanner._port_scanner", return_value=scanner):
            with patch("ip_scanner.resolve_hostname", return_value="host.local"):
                records = scan_host("192.168.1.5")

        scanner.scan.assert_called_once_with(
            hosts="192.168.1.5", arguments="-sV --open",
        )
        self.assertEqual([record["port"] for record in records], [80, 443])
        self.assertEqual(records[0]["hostname"], "host.local")
        self.assertEqual(records[0]["service"], "http")
        self.assertEqual(records[1]["version"], "1.24")
        self.assertEqual(records[1]["state"], "open")

    def test_scan_host_uses_custom_arguments(self):
        host_data = MagicMock()
        host_data.all_protocols.return_value = []
        scanner = MagicMock()
        scanner.all_hosts.return_value = ["192.168.1.5"]
        scanner.__getitem__.return_value = host_data
        with patch("ip_scanner._port_scanner", return_value=scanner):
            scan_host("192.168.1.5", arguments="-sT -p 22")

        scanner.scan.assert_called_once_with(
            hosts="192.168.1.5", arguments="-sT -p 22",
        )


class ProgressiveScanTests(unittest.TestCase):
    def test_scan_worker_publishes_hosts_and_progress_as_they_arrive(self):
        app = IPScannerApp.__new__(IPScannerApp)
        app.events = queue.Queue()
        app.cancel_event = threading.Event()
        host = {
            "ip": "192.168.1.2", "hostname": "", "status": "up",
            "reason": "arp-response", "open_ports": 0, "protocols": "",
            "os": "", "os_accuracy": "",
        }

        def fake_scan(target, arguments, **kwargs):
            self.assertEqual(target, "192.168.1.0/24")
            self.assertEqual(arguments, "-sV --open")
            kwargs["on_progress"](34, "34% done")
            kwargs["on_host"](host, [])
            return "complete"

        with patch("app.run_nmap_scan", side_effect=fake_scan) as scan:
            app._run_scan(
                "192.168.1.0/24", "-sV --open", "/usr/bin/nmap", False,
            )

        events = []
        while not app.events.empty():
            events.append(app.events.get_nowait())

        scan.assert_called_once()
        self.assertEqual(events[0], ("nmap_progress", (34, "34% done")))
        self.assertEqual(events[1], ("host_result", (host, [])))
        self.assertEqual(events[-1], ("finished", "complete"))


if __name__ == "__main__":
    unittest.main()
