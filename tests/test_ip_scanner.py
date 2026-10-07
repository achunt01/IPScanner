import csv
import queue
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from app import IPScannerApp
from ip_scanner import (
    CSV_FIELDS,
    build_target,
    discover_hosts,
    export_results,
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


class ExportResultsTests(unittest.TestCase):
    def test_writes_header_and_rows(self):
        record = {
            "ip": "192.168.1.5",
            "hostname": "host",
            "protocol": "tcp",
            "port": 443,
            "service": "https",
            "product": "nginx",
            "version": "1.24",
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "results.csv"
            self.assertEqual(export_results(path, [record]), path)

            with path.open(newline="", encoding="utf-8") as file:
                rows = list(csv.DictReader(file))

        self.assertEqual(tuple(rows[0]), CSV_FIELDS)
        self.assertEqual(rows[0]["ip"], record["ip"])
        self.assertEqual(rows[0]["port"], "443")


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

    def test_scan_host_extracts_sorted_service_records(self):
        host_data = MagicMock()
        host_data.all_protocols.return_value = ["tcp"]
        host_data.__getitem__.return_value = {
            443: {"name": "https", "product": "nginx", "version": "1.24"},
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


class ProgressiveScanTests(unittest.TestCase):
    def test_worker_publishes_discovery_and_each_host_result(self):
        app = IPScannerApp.__new__(IPScannerApp)
        app.events = queue.Queue()
        app.cancel_event = threading.Event()
        host_results = {
            "192.168.1.2": [],
            "192.168.1.3": [{"ip": "192.168.1.3", "port": 443}],
        }

        with patch(
            "app.discover_hosts", return_value=list(host_results),
        ) as discover:
            with patch("app.scan_host", side_effect=host_results.get):
                app._run_scan("192.168.1.0/24", workers=2)

        events = []
        while not app.events.empty():
            events.append(app.events.get_nowait())

        discover.assert_called_once_with("192.168.1.0/24")
        self.assertEqual(events[0], ("discovered", list(host_results)))
        completed_hosts = {
            payload[0]: payload[1]
            for event, payload in events
            if event == "host_results"
        }
        self.assertEqual(completed_hosts, host_results)
        self.assertEqual(events[-1], ("finished", "complete"))


if __name__ == "__main__":
    unittest.main()
