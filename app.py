"""Desktop application entry point for IP Scanner."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ip_scanner import build_target, discover_hosts, export_results, scan_host


class IPScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Scanner")
        self.root.geometry("1050x640")
        self.root.minsize(760, 460)

        self.events = queue.Queue()
        self.cancel_event = threading.Event()
        self.results = []
        self.errors = []
        self.busy = False
        self.closing = False

        self.target_type = tk.StringVar(value="cidr")
        self.cidr = tk.StringVar()
        self.start_ip = tk.StringVar()
        self.end_ip = tk.StringVar()
        self.workers = tk.IntVar(value=20)
        self.status = tk.StringVar(value="Ready")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(100, self._process_events)

    def _build_ui(self):
        container = ttk.Frame(self.root, padding=12)
        container.pack(fill=tk.BOTH, expand=True)

        target_frame = ttk.LabelFrame(container, text="Scan target", padding=10)
        target_frame.pack(fill=tk.X)

        self.cidr_radio = ttk.Radiobutton(
            target_frame, text="CIDR network", variable=self.target_type,
            value="cidr", command=self._update_target_fields,
        )
        self.cidr_radio.grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.cidr_entry = ttk.Entry(target_frame, textvariable=self.cidr, width=30)
        self.cidr_entry.grid(row=0, column=1, sticky=tk.W)
        ttk.Label(target_frame, text="e.g. 192.168.1.0/24").grid(
            row=0, column=2, sticky=tk.W, padx=8,
        )

        self.range_radio = ttk.Radiobutton(
            target_frame, text="IP range", variable=self.target_type,
            value="range", command=self._update_target_fields,
        )
        self.range_radio.grid(row=1, column=0, sticky=tk.W, padx=(0, 10), pady=(8, 0))
        self.start_entry = ttk.Entry(
            target_frame, textvariable=self.start_ip, width=18,
        )
        self.start_entry.grid(row=1, column=1, sticky=tk.W, pady=(8, 0))
        ttk.Label(target_frame, text="to").grid(
            row=1, column=2, sticky=tk.W, padx=8, pady=(8, 0),
        )
        self.end_entry = ttk.Entry(target_frame, textvariable=self.end_ip, width=18)
        self.end_entry.grid(row=1, column=3, sticky=tk.W, pady=(8, 0))

        controls = ttk.Frame(target_frame)
        controls.grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=(12, 0))
        ttk.Label(controls, text="Concurrent hosts:").pack(side=tk.LEFT)
        self.workers_spinbox = ttk.Spinbox(
            controls, from_=1, to=100, textvariable=self.workers, width=5,
        )
        self.workers_spinbox.pack(side=tk.LEFT, padx=(6, 16))
        self.start_button = ttk.Button(
            controls, text="Start scan", command=self._start_scan,
        )
        self.start_button.pack(side=tk.LEFT, padx=(0, 6))
        self.cancel_button = ttk.Button(
            controls, text="Cancel", command=self._cancel_scan, state=tk.DISABLED,
        )
        self.cancel_button.pack(side=tk.LEFT, padx=(0, 6))
        self.export_button = ttk.Button(
            controls, text="Export CSV…", command=self._export,
        )
        self.export_button.pack(side=tk.LEFT)

        ttk.Label(
            container,
            text="Only scan networks and systems you own or are authorized to assess.",
        ).pack(anchor=tk.W, pady=(8, 6))

        results_frame = ttk.Frame(container)
        results_frame.pack(fill=tk.BOTH, expand=True)
        columns = ("ip", "hostname", "protocol", "port", "service", "product", "version")
        self.table = ttk.Treeview(
            results_frame, columns=columns, show="headings", selectmode="browse",
        )
        widths = {
            "ip": 120, "hostname": 150, "protocol": 75, "port": 70,
            "service": 130, "product": 190, "version": 130,
        }
        for column in columns:
            self.table.heading(column, text=column.capitalize())
            self.table.column(column, width=widths[column], minwidth=55, stretch=True)
        scrollbar = ttk.Scrollbar(
            results_frame, orient=tk.VERTICAL, command=self.table.yview,
        )
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        footer = ttk.Frame(container)
        footer.pack(fill=tk.X, pady=(8, 0))
        self.progress = ttk.Progressbar(footer, mode="determinate")
        self.progress.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Label(footer, textvariable=self.status).pack(side=tk.RIGHT)

        self._update_target_fields()

    def _update_target_fields(self):
        cidr_state = tk.NORMAL if self.target_type.get() == "cidr" else tk.DISABLED
        range_state = tk.NORMAL if self.target_type.get() == "range" else tk.DISABLED
        self.cidr_entry.configure(state=cidr_state)
        self.start_entry.configure(state=range_state)
        self.end_entry.configure(state=range_state)

    def _start_scan(self):
        try:
            if self.target_type.get() == "cidr":
                target = build_target(cidr=self.cidr.get().strip())
            else:
                target = build_target(
                    start_ip=self.start_ip.get().strip(),
                    end_ip=self.end_ip.get().strip(),
                )
            workers = int(self.workers.get())
            if not 1 <= workers <= 100:
                raise ValueError("Concurrent hosts must be between 1 and 100.")
        except (ValueError, tk.TclError) as exc:
            messagebox.showerror("Invalid scan settings", str(exc), parent=self.root)
            return

        self.results.clear()
        self.errors.clear()
        self.table.delete(*self.table.get_children())
        self.progress.configure(maximum=1, value=0)
        self.cancel_event.clear()
        self.busy = True
        self.status.set("Discovering hosts…")
        self.start_button.configure(state=tk.DISABLED)
        self.cancel_button.configure(state=tk.NORMAL)
        self.export_button.configure(state=tk.DISABLED)
        for widget in (self.cidr_entry, self.start_entry, self.end_entry, self.workers_spinbox):
            widget.configure(state=tk.DISABLED)
        self.cidr_radio.configure(state=tk.DISABLED)
        self.range_radio.configure(state=tk.DISABLED)

        threading.Thread(
            target=self._run_scan, args=(target, workers), daemon=True,
        ).start()

    def _run_scan(self, target, workers):
        try:
            hosts = discover_hosts(target)
            self.events.put(("discovered", hosts))
            if self.cancel_event.is_set() or not hosts:
                self.events.put(("finished", "cancelled" if self.cancel_event.is_set() else "empty"))
                return

            completed = 0

            def scan_if_active(host):
                if self.cancel_event.is_set():
                    return None
                return scan_host(host)

            with ThreadPoolExecutor(max_workers=workers) as executor:
                futures = {
                    executor.submit(scan_if_active, host): host
                    for host in hosts
                }
                for future in as_completed(futures):
                    if future.cancelled():
                        completed += 1
                        self.events.put(("progress", completed))
                        continue
                    host = futures[future]
                    try:
                        results = future.result()
                        if results is not None:
                            self.events.put(("results", results))
                    except Exception as exc:
                        self.events.put(("error", f"{host}: {exc}"))
                    completed += 1
                    self.events.put(("progress", completed))
                    if self.cancel_event.is_set():
                        for pending in futures:
                            pending.cancel()

            outcome = "cancelled" if self.cancel_event.is_set() else "complete"
            self.events.put(("finished", outcome))
        except Exception as exc:
            self.events.put(("fatal", str(exc)))
            self.events.put(("finished", "error"))

    def _process_events(self):
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "discovered":
                    count = len(payload)
                    self.progress.configure(maximum=max(count, 1), value=0)
                    self.status.set(f"Found {count} live host(s)")
                elif event == "results":
                    for result in payload:
                        self.results.append(result)
                        self.table.insert(
                            "", tk.END,
                            values=tuple(result.get(key, "") for key in (
                                "ip", "hostname", "protocol", "port",
                                "service", "product", "version",
                            )),
                        )
                elif event == "progress":
                    self.progress.configure(value=payload)
                    total = int(self.progress["maximum"])
                    self.status.set(
                        f"Processed {payload}/{total} host(s)"
                    )
                elif event == "error":
                    self.errors.append(payload)
                    self.status.set(f"{len(self.errors)} host scan error(s)")
                elif event == "fatal":
                    messagebox.showerror("Scan failed", payload, parent=self.root)
                elif event == "finished":
                    self._finish_scan(payload)
        except queue.Empty:
            pass
        if self.closing and not self.busy:
            self.root.destroy()
        else:
            self.root.after(100, self._process_events)

    def _finish_scan(self, outcome):
        self.busy = False
        self.start_button.configure(state=tk.NORMAL)
        self.cancel_button.configure(state=tk.DISABLED)
        self.export_button.configure(state=tk.NORMAL)
        self.cidr_radio.configure(state=tk.NORMAL)
        self.range_radio.configure(state=tk.NORMAL)
        self._update_target_fields()
        self.workers_spinbox.configure(state=tk.NORMAL)
        self.status.set({
            "complete": f"Complete — {len(self.results)} open port(s) found",
            "cancelled": f"Cancelled — {len(self.results)} record(s) collected",
            "empty": "No live hosts found",
            "error": "Scan failed",
        }.get(outcome, "Ready"))
        if self.errors:
            self.status.set(
                f"{self.status.get()} — {len(self.errors)} host scan error(s)"
            )
            if not self.closing:
                shown_errors = "\n".join(self.errors[:10])
                remaining = len(self.errors) - 10
                if remaining:
                    shown_errors += f"\n…and {remaining} more."
                messagebox.showwarning(
                    "Some hosts could not be scanned",
                    shown_errors,
                    parent=self.root,
                )

    def _cancel_scan(self):
        self.cancel_event.set()
        self.cancel_button.configure(state=tk.DISABLED)
        self.status.set("Cancelling after active host scans finish…")

    def _export(self):
        if not self.results:
            messagebox.showinfo(
                "No results", "There are no scan results to export.", parent=self.root,
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export scan results",
            defaultextension=".csv",
            initialfile="scan_results.csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            output = export_results(path, self.results)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)
            return
        self.status.set(f"Exported {len(self.results)} record(s) to {output}")

    def _close(self):
        if self.busy:
            if not messagebox.askyesno(
                "Scan in progress",
                "Cancel the scan and close after active Nmap requests finish?",
                parent=self.root,
            ):
                return
            self.closing = True
            self._cancel_scan()
            self.root.withdraw()
            return
        self.root.destroy()


def main():
    root = tk.Tk()
    IPScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
