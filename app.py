"""Desktop application entry point for IP Scanner."""

import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from ip_scanner import (
    build_scan_arguments,
    build_nmap_command,
    build_target,
    export_hosts,
    export_results,
    format_nmap_command,
    find_nmap,
    nmap_version,
    run_nmap_scan,
    SCAN_PROFILES,
)


class IPScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Scanner")
        self.root.geometry("1120x800")
        self.root.minsize(900, 620)

        self.events = queue.Queue()
        self.cancel_event = threading.Event()
        self.results = []
        self.host_inventory = []
        self.host_inventory_by_ip = {}
        self.host_rows = {}
        self.busy = False
        self.closing = False

        self.target_type = tk.StringVar(value="cidr")
        self.cidr = tk.StringVar()
        self.start_ip = tk.StringVar()
        self.end_ip = tk.StringVar()
        self.tcp_scan = tk.StringVar(value="default")
        self.scan_udp = tk.BooleanVar(value=False)
        self.service_detection = tk.BooleanVar(value=True)
        self.os_detection = tk.BooleanVar(value=False)
        self.default_scripts = tk.BooleanVar(value=False)
        self.timing = tk.StringVar(value="Default")
        self.assume_up = tk.BooleanVar(value=False)
        self.show_all_ports = tk.BooleanVar(value=False)
        self.extra_arguments = tk.StringVar()
        self.status = tk.StringVar(value="Ready")
        self.scan_option_widgets = []

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
        self.export_hosts_button = ttk.Button(
            controls, text="Export host inventory…", command=self._export_hosts,
            state=tk.DISABLED,
        )
        self.export_hosts_button.pack(side=tk.LEFT, padx=(6, 0))

        options_frame = ttk.LabelFrame(container, text="Nmap scan options", padding=10)
        options_frame.pack(fill=tk.X, pady=(10, 0))

        ttk.Label(options_frame, text="Scan profile:").grid(row=0, column=0, sticky=tk.W)
        self.profile_combo = ttk.Combobox(
            options_frame, values=("Quick", "Standard", "Thorough"),
            state="readonly", width=19,
        )
        self.profile_combo.current(1)
        self.profile_combo.bind("<<ComboboxSelected>>", self._apply_scan_profile)
        self.profile_combo.grid(row=0, column=1, sticky=tk.W, padx=(5, 14))
        ttk.Label(
            options_frame,
            text="Profiles are starting points; customize any option below.",
        ).grid(row=0, column=2, columnspan=4, sticky=tk.W)

        ttk.Label(options_frame, text="TCP scan:").grid(row=1, column=0, sticky=tk.W)
        self.tcp_scan_combo = ttk.Combobox(
            options_frame,
            textvariable=self.tcp_scan,
            values=("Default", "SYN (-sS)", "Connect (-sT)", "Do not scan TCP"),
            state="readonly",
            width=19,
        )
        self.tcp_scan_combo.current(0)
        self.tcp_scan_combo.grid(row=1, column=1, sticky=tk.W, padx=(5, 14))
        self.udp_checkbox = ttk.Checkbutton(
            options_frame, text="UDP scan (-sU)", variable=self.scan_udp,
        )
        self.udp_checkbox.grid(row=1, column=2, sticky=tk.W)
        self.service_checkbox = ttk.Checkbutton(
            options_frame, text="Service/version detection (-sV)",
            variable=self.service_detection,
        )
        self.service_checkbox.grid(row=1, column=3, sticky=tk.W, padx=(8, 0))
        self.os_checkbox = ttk.Checkbutton(
            options_frame, text="OS detection (-O)", variable=self.os_detection,
        )
        self.os_checkbox.grid(row=1, column=4, sticky=tk.W, padx=(8, 0))
        self.scripts_checkbox = ttk.Checkbutton(
            options_frame, text="Default scripts (-sC)", variable=self.default_scripts,
        )
        self.scripts_checkbox.grid(row=1, column=5, sticky=tk.W, padx=(8, 0))

        ttk.Label(options_frame, text="Ports (-p):").grid(
            row=2, column=0, sticky=tk.W, pady=(8, 0),
        )
        self.ports_entry = ttk.Entry(options_frame, width=24)
        self.ports_entry.grid(row=2, column=1, sticky=tk.W, padx=(5, 14), pady=(8, 0))
        self.ports_entry.insert(0, "")
        ttk.Label(options_frame, text="blank = Nmap default").grid(
            row=2, column=2, sticky=tk.W, pady=(8, 0),
        )
        ttk.Label(options_frame, text="Timing (-T):").grid(
            row=2, column=3, sticky=tk.E, padx=(8, 4), pady=(8, 0),
        )
        self.timing_combo = ttk.Combobox(
            options_frame, textvariable=self.timing,
            values=("Default", "0 - Paranoid", "1 - Sneaky", "2 - Polite",
                    "3 - Normal", "4 - Aggressive", "5 - Insane"),
            state="readonly", width=19,
        )
        self.timing_combo.current(0)
        self.timing_combo.grid(row=2, column=4, sticky=tk.W, pady=(8, 0))

        self.assume_up_checkbox = ttk.Checkbutton(
            options_frame, text="Assume hosts are up (-Pn)",
            variable=self.assume_up,
        )
        self.assume_up_checkbox.grid(
            row=3, column=0, columnspan=2, sticky=tk.W, pady=(8, 0),
        )
        self.all_ports_checkbox = ttk.Checkbutton(
            options_frame, text="Include closed/filtered ports",
            variable=self.show_all_ports,
        )
        self.all_ports_checkbox.grid(
            row=3, column=2, columnspan=3, sticky=tk.W, pady=(8, 0),
        )

        ttk.Label(options_frame, text="Additional Nmap arguments:").grid(
            row=4, column=0, columnspan=2, sticky=tk.W, pady=(8, 0),
        )
        self.extra_arguments_entry = ttk.Entry(
            options_frame, textvariable=self.extra_arguments,
        )
        self.extra_arguments_entry.grid(
            row=4, column=2, columnspan=4, sticky=tk.EW, padx=(5, 0), pady=(8, 0),
        )
        ttk.Label(
            options_frame,
            text="Advanced options apply to port scans. Target and output options are managed by the app.",
        ).grid(row=5, column=0, columnspan=6, sticky=tk.W, pady=(4, 0))
        options_frame.columnconfigure(5, weight=1)
        self.scan_option_widgets = [
            self.profile_combo, self.tcp_scan_combo, self.udp_checkbox, self.service_checkbox,
            self.os_checkbox, self.scripts_checkbox, self.ports_entry,
            self.timing_combo, self.assume_up_checkbox, self.all_ports_checkbox,
            self.extra_arguments_entry,
        ]

        ttk.Label(
            container,
            text="Only scan networks and systems you own or are authorized to assess.",
        ).pack(anchor=tk.W, pady=(8, 6))

        results_frame = ttk.Frame(container)
        results_frame.pack(fill=tk.BOTH, expand=True)
        columns = (
            "ip", "hostname", "protocol", "port", "service", "product",
            "version", "os", "state",
        )
        self.table = ttk.Treeview(
            results_frame, columns=columns, show="headings", selectmode="browse",
        )
        widths = {
            "ip": 110, "hostname": 125, "protocol": 70, "port": 60,
            "service": 110, "product": 160, "version": 110, "os": 150,
            "state": 90,
        }
        for column in columns:
            self.table.heading(column, text=column.capitalize())
            self.table.column(column, width=widths[column], minwidth=55, stretch=True)
        scrollbar = ttk.Scrollbar(
            results_frame, orient=tk.VERTICAL, command=self.table.yview,
        )
        horizontal_scrollbar = ttk.Scrollbar(
            results_frame, orient=tk.HORIZONTAL, command=self.table.xview,
        )
        self.table.configure(
            yscrollcommand=scrollbar.set,
            xscrollcommand=horizontal_scrollbar.set,
        )
        self.table.pack(side=tk.TOP, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        horizontal_scrollbar.pack(side=tk.BOTTOM, fill=tk.X)

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

    def _apply_scan_profile(self, _event=None):
        profile = SCAN_PROFILES[self.profile_combo.get()]
        self.tcp_scan_combo.current(
            {"default": 0, "syn": 1, "connect": 2, "none": 3}[profile["tcp_scan"]]
        )
        self.scan_udp.set(profile.get("scan_udp", False))
        self.service_detection.set(profile["service_detection"])
        self.os_detection.set(profile["os_detection"])
        self.default_scripts.set(profile["default_scripts"])
        self.timing_combo.current(
            0 if profile["timing"] == "default" else int(profile["timing"]) + 1
        )
        self.show_all_ports.set(profile["show_all_ports"])
        self.ports_entry.delete(0, tk.END)
        self.ports_entry.insert(0, profile["ports"])

    def _start_scan(self):
        try:
            if self.target_type.get() == "cidr":
                target = build_target(cidr=self.cidr.get().strip())
            else:
                target = build_target(
                    start_ip=self.start_ip.get().strip(),
                    end_ip=self.end_ip.get().strip(),
                )
            scan_types = ("default", "syn", "connect", "none")
            scan_type = scan_types[self.tcp_scan_combo.current()]
            scan_arguments = build_scan_arguments(
                tcp_scan=scan_type,
                scan_udp=self.scan_udp.get(),
                ports=self.ports_entry.get(),
                service_detection=self.service_detection.get(),
                os_detection=self.os_detection.get(),
                default_scripts=self.default_scripts.get(),
                timing=("default" if self.timing_combo.current() == 0
                        else str(self.timing_combo.current() - 1)),
                show_all_ports=self.show_all_ports.get(),
                extra_arguments=self.extra_arguments.get(),
            )
        except (ValueError, tk.TclError) as exc:
            messagebox.showerror("Invalid scan settings", str(exc), parent=self.root)
            return

        try:
            executable = find_nmap()
            version = nmap_version(executable)
            command = build_nmap_command(
                target, scan_arguments, assume_up=self.assume_up.get(),
                executable=executable,
            )
        except (ValueError, RuntimeError) as exc:
            messagebox.showerror("Nmap preflight failed", str(exc), parent=self.root)
            return

        self._show_command_preview(
            target, scan_arguments, executable, version,
            format_nmap_command(command),
        )

    def _show_command_preview(self, target, arguments, executable, version, command_text):
        dialog = tk.Toplevel(self.root)
        dialog.title("Review Nmap command")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(True, False)

        body = ttk.Frame(dialog, padding=14)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text=f"{version}").pack(anchor=tk.W, pady=(0, 8))
        ttk.Label(body, text="This exact command will be run:").pack(anchor=tk.W)
        command_box = tk.Text(body, width=90, height=5, wrap=tk.WORD)
        command_box.pack(fill=tk.BOTH, expand=True, pady=(4, 12))
        command_box.insert("1.0", command_text)
        command_box.configure(state=tk.DISABLED)
        ttk.Label(
            body,
            text="Only scan networks and systems you own or are authorized to assess.",
            wraplength=640,
        ).pack(anchor=tk.W, pady=(0, 10))
        buttons = ttk.Frame(body)
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Cancel", command=dialog.destroy).pack(side=tk.RIGHT)
        ttk.Button(
            buttons, text="Run scan",
            command=lambda: (
                dialog.destroy(),
                self._launch_scan(target, arguments, executable),
            ),
        ).pack(side=tk.RIGHT, padx=(0, 8))
        dialog.bind("<Escape>", lambda _event: dialog.destroy())
        dialog.focus_set()

    def _launch_scan(self, target, scan_arguments, executable):
        self.results.clear()
        self.host_inventory.clear()
        self.host_inventory_by_ip.clear()
        self.host_rows.clear()
        self.table.delete(*self.table.get_children())
        self.progress.configure(maximum=1, value=0)
        self.cancel_event.clear()
        self.busy = True
        self.status.set("Starting Nmap…")
        self.start_button.configure(state=tk.DISABLED)
        self.cancel_button.configure(state=tk.NORMAL)
        self.export_button.configure(state=tk.DISABLED)
        self.export_hosts_button.configure(state=tk.DISABLED)
        for widget in (
            self.cidr_entry, self.start_entry, self.end_entry,
            *self.scan_option_widgets,
        ):
            widget.configure(state=tk.DISABLED)
        self.cidr_radio.configure(state=tk.DISABLED)
        self.range_radio.configure(state=tk.DISABLED)

        threading.Thread(
            target=self._run_scan,
            args=(target, scan_arguments, executable, self.assume_up.get()),
            daemon=True,
        ).start()

    def _run_scan(
        self, target, scan_arguments="-sV --open", executable=None, assume_up=False,
    ):
        try:
            outcome = run_nmap_scan(
                target,
                scan_arguments,
                assume_up=assume_up,
                executable=executable,
                cancel_event=self.cancel_event,
                on_host=lambda host, records: self.events.put(("host_result", (host, records))),
                on_host_hint=lambda host: self.events.put(("host_hint", host)),
                on_progress=lambda percent, text: self.events.put(
                    ("nmap_progress", (percent, text))
                ),
            )
            self.events.put(("finished", outcome))
        except Exception as exc:
            self.events.put(("fatal", str(exc)))
            self.events.put(("finished", "error"))

    def _process_events(self):
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event == "host_hint":
                    host = payload
                    address = host["ip"]
                    if address not in self.host_inventory_by_ip:
                        self.host_inventory_by_ip[address] = len(self.host_inventory)
                        self.host_inventory.append(host)
                    self.export_hosts_button.configure(state=tk.NORMAL)
                    row = self.table.insert(
                        "", tk.END,
                        values=(
                            address, host["hostname"], "", "", "", "", "", "",
                            "Scanning ports…",
                        ),
                    )
                    self.host_rows[address] = row
                    self.table.see(row)
                elif event == "host_result":
                    host, results = payload
                    address = host["ip"]
                    inventory_index = self.host_inventory_by_ip.get(address)
                    if inventory_index is None:
                        self.host_inventory_by_ip[address] = len(self.host_inventory)
                        self.host_inventory.append(host)
                    else:
                        self.host_inventory[inventory_index] = host
                    row = self.host_rows.pop(address, None)
                    if row:
                        self.table.delete(row)
                    for result in results:
                        self.results.append(result)
                        self.table.insert(
                            "", tk.END,
                            values=tuple(result.get(key, "") for key in (
                                "ip", "hostname", "protocol", "port",
                                "service", "product", "version", "os", "state",
                            )),
                        )
                    if results:
                        self.export_button.configure(state=tk.NORMAL)
                    if not results:
                        host_status = host["status"]
                        if host_status == "cancelled":
                            row_status = "Cancelled"
                        elif host_status == "scan failed":
                            row_status = "Scan failed"
                        else:
                            row_status = f"{host_status.capitalize()}, no matching ports"
                        self.table.insert(
                            "", tk.END,
                            values=(
                                host["ip"], host["hostname"], "", "", "", "", "", "",
                                row_status,
                            ),
                        )
                    self.table.see(self.table.get_children()[-1])
                elif event == "nmap_progress":
                    percent, text = payload
                    if percent is not None:
                        self.progress.configure(mode="determinate", maximum=100, value=percent)
                        self.status.set(f"Nmap: {percent}% complete")
                    elif text:
                        self.progress.configure(mode="indeterminate")
                        self.progress.start(12)
                        self.status.set(text[:120])
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
        self.progress.stop()
        self.progress.configure(mode="determinate")
        self.start_button.configure(state=tk.NORMAL)
        self.cancel_button.configure(state=tk.DISABLED)
        self.export_button.configure(state=tk.NORMAL)
        self.export_hosts_button.configure(
            state=tk.NORMAL if self.host_inventory else tk.DISABLED,
        )
        self.cidr_radio.configure(state=tk.NORMAL)
        self.range_radio.configure(state=tk.NORMAL)
        self._update_target_fields()
        for widget in self.scan_option_widgets:
            widget.configure(state="readonly" if isinstance(widget, ttk.Combobox) else tk.NORMAL)
        self.status.set({
            "complete": (
                f"Complete — {len(self.host_inventory)} host(s), "
                f"{len(self.results)} port(s)"
            ),
            "cancelled": (
                f"Cancelled — {len(self.host_inventory)} host(s), "
                f"{len(self.results)} port(s) collected"
            ),
            "empty": "No hosts found",
            "error": "Scan failed",
        }.get(outcome, "Ready"))

    def _cancel_scan(self):
        self.cancel_event.set()
        self.cancel_button.configure(state=tk.DISABLED)
        self.status.set("Cancelling Nmap scan…")

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

    def _export_hosts(self):
        if not self.host_inventory:
            messagebox.showinfo(
                "No hosts", "There are no discovered hosts to export.", parent=self.root,
            )
            return
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export host inventory",
            defaultextension=".csv",
            initialfile="host_inventory.csv",
            filetypes=(("CSV files", "*.csv"), ("All files", "*.*")),
        )
        if not path:
            return
        try:
            output = export_hosts(path, self.host_inventory)
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)
            return
        self.status.set(
            f"Exported {len(self.host_inventory)} host(s) to {output}"
        )

    def _close(self):
        if self.busy:
            if not messagebox.askyesno(
                "Scan in progress",
                "Terminate the running Nmap scan and close?",
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
