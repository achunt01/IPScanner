# IP Scanner

IP Scanner is a desktop application for discovering hosts and open services on IPv4 or IPv6 CIDR networks, and inclusive IPv4 ranges. The graphical app runs on macOS and Windows; a command-line interface is also included.

Only scan networks and systems you own or are explicitly authorized to assess.

## Features

- Scan a CIDR network or an inclusive IPv4 start/end range.
- Discover responsive hosts, then identify open TCP services and versions with Nmap.
- Set the number of concurrent host scans.
- Cancel pending host scans while allowing active Nmap requests to finish.
- View results in the desktop app and export them to CSV.
- Run the same scanning engine from the command line.

## Requirements

- Python 3.9 or newer (when running from source).
- Nmap installed and available on your system `PATH`.
- On Windows, install Npcap with Nmap if you want Nmap's packet-capture-based discovery features.

Nmap is a separate prerequisite and is not bundled in the application packages. Install it from [nmap.org/download.html](https://nmap.org/download.html). On Windows, follow the Nmap installer prompts for Npcap.

## Run from source

Install the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

Launch the desktop app:

```bash
python app.py
```

Or run the command-line interface:

```bash
python EnhancedIPScanner.py
```

The CLI prompts for a CIDR or start/end IP range. Use `--workers` to change concurrency and `--output` to choose the CSV path:

```bash
python EnhancedIPScanner.py --workers 10 --output results.csv
```

`IPScanner.py` is retained as a compatibility entry point for the desktop app.

## Build desktop packages

Builds must be run on the operating system being packaged. Install build dependencies and run PyInstaller:

```bash
python -m pip install -r requirements-build.txt
python -m PyInstaller --clean --noconfirm --windowed --name IPScanner --hidden-import=nmap app.py
```

PyInstaller writes the app bundle/executable and its support files under `dist/`. The repository's **Build desktop apps** GitHub Actions workflow can also build macOS and Windows artifacts on their respective runners. Run it manually from the Actions tab or push a version tag such as `v1.0.0`.

The resulting application still requires Nmap to be installed separately. Builds from the workflow are unsigned; macOS may require approving the app in Privacy & Security before its first launch.

## CSV fields

Exports include `ip`, `hostname`, `protocol`, `port`, `service`, `product`, and `version`. A CSV is created by the desktop app when you choose **Export CSV…**; the CLI writes to `scan_results.csv` unless another path is passed with `--output`.

## License

MIT
