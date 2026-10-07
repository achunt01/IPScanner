# IP Scanner

IP Scanner is a desktop application for discovering hosts and open services on IPv4 or IPv6 CIDR networks, and inclusive IPv4 ranges. The graphical app runs on macOS and Windows; a command-line interface is also included.

Only scan networks and systems you own or are explicitly authorized to assess.

## Features

- Scan a CIDR network or an inclusive IPv4 start/end range.
- Configure TCP SYN/connect scans, UDP scans, ports, service/version detection,
  OS detection, default scripts, and Nmap timing templates.
- Enter additional Nmap arguments for options not exposed as individual controls.
- Choose whether to assume target hosts are up and whether to include
  non-open port states.
- Choose Quick, Standard, or Thorough presets and customize their options.
- Review the exact Nmap command before running; the app checks that Nmap is
  installed and available on `PATH`.
- Cancel the running Nmap process.
- See Nmap progress and hosts as Nmap reports them, including hosts with no
  matching open ports.
- Export port details or a separate host inventory that includes hosts with no
  open ports.
- Run the scanner from the command line.

## Requirements

- Python 3.9 or newer (when running from source).
- Tkinter (included with most Python installers; Homebrew Python may require
  a separate Tk package).
- Nmap installed and available on your system `PATH`.
- On Windows, install Npcap with Nmap if you want Nmap's packet-capture-based discovery features.

Nmap is a separate prerequisite and is not bundled in the application packages. Install it from [nmap.org/download.html](https://nmap.org/download.html). On Windows, follow the Nmap installer prompts for Npcap.

## Run from source

Install the Python dependencies:

```bash
python -m pip install -r requirements.txt
```

On macOS with Homebrew Python, install the matching Tkinter package if
`import tkinter` fails (for example, `brew install python-tk@3.14` for Python
3.14), then recreate the virtual environment so it uses the Tk-enabled Python.

Launch the desktop app:

```bash
python app.py
```

Or run the command-line interface:

```bash
python EnhancedIPScanner.py
```

The CLI prompts for a CIDR or start/end IP range. Use `--workers` to change
per-host concurrency and `--output` to choose the CSV path:

```bash
python EnhancedIPScanner.py --workers 10 --output results.csv
```

The **Quick** preset checks a short list of common ports with a connect scan;
**Standard** uses Nmap's default port selection with service detection; and
**Thorough** checks all TCP ports and enables OS detection. SYN and OS detection
may require administrator or root privileges.

The desktop app's **Additional Nmap arguments** field applies extra options to
port scans. IP Scanner controls target selection and output handling, so Nmap
target-list and output-file options are not accepted there. The **Default
scripts (-sC)** option runs Nmap's default NSE scripts; scan only systems you
are authorized to assess. TCP SYN and OS detection may require administrator
or root privileges; use TCP Connect when elevated privileges are unavailable.
For advanced options with values, use shell-style quoting (for example,
`--script-args 'user=scan value'`).

`IPScanner.py` is retained as a compatibility entry point for the desktop app.

## Build desktop packages

Builds must be run on the operating system being packaged. Install build dependencies and run PyInstaller:

```bash
python -m pip install -r requirements-build.txt
python -m PyInstaller --clean --noconfirm --windowed --name IPScanner --hidden-import=nmap app.py
```

PyInstaller writes the app bundle/executable and its support files under `dist/`. The repository's **Build desktop apps** GitHub Actions workflow can also build macOS and Windows artifacts on their respective runners. Run it manually from the Actions tab or push a version tag such as `v1.0.0`.

The resulting application still requires Nmap to be installed separately.
Builds from the workflow are unsigned; macOS may require approving the app in
Privacy & Security before its first launch.

## CSV fields

**Export CSV…** writes port details with `ip`, `hostname`, `protocol`, `port`,
`state`, `service`, `product`, and `version`. **Export host inventory…** writes
one row per host reported by Nmap, including its state, discovery reason,
open-port count, detected protocols, and OS match when available. The CLI writes port details to
`scan_results.csv` unless another path is passed with `--output`.

## License

MIT
