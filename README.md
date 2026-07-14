# IP Range Scanner

A multithreaded Python-based network scanner that uses Nmap to discover live hosts, identify open ports, detect running services, and export results to CSV.

The tool supports both CIDR ranges and start/end IP ranges, making it useful for network discovery, asset inventory, and MSP health assessments.

## Features

- Host discovery using Nmap ping sweep (`-sn`)
- CIDR notation support (e.g. `192.168.1.0/24`)
- Start/End IP range support
- Multithreaded scanning with configurable worker count
- Service detection (`-sV`)
- Reverse DNS hostname lookup
- Progress bar using `tqdm`
- CSV export of scan results
- Error handling for failed scans
- Supports Linux, macOS, and Windows (with Nmap installed)

---

## Requirements

### Install Nmap

#### Ubuntu/Debian

```bash
sudo apt-get update
sudo apt-get install nmap
```

#### RHEL/CentOS

```bash
sudo yum install nmap
```

#### Windows

Download and install Nmap:

https://nmap.org/download.html

Ensure Nmap is added to your system PATH.

---

## Install Python Dependencies

```bash
pip install python-nmap tqdm
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/achunt01/ip-range-scanner.git
cd ip-range-scanner
```

---

## Usage

Run the scanner:

```bash
python scanner.py
```

You'll be prompted to choose a target type:

```text
Target Options
--------------
1. CIDR
2. Start/End IP
```

### Scan a CIDR Range

```text
Select option: 1
Enter CIDR: 192.168.1.0/24
```

### Scan an IP Range

```text
Select option: 2
Start IP: 192.168.1.1
End IP: 192.168.1.254
```

---

## Scan Process

### Host Discovery

The scanner first performs a ping sweep to discover active hosts:

```bash
nmap -sn
```

Only responsive hosts are passed to the port scanning phase.

### Port and Service Detection

Discovered hosts are scanned using:

```bash
nmap -sV --open
```

This identifies:

- Open ports
- Protocols
- Service names
- Product information
- Service versions

---

## CSV Export

Results are automatically exported to:

```text
scan_results.csv
```

Example:

```csv
ip,hostname,protocol,port,service,product,version
192.168.1.1,firewall,tcp,443,https,nginx,1.24.0
192.168.1.5,dc01,tcp,3389,ms-wbt-server,Microsoft Terminal Services,
192.168.1.10,file01,tcp,445,microsoft-ds,Windows Server 2022,
```

---

## Multithreading

The application uses Python's `ThreadPoolExecutor` to scan multiple hosts concurrently.

Default configuration:

```python
MAX_THREADS = 20
```

Adjust based on:

- Network size
- Available system resources
- Network latency
- Scan aggressiveness requirements

---

## Progress Tracking

A live progress indicator is displayed during scanning using `tqdm`.

Example:

```text
Scanning Hosts: 100%|████████████████| 25/25
```

---

## Example Output

```text
[*] Discovering live hosts in 192.168.1.0/24...
[*] Found 12 live hosts

[*] Starting port scans...

Scannin* Hosts: 100%|████████████████| 12/*2

[+] Results exported to scan_re*ults.csv
[+] Scan complete. 34 rec*rds exported.
```

---

## Common *se Cases

- Network asset discover*
- MSP onboarding assessments
- In*ernal network inventories
- Open p*rt identification
- Service enumer*tion
- Lab environment mapping
- S*curity baseline reviews

---

## S*curity Notice

Only scan networks *nd systems you own or have explici* authorization to assess.

Unautho*ized network scanning may violate *ompany policies, service agreement*, or local laws.

---

## Future E*hancements

Potential roadmap item*:

- OS detection (`-O`)
- JSON ex*ort
- SQLite inventory database
- *etwork diagram generation
- Vulner*bility scanning with NSE scripts
-*Asset change detection between sca*s
- Scheduled recurring scans
- Po*erShell wrapper for RMM deployment*
---

## License

MIT License
