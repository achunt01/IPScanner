# IP Range Scanner

This Python script scans a range of IP addresses for open ports using the `nmap` library and performs basic analysis on the scan results.

## Installation

1. Install `nmap` and `python-nmap`:
   ```bash
   sudo apt-get install nmap
   pip install python-nmap
   ```
   
2. Clone the repository:
    ```bash
   git clone https://github.com/achunt01/ip-range-scanner.git
   ```


   ## Usage

1. **Modify IP Range**: Modify the `start_ip` and `end_ip` variables in the script to define the range of IP addresses to scan.

2. **Run the Script**: Run the script to scan each IP address in the range and perform detailed analysis on the open ports.

## Multithreading

The script uses multithreading to scan multiple IP addresses concurrently, speeding up the scanning process.

## Detailed Analysis

In addition to printing the open ports, the script also identifies the operating system and service versions running on the target machines.

## Error Handling

The script includes robust error handling to handle cases where a scan fails or encounters an error.

## Output Formatting

The scan results are formatted for readability and ease of analysis.

## User Interface

A simple user interface using the tkinter library can be added to make the tool more user-friendly.

## Logging

Logging functionality is included to log the scan results and any errors encountered during the scanning process.

## Configuration Options

The script provides options for the user to configure the scan parameters, such as the range of ports to scan or the timeout for each scan.

## Integration

The tool can be integrated with other tools or services, such as a database or a monitoring system, to automate further actions based on the scan results.

## Example

To scan the IP range from 192.168.1.1 to 192.168.1.10:

```python
start_ip = "192.168.1.1"
end_ip = "192.168.1.10"

