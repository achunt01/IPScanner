import nmap
import ipaddress

# Define the IP range to scan
start_ip = "192.168.1.1"
end_ip = "192.168.1.10"

# Initialize the Nmap scanner
nm = nmap.PortScanner()

# Function to scan an IP address
def scan_ip(ip):
    nm.scan(ip, arguments='-p 1-65535 -sV --open')
    return nm[ip]

# Iterate through each IP address in the range
for ip in ipaddress.IPv4Network(f"{start_ip}/{end_ip.split('.')[-1]}"):
    ip_str = str(ip)
    try:
        result = scan_ip(ip_str)
        print(f"Scanned {ip_str}. Open ports: {result['tcp'].keys()}")
    except Exception as e:
        print(f"Failed to scan {ip_str}: {e}")
