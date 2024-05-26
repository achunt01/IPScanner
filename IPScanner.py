import nmap
import ipaddress
import threading

start_ip = "192.168.1.1"
end_ip = "192.168.1.10"

nm = nmap.PortScanner()

def scan_ip(ip):
    nm.scan(ip, arguments='-p 1-65535 -sV --open')
    return nm[ip]

def scan_range(start_ip, end_ip):
    for ip in ipaddress.IPv4Network(f"{start_ip}/{end_ip.split('.')[-1]}"):
        ip_str = str(ip)
        try:
            result = scan_ip(ip_str)
            print(f"Scanned {ip_str}. Open ports: {result['tcp'].keys()}")
        except Exception as e:
            print(f"Failed to scan {ip_str}: {e}")

threads = []
for i in range(5):  # Number of threads
    t = threading.Thread(target=scan_range, args=(start_ip, end_ip))
    threads.append(t)
    t.start()

for t in threads:
    t.join()
