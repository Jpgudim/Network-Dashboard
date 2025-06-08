"""
This is the network scanner. It will detect and display connected devices on a network.

"""

import nmap
from dotenv import load_dotenv
import os

load_dotenv()

class NetworkScanner:

    def __init__(self):
        self.scanner = nmap.PortScanner()

    def scan_local(self):

        local = os.getenv("home_ip_range")

        self.scanner.scan(hosts=local, arguments='-sn')

        devices = []

        for host in self.scanner.all_hosts():
            hostname = self.scanner[host].hostname()
            devices.append({
                'ip': host,
                'hostname': hostname
            })
        
        return devices

def main():
    
    scanner = NetworkScanner()

    devices = scanner.scan_local()

    for device in devices:
        print(device)

if __name__ == "__main__":
    main()