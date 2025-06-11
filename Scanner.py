"""
This is the network scanner. It will detect and display connected devices on a network.

"""

import nmap
from dotenv import load_dotenv
import os

load_dotenv()

class NetworkScanner:

    def __init__(self):
        self.nmap = nmap.PortScanner()

    def scan_local(self):

        network = os.getenv("nmap_test")

        # -sn for ping scan, - sS for port scan
        self.nmap.scan(hosts=network, arguments='-sS')

        devices = []

        # iterating through detected hosts
        for host in self.nmap.all_hosts():
            
            #gets host name
            hostname = self.nmap[host].hostname()

            #gets port status (up or down)
            status = self.nmap[host].state()

            ports = []

            #gets port numbers for each host name
            for protocol in self.nmap[host].all_protocols():
                ports = self.nmap[host][protocol].keys()


            #get ports from nmap:
            #nmap -p scanme.nmap.org

            devices.append({
                'ip': host,
                'hostname': hostname,
                'status:': status,
                'ports:': ports
            })

        return devices

def main():
    
    scanner = NetworkScanner()

    devices = scanner.scan_local()

    for device in devices:
        print(device)

if __name__ == "__main__":
    main()