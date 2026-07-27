import subprocess
import xml.etree.ElementTree as ET
import csv
import os
from datetime import datetime

class Portscanner:

    def __init__(self, target_ip):
        self.target_ip = target_ip


    def run_xmas_scan(self):
        # Execute nmap, capture XML output
        cmd = ["nmap", "-p-", "-sX", self.target_ip, "-oX", "-"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        root = ET.fromstring(proc.stdout)

        open_ports = []
        for host in root.findall("host"):
            addr = host.find("address").get("addr")
            for port in host.findall(".//port"):
                state = port.find("state").get("state")
                # Xmas scan: open|filtered means open or filtered; we treat as open.
                if state in ("open", "open|filtered"):
                    port_id = port.get("portid")
                    protocol = port.get("protocol")
                    open_ports.append((addr, port_id, protocol, state))

        # Save CSV
        os.makedirs("output", exist_ok=True)
        date_str = datetime.now().strftime("%Y-%m-%d")
        csv_name = f"{date_str}_{self.target_ip}.csv"
        csv_path = os.path.join("output", csv_name)
        with open(csv_path, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "port", "protocol", "state"])
            writer.writerows(open_ports)

        return open_ports  # list of tuples for later use