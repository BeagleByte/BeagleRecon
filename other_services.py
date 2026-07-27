import subprocess
import xml.etree.ElementTree as ET

class OtherServicesScanner:
    def __init__(self, ip, ports):
        self.ip = ip
        self.ports = ports  # list of port numbers

    def scan(self):
        if not self.ports:
            return {}
        port_str = ",".join(map(str, self.ports))
        cmd = ["nmap", "-sCV", "-p", port_str, self.ip, "-oX", "-"]
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True)
        root = ET.fromstring(proc.stdout)

        results = {}
        for port_elem in root.findall(".//port"):
            portid = port_elem.get("portid")
            service = port_elem.find("service")
            name = service.get("name") if service is not None else "unknown"
            product = service.get("product", "")
            version = service.get("version", "")
            results[portid] = f"{name} {product} {version}".strip()
        return results