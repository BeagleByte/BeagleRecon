from services.service_module import ServiceModule


class SnmpModule(ServiceModule):
    service_name = "snmp"
    default_ports = (161, 162)
    protocol = "udp"

    def grab_banner(self, ip: str, port: int) -> str:
        return ""

    def nmap_scripts(self) -> list[str]:
        return ["snmp-sysdescr", "snmp-info"]
