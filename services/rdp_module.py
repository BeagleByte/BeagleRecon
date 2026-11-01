from services.service_module import ServiceModule


class RdpModule(ServiceModule):
    service_name = "rdp"
    default_ports = (3389,)

    def grab_banner(self, ip: str, port: int) -> str:
        return ""

    def nmap_scripts(self) -> list[str]:
        return ["rdp-ntlm-info"]
