from services.service_module import ServiceModule


class SmbModule(ServiceModule):
    service_name = "smb"
    default_ports = (139, 445)

    def grab_banner(self, ip: str, port: int) -> str:
        return ""

    def nmap_scripts(self) -> list[str]:
        return ["smb-protocols", "smb-os-discovery",
                "smb-vuln-ms17-010", "smb-vuln-ms08-067"]
