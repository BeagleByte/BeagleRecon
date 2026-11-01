from services.service_module import ServiceModule


class SmtpModule(ServiceModule):
    service_name = "smtp"
    default_ports = (25, 587)

    def grab_banner(self, ip: str, port: int) -> str:
        return self._recv_banner(ip, port)

    def nmap_scripts(self) -> list[str]:
        return ["smtp-commands", "smtp-enum-users"]
