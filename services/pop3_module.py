from services.service_module import ServiceModule


class Pop3Module(ServiceModule):
    service_name = "pop3"
    default_ports = (110, 995)

    def grab_banner(self, ip: str, port: int) -> str:
        if port == 995:
            return self._recv_banner(ip, port, use_ssl=True)
        return self._recv_banner(ip, port)
