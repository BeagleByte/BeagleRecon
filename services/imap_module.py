from services.service_module import ServiceModule


class ImapModule(ServiceModule):
    service_name = "imap"
    default_ports = (143, 993)

    def grab_banner(self, ip: str, port: int) -> str:
        if port == 993:
            return self._recv_banner(ip, port, use_ssl=True)
        return self._recv_banner(ip, port)
