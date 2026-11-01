from services.service_module import ServiceModule


class TelnetModule(ServiceModule):
    service_name = "telnet"
    default_ports = (23,)

    def grab_banner(self, ip: str, port: int) -> str:
        return self._recv_banner(ip, port)
