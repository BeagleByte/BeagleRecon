from services.service_module import ServiceModule


class SshModule(ServiceModule):
    service_name = "ssh"
    default_ports = (22, 2222)

    def grab_banner(self, ip: str, port: int) -> str:
        banner = self._recv_banner(ip, port)
        return banner.splitlines()[0] if banner else ""
