from services.service_module import ServiceModule


class HttpsModule(ServiceModule):
    service_name = "https"
    default_ports = (443, 8443)

    def grab_banner(self, ip: str, port: int) -> str:
        probe = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: BeagleRecon\r\n\r\n".encode()
        return self._recv_banner(ip, port, probe=probe, use_ssl=True)

    def nmap_scripts(self) -> list[str]:
        return ["ssl-cert", "ssl-enum-ciphers"]
