from services.service_module import ServiceModule


class HttpModule(ServiceModule):
    service_name = "http"
    default_ports = (80, 8000, 8008, 8080, 8081, 8888, 9000)

    def grab_banner(self, ip: str, port: int) -> str:
        probe = f"GET / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: BeagleRecon\r\n\r\n".encode()
        banner = self._recv_banner(ip, port, probe=probe)
        return self._extract_headers(banner)

    def nmap_scripts(self) -> list[str]:
        return ["http-title", "http-server-header", "http-methods"]

    def _extract_headers(self, banner: str) -> str:
        lines = banner.splitlines()
        headers = [line for line in lines if line and not line.startswith("<!DOCTYPE")
                   and not line.startswith("<html") and not line.startswith("<head")]
        return "\n".join(headers[:10])
