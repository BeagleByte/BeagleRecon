import socket
import ssl
from abc import ABC, abstractmethod

from services.tool import Tool


class ServiceModule(ABC):
    service_name = "generic"
    default_ports: tuple[int, ...] = ()
    protocol = "tcp"

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    @abstractmethod
    def grab_banner(self, ip: str, port: int) -> str:
        """Return the banner string or an error description."""

    def nmap_scripts(self) -> list[str]:
        return []

    def additional_tools(self) -> list[Tool]:
        return []

    def matches_port(self, port: int) -> bool:
        return port in self.default_ports

    def _recv_banner(self, ip: str, port: int, probe: bytes | None = None,
                     use_ssl: bool = False, buffer: int = 4096) -> str:
        try:
            with socket.create_connection((ip, port), self.timeout) as sock:
                if use_ssl:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    with context.wrap_socket(sock) as tls_sock:
                        if probe:
                            tls_sock.sendall(probe)
                        data = tls_sock.recv(buffer)
                else:
                    if probe:
                        sock.sendall(probe)
                    data = sock.recv(buffer)
                return data.decode(errors="replace").strip()
        except Exception as exc:
            return f"{self.service_name} banner grab failed: {exc}"
