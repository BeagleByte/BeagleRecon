import socket

from services.service_module import ServiceModule
from services.tool import Tool


class FtpModule(ServiceModule):
    service_name = "ftp"
    default_ports = (21, 2121)

    def grab_banner(self, ip: str, port: int) -> str:
        return self._recv_banner(ip, port)

    def nmap_scripts(self) -> list[str]:
        return ["ftp-bounce", "ftp-syst"]

    def additional_tools(self) -> list[Tool]:
        return [Tool(
            name="ftp-anonymous-login",
            description="Check if anonymous FTP login is permitted",
            run=self._check_anonymous_login,
        )]

    def _check_anonymous_login(self, ip: str, port: int) -> str:
        try:
            with socket.create_connection((ip, port), self.timeout) as sock:
                sock.recv(1024)
                sock.sendall(b"USER anonymous\r\n")
                sock.recv(1024)
                sock.sendall(b"PASS anonymous@\r\n")
                response = sock.recv(1024).decode(errors="replace")
                if response.startswith("230"):
                    return f"Anonymous login allowed: {response.strip()}"
                return f"Anonymous login denied: {response.strip()}"
        except Exception as exc:
            return f"Anonymous login check failed: {exc}"
