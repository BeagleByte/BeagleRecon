import socket


class DnsResolver:
    def resolve(self, ip: str, timeout: float = 3.0) -> str | None:
        try:
            socket.setdefaulttimeout(timeout)
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname if hostname != ip else None
        except (socket.herror, socket.gaierror, OSError):
            return None
