import nmap
from rich.console import Console

from config import Config
from core.open_port import OpenPort


class PortScanner:
    def __init__(self, config: Config):
        self.config = config
        self.console = Console()

    def scan(self, target: str) -> list[OpenPort]:
        ports = self._scan_protocol(target, "tcp", self.config.ports)
        if self.config.scan_udp:
            try:
                ports.extend(self._scan_protocol(target, "udp", self.config.udp_ports))
            except RuntimeError as exc:
                self.console.print(
                    f"[yellow]UDP scan skipped: {exc}[/yellow]\n"
                    "[yellow]UDP scans need root - run with sudo, or use --no-udp[/yellow]"
                )
        return ports

    def _scan_protocol(self, target: str, protocol: str, ports: str) -> list[OpenPort]:
        if protocol == "udp":
            return self._run_scan(target, ports, "-sU --open -T4", protocol)
        try:
            return self._run_scan(target, ports, "-sS --open -T4", protocol)
        except RuntimeError as exc:
            if not self._is_privilege_error(exc):
                raise
            self.console.print("[yellow]-sS needs root privileges, falling back to -sT[/yellow]")
            return self._run_scan(target, ports, "-sT --open -T4", protocol)

    def _run_scan(self, target: str, ports: str, arguments: str,
                  protocol: str) -> list[OpenPort]:
        scanner = nmap.PortScanner()
        try:
            scanner.scan(hosts=target, ports=ports, arguments=arguments)
        except nmap.PortScannerError as exc:
            raise RuntimeError(f"nmap scan failed: {exc}") from exc

        open_ports = []
        for host in scanner.all_hosts():
            for port, data in scanner[host].get(protocol, {}).items():
                if data.get("state") == "open":
                    open_ports.append(OpenPort(
                        port=int(port),
                        protocol=protocol,
                        state=data.get("state", "open"),
                        service_name=data.get("name", "unknown"),
                    ))
        return open_ports

    def _is_privilege_error(self, exc: Exception) -> bool:
        message = str(exc).lower()
        return "root" in message or "privilege" in message
