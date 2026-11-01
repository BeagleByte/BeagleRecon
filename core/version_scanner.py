import nmap

from config import Config
from core.open_port import OpenPort
from core.service_info import ServiceInfo


class VersionScanner:
    def __init__(self, config: Config):
        self.config = config

    def scan(self, target: str, open_ports: list[OpenPort]) -> dict[tuple[int, str], ServiceInfo]:
        results: dict[tuple[int, str], ServiceInfo] = {}
        for protocol in ("tcp", "udp"):
            ports = [p.port for p in open_ports if p.protocol == protocol]
            if not ports:
                continue
            results.update(self._scan_protocol(target, protocol, ports))
        return results

    def _scan_protocol(self, target: str, protocol: str, ports: list[int]) -> dict[tuple[int, str], ServiceInfo]:
        ports_str = ",".join(str(p) for p in sorted(set(ports)))
        arguments = f"-sV --version-light -s{'U' if protocol == 'udp' else 'T'} --open -T4"
        scanner = nmap.PortScanner()
        try:
            scanner.scan(hosts=target, ports=ports_str, arguments=arguments)
        except nmap.PortScannerError as exc:
            raise RuntimeError(f"version scan failed: {exc}") from exc

        results: dict[tuple[int, str], ServiceInfo] = {}
        for host in scanner.all_hosts():
            for port, data in scanner[host].get(protocol, {}).items():
                if data.get("state") != "open":
                    continue
                service = data.get("service", data)
                results[(int(port), protocol)] = ServiceInfo(
                    port=int(port),
                    protocol=protocol,
                    name=service.get("name", "unknown"),
                    product=service.get("product", "") or "",
                    version=service.get("version", "") or "",
                    extrainfo=service.get("extrainfo", "") or "",
                    cpe=service.get("cpe", "") or "",
                )
        return results
