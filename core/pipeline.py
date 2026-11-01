from datetime import datetime
from pathlib import Path

from rich.console import Console

from config import Config
from core.dns_resolver import DnsResolver
from core.nmap_script_runner import NmapScriptRunner
from core.port_scanner import PortScanner
from core.report_writer import MarkdownReportWriter
from core.scan_result import ScanResult
from core.service_info import ServiceInfo
from core.version_scanner import VersionScanner
from intel.intel_service import IntelService
from services.service_registry import ServiceRegistry


class ReconPipeline:
    def __init__(self, config: Config, port_scanner: PortScanner,
                 version_scanner: VersionScanner, dns_resolver: DnsResolver,
                 script_runner: NmapScriptRunner, registry: ServiceRegistry,
                 intel_service: IntelService | None, report_writer: MarkdownReportWriter):
        self.config = config
        self.port_scanner = port_scanner
        self.version_scanner = version_scanner
        self.dns_resolver = dns_resolver
        self.script_runner = script_runner
        self.registry = registry
        self.intel_service = intel_service
        self.report_writer = report_writer
        self.console = Console()

    def run(self, target: str) -> Path:
        self.console.print(f"[bold]BeagleRecon[/bold] starting scan of {target}")

        hostname = self.dns_resolver.resolve(target)
        if hostname:
            self.console.print(f"  DNS: [green]{hostname}[/green]")

        open_ports = self.port_scanner.scan(target)
        self.console.print(f"  Open ports: {len(open_ports)}")
        for port in open_ports:
            self.console.print(f"    - {port.port}/{port.protocol}")

        banners = self._grab_banners(target, open_ports)
        self.console.print("  Banners collected")

        version_results = self.version_scanner.scan(target, open_ports)
        self.console.print("  Version scan complete")

        services = self._build_services(open_ports, version_results, banners)
        if self.config.run_nmap_scripts:
            self._run_module_tools(target, services)

        scan_result = ScanResult(ip=target, hostname=hostname,
                                 scanned_at=datetime.now(), services=services)

        analysis_markdown = self._run_intel(scan_result)
        report_content = self._build_report(scan_result, analysis_markdown)
        path = self.report_writer.write(report_content, target, hostname)
        self.console.print(f"[bold green]Report saved:[/bold green] {path}")
        return path

    def _grab_banners(self, target: str, open_ports: list) -> dict[tuple[int, str], str]:
        banners: dict[tuple[int, str], str] = {}
        for port in open_ports:
            module = self.registry.get_for_port(port.port, port.protocol)
            banners[(port.port, port.protocol)] = module.grab_banner(target, port.port)
        return banners

    def _build_services(self, open_ports: list, version_results: dict,
                        banners: dict) -> list[ServiceInfo]:
        services: list[ServiceInfo] = []
        for port in open_ports:
            key = (port.port, port.protocol)
            service = version_results.get(key) or ServiceInfo(
                port=port.port,
                protocol=port.protocol,
                name=port.service_name,
            )
            module = self.registry.get_for_port(port.port, port.protocol)
            service.module = module.service_name
            service.banner = banners.get(key, "")
            services.append(service)
        return services

    def _run_module_tools(self, target: str, services: list[ServiceInfo]) -> None:
        for service in services:
            module = self.registry.get_for_port(service.port, service.protocol)
            scripts = module.nmap_scripts()
            if scripts:
                service.tool_results.update(
                    self.script_runner.run_scripts(
                        target, service.port, service.protocol, scripts
                    )
                )
            for tool in module.additional_tools():
                try:
                    service.tool_results[tool.name] = tool.run(target, service.port)
                except Exception as exc:
                    service.tool_results[tool.name] = f"tool failed: {exc}"

    def _run_intel(self, scan_result: ScanResult) -> str:
        if self.intel_service is None or not self.config.use_intel:
            return "_CVE analysis disabled._"
        if not self.intel_service.ready():
            self.console.print("[yellow]Search index is empty; run --ingest first[/yellow]")
            return "_No CVE analysis available: search index is empty. Run ingestion first._"
        self.console.print("  Querying CVE knowledge base")
        analyses = self.intel_service.analyze(scan_result)
        markdown = self.intel_service.synthesize(scan_result, analyses)
        self.console.print("  Vulnerability analysis complete")
        return markdown

    def _build_report(self, scan_result: ScanResult, analysis_markdown: str) -> str:
        lines = [
            "# BeagleRecon Report",
            "",
            f"- **IP:** {scan_result.ip}",
            f"- **DNS:** {scan_result.hostname or 'unknown'}",
            f"- **Date:** {scan_result.scanned_at.strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Open Ports",
            "",
            "| Port | Protocol | Service | Product | Version | Extra |",
            "|------|----------|---------|---------|---------|-------|",
        ]
        for service in scan_result.services:
            lines.append(
                f"| {service.port} | {service.protocol} | {service.name} | "
                f"{service.product} | {service.version} | {service.extrainfo} |"
            )
        lines.append("")

        for service in scan_result.services:
            lines.append(f"## Service {service.port}/{service.protocol} {service.display}")
            lines.append("")
            if service.banner:
                lines.append("### Banner")
                lines.append("```text")
                lines.append(service.banner)
                lines.append("```")
                lines.append("")
            for tool_name, output in service.tool_results.items():
                lines.append(f"### {tool_name}")
                lines.append("```text")
                lines.append(output)
                lines.append("```")
                lines.append("")

        lines.append("## Vulnerability Analysis")
        lines.append("")
        lines.append(analysis_markdown)
        lines.append("")
        return "\n".join(lines)
