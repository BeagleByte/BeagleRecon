
import re
import socket
from datetime import datetime
from pathlib import Path

import requests
import urllib3
from rich.console import Console

from Fuzzing.Scanner.ferox_scanner import FeroxScanner
from Fuzzing.Scanner.ffuf_scanner import FfufScanner
from Fuzzing.Scanner.tool_runner import ToolRunner
from config import Config

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebReconRunner:
    """Deterministic stage 2: feroxbuster + ffuf against every target URL."""

    def __init__(self, config: Config):
        self.config = config
        self.console = Console()
        runner = ToolRunner()
        self.ferox = FeroxScanner(config, runner)
        self.ffuf = FfufScanner(config, runner)

    def run(self, domain: str, ip: str, ports: list[int],
            wordlists: dict[str, str]) -> Path:
        self.config.web_output_dir.mkdir(parents=True, exist_ok=True)
        resolved = self._check_dns(domain, ip)
        urls = [
            f"https://{domain}:{port}" if port == 443 else f"http://{domain}:{port}"
            for port in ports
        ]

        ferox_results: dict[str, str] = {}
        ffuf_results: dict[str, str] = {}
        for url in urls:
            self._remove_stale_results(url)
            if not self._is_http(url):
                self.console.print(f"[yellow]skipping {url} - no HTTP response[/yellow]")
                ferox_results[url] = "Skipped: no HTTP response within 5s."
                ffuf_results[url] = "Skipped: no HTTP response within 5s."
                continue
            self.console.print(f"[cyan]feroxbuster[/cyan] {url}")
            ferox_results[url] = self.ferox.execute(
                url, wordlists["dirs"], self.config.ferox_threads
            )
            self.console.print(f"[cyan]ffuf directories[/cyan] {url}")
            parts = [
                self.ffuf.directories(url, wordlists["dirs"], self.config.ffuf_threads)
            ]
            self.console.print(f"[cyan]ffuf api[/cyan] {url}")
            parts.append(
                self.ffuf.api(url, wordlists["api"], self.config.ffuf_threads)
            )
            if domain != self._host_from_url(url):
                self.console.print(f"[cyan]ffuf vhost[/cyan] {url}")
                parts.append(self.ffuf.vhost(url, domain, wordlists["vhost"],
                                             self.config.ffuf_threads))
            ffuf_results[url] = "\n".join(parts)

        return self._write_report(domain, ip, resolved, urls,
                                  ferox_results, ffuf_results)

    def _is_http(self, url: str) -> bool:
        """Pre-flight check: does this URL answer a plain GET quickly?

        Non-HTTP services (e.g. tcpwrapped ports) would otherwise hang the
        fuzzers for hours - every request timing out."""
        try:
            requests.get(url, timeout=5, verify=False)
            return True
        except requests.RequestException:
            return False

    def discover_http_ports(self, ip: str) -> list[int]:
        """Look for the latest stage-1 report for this IP and return its http/https ports."""
        reports = sorted(Path(self.config.output_dir).glob("*.md"), reverse=True)
        for report in reports:
            if ip not in report.name:
                continue
            matches = re.findall(
                r"^\| (\d+) \| tcp \| (http|https|ipp)",
                report.read_text(encoding="utf-8"), re.MULTILINE,
            )
            ports = [int(port) for port, _ in matches]
            if ports:
                return ports
        return []

    def _check_dns(self, domain: str, ip: str) -> str:
        try:
            resolved_ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return (f"{domain} does not resolve - add '{ip} {domain}' "
                    f"to /etc/hosts (CTFs have no DNS server)")
        if resolved_ip != ip:
            return (f"{domain} resolves to {resolved_ip}, not {ip} - "
                    f"fix your /etc/hosts entry")
        return f"{domain} -> {resolved_ip} OK"

    def _host_from_url(self, url: str) -> str:
        return url.split("://")[1].split("/")[0]

    def _remove_stale_results(self, url: str) -> None:
        host = self._host_from_url(url).replace(":", "_")
        for pattern in (f"ferox_{host}.json", f"ffuf_dirs_{host}.json",
                        f"ffuf_vhost_{host}.json", f"ffuf_api_{host}.json"):
            stale = self.config.web_output_dir / pattern
            if stale.exists():
                stale.unlink()

    def _write_report(self, domain: str, ip: str, resolved: str, urls: list[str],
                      ferox_results: dict[str, str],
                      ffuf_results: dict[str, str]) -> Path:
        path = self.config.web_output_dir / (
            datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + f"_{domain}_web.md"
        )
        lines = [
            "# Web Recon Report", "",
            f"- **Domain:** {domain}",
            f"- **IP:** {ip}",
            f"- **DNS:** {resolved}",
            f"- **Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "",
            "## Targets", "",
        ]
        lines += [f"- {url}" for url in urls]
        lines += ["", "## Feroxbuster", ""]
        for url, summary in ferox_results.items():
            lines += [f"### {url}", "", summary, ""]
        lines += ["## Ffuf", ""]
        for url, summary in ffuf_results.items():
            lines += [f"### {url}", "", summary, ""]
        path.write_text("\n".join(lines), encoding="utf-8")
        return path
