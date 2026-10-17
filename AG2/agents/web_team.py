import json
import re
import socket
from datetime import datetime
from pathlib import Path
from autogen import UserProxyAgent
from AG2.agents.ferox_agent import FeroxAgent
from AG2.agents.ffuf_agent import FfufAgent
from AG2.agents.agents_model_factory import ModelFactory
from AG2.agents.tool_runner import ToolRunner
from config import Config


class WebReconTeam:
    def __init__(self, config: Config):
        self.config = config
        factory = ModelFactory(config)
        runner = ToolRunner()
        # The coordinator executes the agents' tool calls - it must exist
        # before the agents so it can be registered as their executor.
        self.coordinator = UserProxyAgent(
            name="coordinator",
            human_input_mode="NEVER",
            code_execution_config=False,
        )
        self.ferox = FeroxAgent(config, factory, runner, executor=self.coordinator)
        self.ffuf = FfufAgent(config, factory, runner, executor=self.coordinator)

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
            ferox_results[url] = self._run_ferox_with_fallback(url, wordlists["dirs"])
            ffuf_results[url] = self._run_ffuf_with_fallback(url, domain, wordlists)

        return self._write_report(domain, ip, resolved, urls,
                                  ferox_results, ffuf_results)

    def _run_ferox_with_fallback(self, url: str, wordlist: str) -> str:
        task = (f"Enumerate all directories on {url} with wordlist "
                f"{wordlist}. Call run_ferox and summarize.")
        chat = self.coordinator.initiate_chat(
            self.ferox.agent, message=task, max_turns=3, silent=True
        )
        summary = chat.summary or self._last_text(chat)
        if self._ferox_executed(url):
            if summary:
                return summary
            # Tool ran but the model's summary was cut off by max_turns -
            # re-read the results and summarize in a fresh one-turn chat.
            raw = self.ferox._summarize(self._result_file("ferox", url))
            return self._summarize_with_agent(self.ferox.agent, raw) or raw
        # The model roleplayed the tool call instead of emitting one - run the
        # tool deterministically and let the agent summarize the real results.
        result = self.ferox.execute(url, wordlist, self.config.ferox_threads)
        return self._summarize_with_agent(self.ferox.agent, result) or result

    def _run_ffuf_with_fallback(self, url: str, domain: str,
                                wordlists: dict[str, str]) -> str:
        task = (f"For {url} and domain {domain}: call ffuf_directories with "
                f"{wordlists['dirs']}, ffuf_vhost with {wordlists['vhost']}, "
                f"and ffuf_api with {wordlists['api']}. Summarize all findings.")
        chat = self.coordinator.initiate_chat(
            self.ffuf.agent, message=task, max_turns=5, silent=True
        )
        summary = chat.summary or self._last_text(chat)
        if self._ffuf_executed(url):
            if summary:
                return summary
            raw = self._read_ffuf_results(url)
            return self._summarize_with_agent(self.ffuf.agent, raw) or raw
        parts = [
            self.ffuf.directories(url, wordlists["dirs"], self.config.ffuf_threads),
            self.ffuf.api(url, wordlists["api"], self.config.ffuf_threads),
        ]
        if domain != url.split("://")[1].split("/")[0]:
            parts.append(self.ffuf.vhost(url, domain, wordlists["vhost"],
                                         self.config.ffuf_threads))
        result = "\n".join(parts)
        return self._summarize_with_agent(self.ffuf.agent, result) or result

    def _read_ffuf_results(self, url: str) -> str:
        host = self._host_from_url(url)
        parts = []
        for mode in ("dirs", "api", "vhost"):
            path = self.config.web_output_dir / f"ffuf_{mode}_{host}.json"
            if not path.exists():
                continue
            try:
                data = json.loads(path.read_text())
                top = "\n".join(
                    f"- {r.get('status')} {r.get('url')}"
                    for r in data.get("results", [])[:10]
                )
                parts.append(f"ffuf {mode}: {len(data.get('results', []))} results.\n{top}")
            except (json.JSONDecodeError, OSError):
                continue
        return "\n".join(parts)

    def _summarize_with_agent(self, agent, tool_result: str) -> str:
        """Ask the agent for a short summary of already-executed tool results."""
        try:
            chat = self.coordinator.initiate_chat(
                agent,
                message=("Here are the tool results. Do not call any tools - "
                         f"summarize the findings:\n{tool_result[:4000]}"),
                max_turns=1, silent=True,
            )
            return chat.summary or self._last_text(chat)
        except Exception:
            return ""

    def _ferox_executed(self, url: str) -> bool:
        return self._result_file("ferox", url).exists()

    def _ffuf_executed(self, url: str) -> bool:
        host = self._host_from_url(url)
        return all(
            (self.config.web_output_dir / f"ffuf_{mode}_{host}.json").exists()
            for mode in ("dirs", "api")
        )

    def _result_file(self, prefix: str, url: str) -> Path:
        host = self._host_from_url(url)
        return self.config.web_output_dir / f"{prefix}_{host}.json"

    def _host_from_url(self, url: str) -> str:
        return url.split("://")[1].split("/")[0].replace(":", "_")

    def _remove_stale_results(self, url: str) -> None:
        host = self._host_from_url(url)
        for pattern in (f"ferox_{host}.json", f"ffuf_dirs_{host}.json",
                        f"ffuf_vhost_{host}.json", f"ffuf_api_{host}.json"):
            stale = self.config.web_output_dir / pattern
            if stale.exists():
                stale.unlink()

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

    def _last_text(self, chat) -> str:
        for message in reversed(chat.chat_history):
            if message.get("content"):
                return str(message["content"])[:2000]
        return ""

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