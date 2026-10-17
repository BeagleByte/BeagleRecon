import json
import random
from pathlib import Path
from typing import Annotated

import requests
import urllib3
from autogen import ConversableAgent, register_function

from AG2.agents.agents_model_factory import ModelFactory
from AG2.agents.tool_runner import ToolRunner
from config import Config

# ffuf filter/matcher reference (comma-separated values, also ranges like 500-599):
#   MATCHER OPTIONS:
#     -mc      Match HTTP status codes, or "all" for everything. (default: 200-299,301,302,307,401,403,405,500)
#     -ml      Match amount of lines in response
#     -mmode   Matcher set operator. Either of: and, or (default: or)
#     -mr      Match regexp
#     -ms      Match HTTP response size
#     -mt      Match how many milliseconds to the first response byte, either greater or less than. EG: >100 or <100
#     -mw      Match amount of words in response
#   FILTER OPTIONS:
#     -fc      Filter HTTP status codes from response. Comma separated list of codes and ranges
#     -fl      Filter by amount of lines in response. Comma separated list of line counts and ranges
#     -fmode   Filter set operator. Either of: and, or (default: or)
#     -fr      Filter regexp
#     -fs      Filter HTTP response size. Comma separated list of sizes and ranges
#     -ft      Filter by number of milliseconds to the first response byte, either greater or less than. EG: >100 or <100
#     -fw      Filter by amount of words in response. Comma separated list of word counts and ranges

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FfufAgent:
    SYSTEM_PROMPT = (
        "You are an expert for ffuf. Your tasks are: 1) find directories, "
        "2) find virtual hosts via the Host header, 3) find API endpoints. "
        "For every target you receive, call ffuf_directories, ffuf_vhost and "
        "ffuf_api with suitable wordlists, then summarize what was found. "
        "Many web apps answer with soft-404 pages (HTTP 200, always the same "
        "body size). The tools auto-calibrate: when you leave filter_size "
        "empty they probe a nonexistent path and pass that size to -fs, so "
        "only real endpoints show up. Pass filter_size yourself when you "
        "already know it, e.g. '612' or '612,0'."
    )

    def __init__(self, config: Config, model_factory: ModelFactory, runner: ToolRunner,
                 executor=None):
        self.config = config
        self.runner = runner
        self.agent = ConversableAgent(
            name="ffuf_expert",
            system_message=self.SYSTEM_PROMPT,
            llm_config=model_factory.build_llm_config(),
            human_input_mode="NEVER",
        )
        # The executor (usually the coordinator UserProxy) must be the one that
        # runs the tool calls - an agent cannot execute them for itself.
        target = executor or self.agent
        register_function(self._make_directories_tool(), caller=self.agent,
                          executor=target, name="ffuf_directories",
                          description="Fuzz directory names on a base URL. Auto-calibrates a -fs size filter against soft-404 pages.")
        register_function(self._make_vhost_tool(), caller=self.agent,
                          executor=target, name="ffuf_vhost",
                          description="Fuzz virtual hosts via the Host header (FUZZ.<domain>). Auto-calibrates with -ac.")
        register_function(self._make_api_tool(), caller=self.agent,
                          executor=target, name="ffuf_api",
                          description="Fuzz API endpoint paths on a base URL. Auto-calibrates a -fs size filter against soft-404 pages.")

    # --- tools (closures: plain functions that call the public methods) ---

    def _make_directories_tool(self):
        def ffuf_directories(
            url: Annotated[str, "base URL, e.g. http://host:port"],
            wordlist: Annotated[str, "absolute path to a wordlist"],
            threads: Annotated[int, "number of threads"] = 40,
            filter_size: Annotated[str, "comma-separated response sizes to filter out, e.g. '612' or '612,0'; empty = auto-calibrate"] = "",
            filter_status: Annotated[str, "comma-separated HTTP status codes to filter out, e.g. '301,302'"] = "",
            matcher_status: Annotated[str, "override: comma-separated status codes to match; empty = ffuf default set"] = "",
        ) -> str:
            return self.directories(url, wordlist, threads,
                                    filter_size, filter_status, matcher_status)

        return ffuf_directories

    def _make_vhost_tool(self):
        def ffuf_vhost(
            url: Annotated[str, "base URL, e.g. http://<ip>:<port>"],
            domain: Annotated[str, "the domain, e.g. hackthebox.htb"],
            wordlist: Annotated[str, "absolute path to a subdomain wordlist"],
            threads: Annotated[int, "number of threads"] = 40,
            filter_size: Annotated[str, "comma-separated response sizes to filter out, e.g. '612'; empty = -ac only"] = "",
            filter_status: Annotated[str, "comma-separated HTTP status codes to filter out"] = "",
        ) -> str:
            return self.vhost(url, domain, wordlist, threads,
                              filter_size, filter_status)

        return ffuf_vhost

    def _make_api_tool(self):
        def ffuf_api(
            url: Annotated[str, "base URL"],
            wordlist: Annotated[str, "absolute path to an API wordlist"],
            threads: Annotated[int, "number of threads"] = 40,
            filter_size: Annotated[str, "comma-separated response sizes to filter out, e.g. '612'; empty = auto-calibrate"] = "",
            filter_status: Annotated[str, "comma-separated HTTP status codes to filter out"] = "",
            matcher_status: Annotated[str, "override: comma-separated status codes to match; empty = ffuf default set"] = "",
        ) -> str:
            return self.api(url, wordlist, threads,
                            filter_size, filter_status, matcher_status)

        return ffuf_api

    # --- public deterministic methods (directly callable in tests) ---

    def directories(self, url: str, wordlist: str, threads: int = 40,
                    filter_size: str = "", filter_status: str = "",
                    matcher_status: str = "") -> str:
        if not filter_size:
            filter_size = self._baseline_filter_size(url)
        return self._run_ffuf("dirs", url, wordlist, threads,
                              ["-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist,
                               "-t", str(threads)]
                              + self._filter_args(filter_size, filter_status, matcher_status))

    def vhost(self, url: str, domain: str, wordlist: str, threads: int = 40,
              filter_size: str = "", filter_status: str = "") -> str:
        return self._run_ffuf("vhost", url, wordlist, threads,
                              ["-u", url, "-H", f"Host: FUZZ.{domain}",
                               "-w", wordlist, "-t", str(threads), "-ac"]
                              + self._filter_args(filter_size, filter_status, ""))

    def api(self, url: str, wordlist: str, threads: int = 40,
            filter_size: str = "", filter_status: str = "",
            matcher_status: str = "") -> str:
        if not filter_size:
            filter_size = self._baseline_filter_size(url)
        return self._run_ffuf("api", url, wordlist, threads,
                              ["-u", f"{url.rstrip('/')}/FUZZ", "-w", wordlist,
                               "-t", str(threads)]
                              + self._filter_args(filter_size, filter_status, matcher_status))

    # --- filter / matcher helpers ---

    def _filter_args(self, filter_size: str, filter_status: str,
                     matcher_status: str) -> list[str]:
        """Turn filter/matcher parameters into ffuf CLI flags."""
        args = []
        if filter_size:
            args += ["-fs", filter_size]
        if filter_status:
            args += ["-fc", filter_status]
        if matcher_status:
            args += ["-mc", matcher_status]
        return args

    def _baseline_filter_size(self, url: str) -> str:
        """Probe a guaranteed-nonexistent path and return its response size.

        Soft-404 pages (HTTP 200 with a fixed body size) are the classic ffuf
        false-positive source - this gives us the exact -fs value without
        guessing."""
        probe = f"{url.rstrip('/')}/beaglerecon-{random.randint(100000, 999999)}.html"
        try:
            response = requests.get(probe, timeout=10, verify=False)
            return str(response.headers.get("Content-Length") or len(response.content))
        except requests.RequestException:
            return ""

    # --- shared execution path ---

    def _run_ffuf(self, mode: str, url: str, wordlist: str, threads: int,
                  ffuf_args: list[str]) -> str:
        host = url.split("://")[1].split("/")[0].replace(":", "_")
        output_file = self.config.web_output_dir / f"ffuf_{mode}_{host}.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        command = ["ffuf", *ffuf_args,
                   "-o", str(output_file), "-of", "json", "-s"]
        result = self.runner.run(command)
        if result.return_code != 0:
            return f"ffuf {mode} failed: {result.stderr.strip()[:500]}"
        data = json.loads(output_file.read_text())
        top = "\n".join(
            f"- {r.get('status')} {r.get('url')}" for r in data.get("results", [])[:10]
        )
        return f"ffuf {mode}: {len(data.get('results', []))} results.\n{top}"
