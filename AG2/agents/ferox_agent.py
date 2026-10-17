import json
from pathlib import Path
from typing import Annotated

from autogen import ConversableAgent, register_function

from AG2.agents.agents_model_factory import ModelFactory
from AG2.agents.tool_runner import ToolRunner
from config import Config

class FeroxAgent:
    SYSTEM_PROMPT = (
        "You are an expert for feroxbuster and are supposed to find all "
        "directories in a given http path. For every target URL you receive, "
        "call the run_ferox tool with a suitable wordlist, then report which "
        "directories were found with their HTTP status codes."
    )

    def __init__(self, config: Config, model_factory: ModelFactory, runner: ToolRunner,
                 executor=None):
        self.config = config
        self.runner = runner
        self.agent = ConversableAgent(
            name="ferox_expert",
            system_message=self.SYSTEM_PROMPT,
            llm_config=model_factory.build_llm_config(),
            human_input_mode="NEVER",
        )
        # The executor (usually the coordinator UserProxy) must be the one that
        # runs the tool calls - an agent cannot execute them for itself.
        register_function(
            self._make_run_ferox_tool(),
            caller=self.agent,
            executor=executor or self.agent,
            name="run_ferox",
            description="Run feroxbuster directory enumeration against one http/https URL.",
        )

    def _make_run_ferox_tool(self):
        # AG2's register_for_llm rejects bound methods, so we register a
        # closure (a plain function) that calls our method.
        def run_ferox(
            url: Annotated[str, "full target URL, e.g. http://example.com:80"],
            wordlist: Annotated[str, "absolute path to a wordlist"],
            threads: Annotated[int, "number of threads"] = 50,
        ) -> str:
            return self.execute(url, wordlist, threads)

        return run_ferox

    def execute(self, url: str, wordlist: str, threads: int = 50) -> str:
        host = url.split("://")[1].split("/")[0].replace(":", "_")
        output_file = self.config.web_output_dir / f"ferox_{host}.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        command = [
            "feroxbuster", "-u", url, "-w", wordlist,
            "-t", str(threads), "--depth", "3",
            "--json", "-o", str(output_file),
        ]
        result = self.runner.run(command)
        if result.return_code != 0:
            return f"feroxbuster failed: {result.stderr.strip()[:500]}"
        return self._summarize(output_file)

    def _summarize(self, output_file: Path) -> str:
        # feroxbuster 2.x writes JSON Lines: the first line is configuration
        # metadata, every following line is one result object with 'url'.
        entries = []
        for line in output_file.read_text().splitlines():
            entry = json.loads(line)
            if "url" in entry:
                entries.append(entry)
        top = "\n".join(
            f"- {entry.get('status')} {entry.get('url')}" for entry in entries[:10]
        )
        return f"{len(entries)} directories found.\n{top}"