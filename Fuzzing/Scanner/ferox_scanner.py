import json
from pathlib import Path

from Fuzzing.Scanner.tool_runner import ToolRunner
from config import Config


class FeroxScanner:
    """Deterministic feroxbuster directory enumeration."""

    def __init__(self, config: Config, runner: ToolRunner):
        self.config = config
        self.runner = runner

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
        return self.summarize(output_file)

    def summarize(self, output_file: Path) -> str:
        # feroxbuster 2.x writes JSON Lines: the first line is configuration
        # metadata, every following line is one result object with 'url'.
        entries = []
        for line in output_file.read_text().splitlines():
            entry = json.loads(line)
            if "url" in entry:
                entries.append(entry)
        top = "\n".join(
            f"- {entry.get('status')} {entry.get('url')}" for entry in entries[:15]
        )
        return f"{len(entries)} directories found.\n{top}"
