import subprocess
from dataclasses import dataclass

@dataclass
class CommandResult:
    command: list[str]
    return_code: int
    stdout: str
    stderr: str

class ToolRunner:
    """Runs external commands with a timeout and captures their output."""

    def __init__(self, timeout: float = 1800.0):
        self.timeout = timeout

    def run(self, command: list[str], timeout: float | None = None) -> CommandResult:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout or self.timeout,
        )
        return CommandResult(
            command=command,
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
        )