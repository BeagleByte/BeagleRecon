import subprocess
from pathlib import Path

import requests

from config import Config


class DataDownloader:
    def __init__(self, config: Config):
        self.config = config

    def download_file(self, url: str, destination: Path, update: bool = False) -> Path:
        if destination.exists() and not update:
            return destination
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        with requests.get(url, stream=True, timeout=60) as response:
            response.raise_for_status()
            with open(temporary, "wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    handle.write(chunk)
        temporary.replace(destination)
        return destination

    def sync_git_repo(self, url: str, destination: Path, sparse_dirs: tuple[str, ...] = (),
                      update: bool = False) -> Path:
        if not destination.exists():
            self._clone(url, destination, sparse_dirs)
        elif update:
            self._pull(destination)
            if sparse_dirs:
                self._set_sparse(destination, sparse_dirs)
        return destination

    def _clone(self, url: str, destination: Path, sparse_dirs: tuple[str, ...]) -> None:
        command = ["git", "clone", "--depth", "1", "--filter=blob:none"]
        if sparse_dirs:
            command.append("--sparse")
        command.extend([url, str(destination)])
        subprocess.run(command, check=True, capture_output=True, text=True)
        if sparse_dirs:
            self._set_sparse(destination, sparse_dirs)

    def _pull(self, destination: Path) -> None:
        subprocess.run(["git", "-C", str(destination), "pull", "--ff-only"],
                       check=True, capture_output=True, text=True)

    def _set_sparse(self, destination: Path, sparse_dirs: tuple[str, ...]) -> None:
        subprocess.run(["git", "-C", str(destination), "sparse-checkout", "set", *sparse_dirs],
                       check=True, capture_output=True, text=True)
