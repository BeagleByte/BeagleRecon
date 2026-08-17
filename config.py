import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()


def _env(key, default):
    return os.getenv(key, default)


@dataclass
class Config:
    target: str = ""

    ollama_base_url: str = field(default_factory=lambda: _env("OLLAMA_BASE_URL", "http://localhost:11434"))
    chat_model: str = field(default_factory=lambda: _env("OLLAMA_CHAT_MODEL", "granite4:3b"))
    chat_num_ctx: int = 4096
    chat_num_predict: int = 1024
    chat_timeout: float = 1200.0

    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", "data")))
    output_dir: Path = field(default_factory=lambda: Path(_env("OUTPUT_DIR", "output")))

    ports: str = field(default_factory=lambda: _env("PORTS", "0-65535"))
    udp_ports: str = field(default_factory=lambda: _env("UDP_PORTS", "0-65535"))
    scan_udp: bool = True
    banner_timeout: float = 5.0

    min_cve_year: int = field(default_factory=lambda: int(_env("MIN_CVE_YEAR", "2010")))

    run_nmap_scripts: bool = True
    use_intel: bool = True

    top_k: int = 20
    source_limit: int = 0

    exploits_url: str = field(default_factory=lambda: _env(
        "EXPLOITS_URL",
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv",
    ))
    advisory_repo_url: str = field(default_factory=lambda: _env(
        "ADVISORY_REPO_URL",
        "https://github.com/github/advisory-database",
    ))
