import re
from datetime import datetime
from pathlib import Path

from config import Config


class MarkdownReportWriter:
    def __init__(self, config: Config):
        self.config = config

    def build_filename(self, ip: str, hostname: str | None) -> str:
        date_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        host_part = self._sanitize_hostname(hostname) if hostname else "no-dns"
        return f"{date_str}_{ip}_{host_part}.md"

    def write(self, content: str, ip: str, hostname: str | None) -> Path:
        output_dir = self.config.output_dir
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / self.build_filename(ip, hostname)
        path.write_text(content, encoding="utf-8")
        return path

    def _sanitize_hostname(self, hostname: str) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", hostname)
        return cleaned[:60] or "no-dns"
