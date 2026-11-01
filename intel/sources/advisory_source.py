import json
from pathlib import Path
from typing import Iterator

from config import Config
from intel.chunk import Chunk
from intel.chunker import TextChunker
from intel.sources.data_downloader import DataDownloader
from intel.sources.data_source import DataSource

ADVISORIES_DIR = "advisories/github-reviewed"
MAX_PACKAGE_CHUNKS = 20


class AdvisoryDatabaseSource(DataSource):
    name = "advisory"
    collection = "advisories"
    id_prefix = "ghsa"

    def __init__(self, config: Config):
        super().__init__(config)
        self.downloader = DataDownloader(config)
        self.chunker = TextChunker(max_chars=1500, overlap=150)

    def ensure_local(self, update: bool = False) -> Path:
        return self.downloader.sync_git_repo(
            self.config.advisory_repo_url,
            self.config.data_dir / "advisory-database",
            sparse_dirs=(ADVISORIES_DIR,),
            update=update,
        )

    def iter_chunks(self, limit: int = 0) -> Iterator[Chunk]:
        repo_path = self.ensure_local()
        advisories_dir = repo_path / ADVISORIES_DIR
        json_paths = sorted(advisories_dir.rglob("*.json"), reverse=True)
        produced = 0
        for json_path in json_paths:
            for chunk in self._advisory_to_chunks(json_path):
                yield chunk
                produced += 1
                if limit and produced >= limit:
                    return

    def _advisory_to_chunks(self, json_path: Path) -> list[Chunk]:
        try:
            data = json.loads(json_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return []
        if not self._within_year(data.get("published", "")):
            return []

        ghsa_id = data.get("id") or json_path.stem
        cve_ids = [alias for alias in data.get("aliases", []) if alias.startswith("CVE-")]
        packages = self._extract_packages(data)
        severity = self._extract_severity(data)

        chunks = []
        summary = (data.get("summary") or "").strip()
        details = (data.get("details") or "").strip()
        overview_text = f"GitHub Advisory {ghsa_id} — {summary}"
        if details:
            overview_text += f" {details}"
        overview_text += f" CVE: {' '.join(cve_ids) or 'none'}."
        overview_text += f" Affected packages: {'; '.join(packages[:10]) or 'none'}."

        for index, text in enumerate(self.chunker.chunk(overview_text)):
            chunks.append(Chunk(
                id=f"{self.id_prefix}-{ghsa_id}-{index}",
                text=text,
                collection=self.collection,
                metadata=self._base_metadata(data, ghsa_id, cve_ids, severity, packages),
            ))

        for package_index, package in enumerate(packages[:MAX_PACKAGE_CHUNKS]):
            chunks.append(Chunk(
                id=f"{self.id_prefix}-{ghsa_id}-pkg{package_index}",
                text=package,
                collection=self.collection,
                metadata={
                    "source": self.name,
                    "ghsa_id": ghsa_id,
                    "cves": ";".join(cve_ids),
                    "severity": severity,
                    "published": data.get("published", ""),
                    "package": package,
                    "url": f"https://github.com/advisories/{ghsa_id}",
                },
            ))
        return chunks

    def _base_metadata(self, data: dict, ghsa_id: str, cve_ids: list[str],
                       severity: str, packages: list[str]) -> dict:
        cwe_ids = data.get("database_specific", {}).get("cwe_ids", [])
        return {
            "source": self.name,
            "ghsa_id": ghsa_id,
            "cves": ";".join(cve_ids),
            "severity": severity,
            "published": data.get("published", ""),
            "packages": ";".join(packages[:10]),
            "cwe_ids": ";".join(cwe_ids or []),
            "url": f"https://github.com/advisories/{ghsa_id}",
        }

    def _within_year(self, published: str) -> bool:
        year = (published or "")[:4]
        if not year.isdigit():
            return True
        return int(year) >= self.config.min_cve_year

    def _extract_packages(self, data: dict) -> list[str]:
        packages = []
        for affected in data.get("affected", []):
            package = affected.get("package", {})
            name = package.get("name")
            ecosystem = package.get("ecosystem")
            if not name:
                continue
            entry = f"{ecosystem}/{name} ({self._render_ranges(affected)})".strip()
            packages.append(entry)
        return packages

    def _render_ranges(self, affected: dict) -> str:
        parts = []
        for version_range in affected.get("ranges", []):
            events = version_range.get("events", [])
            introduced = next((e.get("introduced") for e in events if "introduced" in e), None)
            fixed = next((e.get("fixed") for e in events if "fixed" in e), None)
            if introduced or fixed:
                parts.append(f">={introduced or '0'}, <{fixed or 'unfixed'}")
        last_known = affected.get("database_specific", {}).get("last_known_affected_version_range")
        if last_known:
            parts.append(f"<= {last_known}")
        return ", ".join(parts) or "unknown range"

    def _extract_severity(self, data: dict) -> str:
        database_specific = data.get("database_specific", {})
        severity = database_specific.get("severity")
        if severity:
            return severity
        severities = data.get("severity", [])
        if severities:
            return severities[0].get("score", "")
        return ""
