import hashlib
import json
import re
import sqlite3
from typing import Iterator

from rich.console import Console

from config import Config
from intel.retrieval_result import RetrievalResult
from intel.sources.data_source import DataSource

HASH_KEY = "content_hash"


class FtsIndex:
    TOKEN_PATTERN = re.compile(r"[a-z0-9][a-z0-9.\-_:+/]{1,}")

    def __init__(self, config: Config):
        self.config = config
        self.path = config.data_dir / "fts.db"
        self.console = Console()
        self._connection: sqlite3.Connection | None = None

    @property
    def connection(self) -> sqlite3.Connection:
        if self._connection is None:
            self._connection = sqlite3.connect(self.path)
        return self._connection

    def exists(self) -> bool:
        return self.path.exists() and self.count() > 0

    def count(self) -> int:
        if not self.path.exists():
            return 0
        return self.connection.execute("SELECT COUNT(*) FROM chunks").fetchone()[0]

    def build(self, sources: list[DataSource], update: bool = False, reset: bool = False,
              limit: int = 0) -> int:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = self.connection
        if reset:
            connection.execute("DROP TABLE IF EXISTS chunks")
        connection.execute(
            "CREATE VIRTUAL TABLE IF NOT EXISTS chunks USING fts5("
            "id UNINDEXED, collection UNINDEXED, text, meta UNINDEXED)"
        )
        stored = 0
        for source in sources:
            self.console.print(f"[bold cyan]Indexing[/bold cyan] {source.name}")
            source.ensure_local(update=update)
            stored += self._insert_chunks(
                connection,
                source.iter_chunks(limit=limit or self.config.source_limit),
                self._load_existing(connection) if not reset else {},
            )
            self.console.print(f"[green]Done[/green] {source.name}")
        self.console.print(f"[bold green]FTS index total:[/bold green] {stored} rows")
        return stored

    def _load_existing(self, connection: sqlite3.Connection) -> dict[str, str]:
        existing: dict[str, str] = {}
        for chunk_id, meta in connection.execute("SELECT id, meta FROM chunks"):
            try:
                parsed = json.loads(meta) if meta else {}
            except json.JSONDecodeError:
                parsed = {}
            existing[chunk_id] = parsed.get(HASH_KEY, "")
        return existing

    def _insert_chunks(self, connection: sqlite3.Connection, chunks: Iterator,
                       existing: dict[str, str]) -> int:
        inserted = 0
        for chunk in chunks:
            content_hash = hashlib.sha256(chunk.text.encode("utf-8", "replace")).hexdigest()[:16]
            if chunk.id in existing and existing[chunk.id] == content_hash:
                continue
            metadata = dict(chunk.metadata)
            metadata[HASH_KEY] = content_hash
            if chunk.id in existing:
                connection.execute("DELETE FROM chunks WHERE id = ?", (chunk.id,))
            connection.execute(
                "INSERT INTO chunks (id, collection, text, meta) VALUES (?, ?, ?, ?)",
                (chunk.id, chunk.collection, chunk.text, json.dumps(metadata, ensure_ascii=False)),
            )
            inserted += 1
            if inserted % 5000 == 0:
                connection.commit()
                self.console.print(f"  + {inserted} rows")
        connection.commit()
        return inserted

    def search(self, query_text: str, top_k: int = 20) -> list[RetrievalResult]:
        terms = self._query_terms(query_text)
        if not terms:
            return []
        match = " OR ".join(f'"{term}"' for term in terms[:16])
        rows = self.connection.execute(
            "SELECT id, collection, text, meta, bm25(chunks) AS rank "
            "FROM chunks WHERE chunks MATCH ? ORDER BY rank LIMIT ?",
            (match, top_k),
        ).fetchall()
        results = []
        for rank, (chunk_id, collection, text, meta, bm25_score) in enumerate(rows, start=1):
            results.append(RetrievalResult(
                chunk_id=chunk_id,
                text=text,
                collection=collection,
                metadata=json.loads(meta) if meta else {},
                score=float(-bm25_score),
                rank=rank,
            ))
        return results

    def _query_terms(self, query_text: str) -> list[str]:
        terms = []
        for term in self.TOKEN_PATTERN.findall(query_text.lower()):
            if len(term) > 1 and term not in terms:
                terms.append(term)
        return terms
