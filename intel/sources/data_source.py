from abc import ABC, abstractmethod
from pathlib import Path
from typing import Iterator

from config import Config
from intel.chunk import Chunk


class DataSource(ABC):
    name: str = ""
    collection: str = ""
    id_prefix: str = ""

    def __init__(self, config: Config):
        self.config = config

    @abstractmethod
    def ensure_local(self, update: bool = False) -> Path:
        """Ensure the local copy of the data exists and return its path."""

    @abstractmethod
    def iter_chunks(self, limit: int = 0) -> Iterator[Chunk]:
        """Yield chunks from the local data. limit=0 means unlimited."""
