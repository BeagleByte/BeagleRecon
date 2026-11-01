from dataclasses import dataclass, field


@dataclass
class RetrievalResult:
    chunk_id: str
    text: str
    collection: str
    metadata: dict = field(default_factory=dict)
    score: float = 0.0
    rank: int = 0
