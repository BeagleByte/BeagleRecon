from dataclasses import dataclass, field


@dataclass
class Chunk:
    id: str
    text: str
    collection: str
    metadata: dict = field(default_factory=dict)
