from dataclasses import dataclass


@dataclass
class SearchQuery:
    text: str
    port: int
    protocol: str = "tcp"
