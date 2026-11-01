from dataclasses import dataclass, field


@dataclass
class CveFinding:
    cve_ids: list[str] = field(default_factory=list)
    title: str = ""
    vendor: str = ""
    severity: str = ""
    source: str = ""
    url: str = ""
    score: float = 0.0
    description: str = ""
