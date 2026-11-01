from dataclasses import dataclass, field

from core.cve_finding import CveFinding
from core.service_info import ServiceInfo


@dataclass
class PortAnalysis:
    service: ServiceInfo
    queries: list[str] = field(default_factory=list)
    findings: list[CveFinding] = field(default_factory=list)
