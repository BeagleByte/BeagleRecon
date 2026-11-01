from dataclasses import dataclass, field
from datetime import datetime

from core.service_info import ServiceInfo


@dataclass
class ScanResult:
    ip: str
    hostname: str | None
    scanned_at: datetime
    services: list[ServiceInfo] = field(default_factory=list)
