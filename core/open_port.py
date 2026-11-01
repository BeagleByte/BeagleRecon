from dataclasses import dataclass


@dataclass
class OpenPort:
    port: int
    protocol: str
    state: str = "open"
    service_name: str = "unknown"
