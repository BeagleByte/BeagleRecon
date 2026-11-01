from dataclasses import dataclass, field


@dataclass
class ServiceInfo:
    port: int
    protocol: str = "tcp"
    name: str = "unknown"
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    cpe: str = ""
    banner: str = ""
    module: str = "generic"
    tool_results: dict[str, str] = field(default_factory=dict)

    @property
    def display(self) -> str:
        parts = [self.name]
        if self.product:
            parts.append(self.product)
        if self.version:
            parts.append(self.version)
        return " ".join(parts)
