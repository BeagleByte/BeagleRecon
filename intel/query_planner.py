from config import Config
from core.service_info import ServiceInfo
from intel.search_query import SearchQuery


class QueryPlanner:
    """Builds one deterministic FTS query per service from the scan data.

    No LLM involved: the query is derived purely from the product/version
    tokens nmap reported, so results are reproducible."""

    def __init__(self, config: Config):
        self.config = config

    def plan_queries(self, services: list[ServiceInfo]) -> list[SearchQuery]:
        return [
            SearchQuery(
                text=self._heuristic_query(service),
                port=service.port,
                protocol=service.protocol,
            )
            for service in services
        ]

    def _heuristic_query(self, service: ServiceInfo) -> str:
        parts = [service.product, service.version, service.name, service.extrainfo]
        identifier = " ".join(part for part in parts if part).strip() or service.name
        return f"{identifier} CVE vulnerability exploit"
