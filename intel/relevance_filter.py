import re

from core.service_info import ServiceInfo
from intel.retrieval_result import RetrievalResult

IGNORED_NAMES = {"", "unknown", "tcpwrapped", "generic"}
GENERIC_NAMES = {"ftp", "http", "https", "ssh", "irc", "smtp", "ipp", "smb",
                 "rdp", "pop3", "imap", "telnet", "dns", "snmp", "rtsp", "rpc"}


class RelevanceFilter:
    def __init__(self, version_boost: float = 0.02):
        self.version_boost = version_boost

    def filter(self, service: ServiceInfo, results: list[RetrievalResult]) -> list[RetrievalResult]:
        product_tokens = self._product_tokens(service)
        version_tokens = self._version_tokens(service)

        if product_tokens:
            matched = [result for result in results
                       if self._is_relevant(result, product_tokens)]
        elif service.name not in IGNORED_NAMES and service.name not in GENERIC_NAMES:
            matched = [r for r in results if self._matches_any(r.text, [service.name])]
        else:
            matched = self._match_by_port(service, results)

        for result in matched:
            if self._matches_any(result.text, version_tokens):
                result.score += self.version_boost
        matched.sort(key=lambda item: item.score, reverse=True)
        for rank, item in enumerate(matched, start=1):
            item.rank = rank
        return matched

    def _is_relevant(self, result: RetrievalResult, product_tokens: list[str]) -> bool:
        if result.collection == "advisories":
            package_text = " ".join(
                str(result.metadata.get(key, "")) for key in ("package", "packages")
            ).lower()
            return self._matches_any(package_text, product_tokens)
        return self._matches_any(result.text, product_tokens)

    def _product_tokens(self, service: ServiceInfo) -> list[str]:
        tokens = []
        for part in service.product.split():
            token = part.strip().lower()
            if token and token not in IGNORED_NAMES:
                tokens.append(token)
        return tokens

    def _version_tokens(self, service: ServiceInfo) -> list[str]:
        tokens = []
        for match in re.finditer(r"\d+(?:\.\d+)+", service.version):
            tokens.append(match.group(0))
        return tokens

    def _match_by_port(self, service: ServiceInfo,
                       results: list[RetrievalResult]) -> list[RetrievalResult]:
        port_marker = f"port: {service.port}"
        return [r for r in results if port_marker in r.text.lower()]

    def _matches_any(self, text: str, tokens: list[str]) -> bool:
        lowered = text.lower()
        for token in tokens:
            if token and re.search(rf"(?<![a-z0-9]){re.escape(token)}(?![a-z0-9])", lowered):
                return True
        return False
