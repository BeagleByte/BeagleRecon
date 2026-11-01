from config import Config
from core.cve_finding import CveFinding
from core.scan_result import ScanResult
from core.service_info import ServiceInfo
from intel.port_analysis import PortAnalysis
from intel.query_planner import QueryPlanner
from intel.relevance_filter import RelevanceFilter
from intel.retrieval_result import RetrievalResult


class IntelService:
    """Deterministic CVE lookups: FTS5 retrieval + relevance filtering.

    Findings come exclusively from the indexed data, so there is no LLM and
    no hallucination risk - every reported CVE was found in the index."""

    def __init__(self, config: Config, planner: QueryPlanner, retriever):
        self.config = config
        self.planner = planner
        self.retriever = retriever
        self.relevance_filter = RelevanceFilter()

    def ready(self) -> bool:
        return self.retriever.index.exists()

    def analyze(self, scan_result: ScanResult) -> list[PortAnalysis]:
        all_queries = self.planner.plan_queries(scan_result.services)
        analyses: list[PortAnalysis] = []
        for service in scan_result.services:
            service_queries = [
                query for query in all_queries
                if query.port == service.port and query.protocol == service.protocol
            ]
            results: list[RetrievalResult] = []
            for query in service_queries:
                results.extend(self.retriever.retrieve(query.text, top_k=self.config.top_k))
            analyses.append(PortAnalysis(
                service=service,
                queries=[query.text for query in service_queries],
                findings=self._findings_from_results(service, results),
            ))
        return analyses

    def synthesize(self, scan_result: ScanResult,
                   analyses: list[PortAnalysis]) -> str:
        return "\n\n".join(self._section(analysis) for analysis in analyses)

    def _section(self, analysis: PortAnalysis) -> str:
        service = analysis.service
        identity = " ".join(part for part in (service.name, service.product, service.version) if part)
        lines = [f"### {service.port}/{service.protocol} {identity}"]
        if not analysis.findings:
            lines.append("No known CVEs matched for this version.")
        for finding in analysis.findings:
            cve_list = ", ".join(finding.cve_ids) or "no CVE listed"
            vendor = finding.vendor or "unknown vendor"
            link = f" [source]({finding.url})" if finding.url else ""
            lines.append(f"- {cve_list} — {finding.severity or 'n/a'} — {vendor} — "
                         f"{finding.title[:180]}{link}")
        lines.append(f"Confidence: {'high' if analysis.findings else 'low'}")
        return "\n".join(lines)

    def _findings_from_results(self, service: ServiceInfo,
                               results: list[RetrievalResult]) -> list[CveFinding]:
        filtered = self.relevance_filter.filter(service, results)
        merged: dict[tuple, CveFinding] = {}
        for result in filtered:
            finding = self._result_to_finding(result)
            key = (tuple(sorted(finding.cve_ids)) or (result.chunk_id,), result.collection)
            if key in merged:
                merged[key].score = max(merged[key].score, finding.score)
                continue
            merged[key] = finding
        findings = sorted(merged.values(), key=lambda item: item.score, reverse=True)
        return findings[:self.config.top_k]

    def _result_to_finding(self, result: RetrievalResult) -> CveFinding:
        metadata = result.metadata
        if result.collection == "exploits":
            return CveFinding(
                cve_ids=self._split_cves(metadata.get("cves", "")),
                title=self._exploit_title(result.text),
                vendor=metadata.get("platform", ""),
                severity="",
                source="exploitdb",
                url=metadata.get("url", ""),
                score=result.score,
            )
        title = result.text.replace(
            f"GitHub Advisory {metadata.get('ghsa_id', '')} — ", ""
        ).split(" CVE: ")[0][:250]
        return CveFinding(
            cve_ids=self._split_cves(metadata.get("cves", "")),
            title=title,
            vendor=metadata.get("package", metadata.get("packages", "")),
            severity=metadata.get("severity", ""),
            source="github-advisory",
            url=metadata.get("url", ""),
            score=result.score,
        )

    def _split_cves(self, value: str) -> list[str]:
        return [cve.strip() for cve in value.replace(";", " ").split() if cve.strip().startswith("CVE-")]

    def _exploit_title(self, text: str) -> str:
        description = text.removeprefix("ExploitDB: ").split(" | ")[0]
        return description[:250]
