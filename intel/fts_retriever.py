from intel.fts_index import FtsIndex
from intel.retrieval_result import RetrievalResult


class FtsRetriever:
    def __init__(self, index: FtsIndex):
        self.index = index

    def retrieve(self, query_text: str, top_k: int = 20) -> list[RetrievalResult]:
        return self.index.search(query_text, top_k)
