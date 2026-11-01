class TextChunker:
    def __init__(self, max_chars: int = 1000, overlap: int = 150):
        self.max_chars = max_chars
        self.overlap = overlap

    def chunk(self, text: str) -> list[str]:
        text = text.strip()
        if not text:
            return []
        if len(text) <= self.max_chars:
            return [text]
        chunks = []
        start = 0
        while start < len(text):
            end = min(start + self.max_chars, len(text))
            if end < len(text):
                cut = self._find_cut_point(text, end)
                if cut > start:
                    end = cut
            chunks.append(text[start:end].strip())
            if end >= len(text):
                break
            start = max(end - self.overlap, start + 1)
        return chunks

    def _find_cut_point(self, text: str, end: int) -> int:
        window = text[max(0, end - 200):end]
        for separator in ("\n\n", "\n", ". ", " "):
            position = window.rfind(separator)
            if position >= 0:
                return max(0, end - 200) + position + len(separator)
        return end
