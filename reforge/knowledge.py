"""Local methodology knowledge base (#1).

Indexes the analyst's reference PDFs/notes on disk and lets the agent consult them
during an investigation. Pure-Python BM25 over per-page chunks, cached to disk so
startup is cheap. No cloud, no heavy deps beyond a PDF text extractor.

Point REFORGE_KNOWLEDGE_DIR at a folder of .pdf/.txt/.md files (your vulnerability-research
books and notes). Each result is returned with its source file and page for citation.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import re
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from . import config

log = logging.getLogger("reforge.knowledge")
_WORD = re.compile(r"[a-z0-9]{2,}")
_STOP = set("the a an of to and or in on for is are be as by with from this that it at "
            "we you it's its can will may use used using into when how what which".split())


def _tok(text: str) -> List[str]:
    return [w for w in _WORD.findall((text or "").lower()) if w not in _STOP]


class _Chunk:
    __slots__ = ("source", "page", "text", "tf", "length")

    def __init__(self, source: str, page: int, text: str):
        self.source = source
        self.page = page
        self.text = text
        toks = _tok(text)
        self.tf = Counter(toks)
        self.length = len(toks)


class KnowledgeBase:
    def __init__(self, directory: Path):
        self.dir = Path(directory)
        self.chunks: List[_Chunk] = []
        self.df: Counter = Counter()
        self.avgdl = 0.0
        self.loaded = False
        self.sources: List[str] = []

    # --- building / caching --------------------------------------------
    def _cache_path(self) -> Path:
        """Where the derived BM25 index is cached.

        Under STATE_ROOT, never next to the documents. The knowledge directory is shipped with the
        product (and may be read-only, or on a share), so a derived index written into it
        contaminated the source tree and the release artifact. The cache key includes the resolved
        knowledge directory so two configured directories cannot collide.
        See docs/adr/0001-config-and-secrets.md.
        """
        cache_dir = Path(config.STATE_ROOT) / "cache"
        cache_dir.mkdir(parents=True, exist_ok=True)
        key = hashlib.sha256(str(self.dir.resolve()).encode("utf-8")).hexdigest()[:16]
        return cache_dir / f"knowledge-index-{key}.json"

    def _signature(self) -> str:
        h = hashlib.md5()
        for f in sorted(self.dir.glob("**/*")):
            if f.suffix.lower() in (".pdf", ".txt", ".md") and f.is_file():
                st = f.stat()
                rel = f.relative_to(self.dir).as_posix()
                h.update(rel.encode("utf-8", errors="ignore"))
                h.update(str(st.st_size).encode())
                h.update(str(st.st_mtime_ns).encode())
        return h.hexdigest()

    def build(self) -> None:
        if not self.dir.is_dir():
            log.info("knowledge dir '%s' is missing; the KB is empty", self.dir)
            self.loaded = True
            return
        cache = self._cache_path()
        sig = self._signature()
        if cache.is_file():
            try:
                data = json.loads(cache.read_text(encoding="utf-8"))
                if data.get("sig") == sig:
                    self._load_cached(data)
                    log.info("KB loaded from cache: %d chunks, %d documents", len(self.chunks), len(self.sources))
                    return
            except Exception:
                pass
        self._index_files()
        self._persist(sig)

    def _index_files(self) -> None:
        files = [f for f in sorted(self.dir.glob("**/*"))
                 if f.suffix.lower() in (".pdf", ".txt", ".md") and f.is_file()]
        for f in files:
            try:
                pages = self._extract(f)
            except Exception as exc:
                log.warning("extraction failed for %s: %s", f.name, exc)
                continue
            source = f.relative_to(self.dir).as_posix()
            self.sources.append(source)
            for pageno, text in pages:
                for piece in self._split(text):
                    if len(piece) >= 120:
                        self.chunks.append(_Chunk(source, pageno, piece))
        self._finalize()
        log.info("KB indexed: %d chunks from %d documents", len(self.chunks), len(self.sources))

    @staticmethod
    def _clean_text(text: str) -> str:
        text = (text or "").replace("\x00", " ")
        text = re.sub(r"[ \t]+", " ", text)
        text = re.sub(r"\n{3,}", "\n\n", text)
        return text.strip()

    @staticmethod
    def _extract(path: Path) -> List[Tuple[int, str]]:
        if path.suffix.lower() in (".txt", ".md"):
            return [(1, KnowledgeBase._clean_text(path.read_text(encoding="utf-8", errors="ignore")))]
        from pypdf import PdfReader  # lazy; only needed for PDFs
        reader = PdfReader(str(path))
        if getattr(reader, "is_encrypted", False):
            try:
                reader.decrypt("")
            except Exception:
                log.warning("encrypted PDF cannot be read without a password: %s", path.name)
        out: List[Tuple[int, str]] = []
        for i, page in enumerate(reader.pages, start=1):
            try:
                out.append((i, KnowledgeBase._clean_text(page.extract_text() or "")))
            except Exception:
                out.append((i, ""))
        chars = sum(len(t) for _, t in out)
        empty = sum(1 for _, t in out if not t)
        if out and (chars < 1000 or empty / max(len(out), 1) > 0.7):
            fallback = KnowledgeBase._extract_pdf_with_pymupdf(path)
            if sum(len(t) for _, t in fallback) > chars:
                log.info("PyMuPDF fallback used for %s", path.name)
                return fallback
            log.warning("PDF has little extractable text: %s (%d empty pages of %d)",
                        path.name, empty, len(out))
        return out

    @staticmethod
    def _extract_pdf_with_pymupdf(path: Path) -> List[Tuple[int, str]]:
        try:
            import fitz  # type: ignore
        except Exception:
            return []
        try:
            doc = fitz.open(str(path))
        except Exception:
            return []
        out: List[Tuple[int, str]] = []
        try:
            for i, page in enumerate(doc, start=1):
                try:
                    out.append((i, KnowledgeBase._clean_text(page.get_text("text") or "")))
                except Exception:
                    out.append((i, ""))
        finally:
            doc.close()
        return out

    @staticmethod
    def _split(text: str, size: int = 1100, overlap: int = 150) -> List[str]:
        text = KnowledgeBase._clean_text(text)
        if len(text) <= size:
            return [text] if text else []
        out, i = [], 0
        while i < len(text):
            out.append(text[i:i + size])
            i += size - overlap
        return out

    def _finalize(self) -> None:
        self.df = Counter()
        total = 0
        for c in self.chunks:
            total += c.length
            for term in c.tf:
                self.df[term] += 1
        self.avgdl = (total / len(self.chunks)) if self.chunks else 0.0
        self.loaded = True

    # --- persistence ----------------------------------------------------
    def _persist(self, sig: str) -> None:
        try:
            payload = {"sig": sig, "sources": self.sources,
                       "chunks": [{"s": c.source, "p": c.page, "t": c.text} for c in self.chunks]}
            self._cache_path().write_text(json.dumps(payload), encoding="utf-8")
        except Exception as exc:
            log.warning("KB cache not saved: %s", exc)

    def _load_cached(self, data: dict) -> None:
        self.sources = data.get("sources", [])
        self.chunks = [_Chunk(c["s"], c["p"], c["t"]) for c in data.get("chunks", [])]
        self._finalize()

    # --- search (BM25) --------------------------------------------------
    def search(self, query: str, k: int = 4) -> List[Dict]:
        if not self.chunks:
            return []
        q = [t for t in _tok(query) if t in self.df]
        if not q:
            return []
        n = len(self.chunks)
        idf = {t: math.log(1 + (n - self.df[t] + 0.5) / (self.df[t] + 0.5)) for t in set(q)}
        k1, b = 1.5, 0.75
        scored = []
        for c in self.chunks:
            score = 0.0
            for t in q:
                f = c.tf.get(t, 0)
                if f:
                    denom = f + k1 * (1 - b + b * c.length / (self.avgdl or 1))
                    score += idf[t] * (f * (k1 + 1)) / denom
            if score > 0:
                scored.append((score, c))
        scored.sort(key=lambda s: -s[0])
        return [{"source": c.source, "page": c.page, "text": c.text} for _, c in scored[:k]]


_KB: Optional[KnowledgeBase] = None


def get_kb() -> KnowledgeBase:
    global _KB
    if _KB is None:
        _KB = KnowledgeBase(config.KNOWLEDGE_DIR)
        _KB.build()
    return _KB
