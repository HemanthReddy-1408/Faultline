"""Knowledge base: runbooks, past incidents and real GitHub issues, searched with RetrievalLab pipelines."""
from __future__ import annotations

import json
import os
from pathlib import Path

from retrievallab.data import Dataset
from retrievallab.pipeline import Context, Pipeline

DATA = Path(__file__).resolve().parents[2] / "data"
os.environ.setdefault("RETRIEVALLAB_CACHE", str(DATA / ".cache"))

MODES = {
    "bm25": lambda rr: {"retrievers": [{"type": "bm25"}]},
    "dense": lambda rr: {"retrievers": [{"type": "dense", "model": "sentence-transformers/all-MiniLM-L6-v2", "index": "flat"}]},
    "hybrid": lambda rr: {"retrievers": [{"type": "bm25"}, {"type": "dense", "index": "flat"}], "fusion": {"type": "rrf", "k": 60}},
    "hybrid+rerank": lambda rr: {"retrievers": [{"type": "bm25"}, {"type": "dense", "index": "flat"}], "fusion": {"type": "rrf", "k": 60},
                                 "rerank": {"type": "cross-encoder", "model": rr or "cross-encoder/ms-marco-MiniLM-L-6-v2", "top_n": 20}},
}


def load_github(path: Path | None = None) -> list[dict]:
    p = path or DATA / "github_issues.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines() if l.strip()] if p.exists() else []


class KnowledgeBase:
    """Three searchable collections. `mode` selects the retrieval architecture (see MODES), which is what the
    benchmark ablates; `reranker` may be a HF id or a local RankForge checkpoint directory."""

    def __init__(self, runbooks: list[dict], incidents: list[dict], issues: list[dict], mode: str = "hybrid", reranker: str | None = None):
        self.mode, self.reranker = mode, reranker
        self.docs = {
            "runbooks": {r["id"]: r for r in runbooks},
            "incidents": {i["id"]: i for i in incidents},
            "issues": {g["id"]: g for g in issues},
        }
        self._pipes: dict[str, Pipeline] = {}

    def _text(self, kind: str, d: dict) -> str:
        if kind == "runbooks":
            return d["text"]
        if kind == "incidents":
            return f"{d['title']}. {d['summary']} Resolution: {d['resolution']}"
        return f"{d['title']}. {d['body'][:700]}"

    def _pipe(self, kind: str) -> Pipeline:
        if kind not in self._pipes:
            corpus = {i: {"title": "", "text": self._text(kind, d)} for i, d in self.docs[kind].items()}
            ctx = Context(Dataset(f"faultline-{kind}", corpus, {}, {}))
            spec = {"name": f"{kind}-{self.mode}", "depth": 50, **MODES[self.mode](self.reranker)}
            self._pipes[kind] = Pipeline(spec, ctx)
        return self._pipes[kind]

    def search(self, kind: str, query: str, k: int = 5) -> list[dict]:
        if not self.docs[kind]:
            return []
        hits = self._pipe(kind).search(query, k)["final"][:k]
        out = []
        for doc_id, score in hits:
            d = self.docs[kind][doc_id]
            item = {"id": doc_id, "score": round(float(score), 5), "title": d.get("title", ""), "text": self._text(kind, d)[:500]}
            if kind == "incidents":
                item.update(cause_id=d["cause_id"], class_id=d["class_id"], tests_run=d["tests_run"], service=d["service"])
            elif kind == "runbooks":
                item.update(cause_id=d["cause_id"], class_id=d["class_id"], tests=d["tests"])
            else:
                item.update(url=d["url"])
            out.append(item)
        return out

    def get(self, kind: str, doc_id: str) -> dict | None:
        return self.docs[kind].get(doc_id)

    def text_of(self, kind: str, doc_id: str) -> str | None:
        d = self.docs[kind].get(doc_id)
        return self._text(kind, d) if d else None


def default_kb(mode: str = "hybrid", reranker: str | None = None, history: list[dict] | None = None) -> KnowledgeBase:
    from .synth import make_history, runbooks

    return KnowledgeBase(runbooks(), history or make_history(), load_github(), mode=mode, reranker=reranker or os.environ.get("FAULTLINE_RERANKER"))
