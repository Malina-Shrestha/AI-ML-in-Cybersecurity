"""
RAG retriever for TriageMate.

Builds a small knowledge base from the MITRE ATT&CK subset and the SOC playbook,
then retrieves the most relevant passages for an alert so the LLM can ground its
explanation and cite a source.

Two backends, chosen automatically:
  1. Chroma + sentence-transformers embeddings, if both are installed and a model
     is available (semantic search).
  2. A built-in TF-IDF cosine retriever in pure Python (no downloads), used as the
     default and the fallback, so retrieval always works offline for the demo.

Each retrieved passage carries a `source` string for citation.
"""
import json
import math
import os
import re
from collections import Counter
from typing import Dict, List

HERE = os.path.dirname(__file__)
KB_PATH = os.path.join(HERE, "knowledge", "mitre_kb.json")
PB_PATH = os.path.join(HERE, "knowledge", "playbook.json")


def _load_documents() -> List[Dict]:
    """Flatten the KB and playbook into retrievable documents."""
    docs = []
    kb = json.load(open(KB_PATH))
    for t in kb["techniques"]:
        text = f"{t['id']} {t['name']} ({t['tactic']}). {t['description']} Detection: {t['detection']} Investigation: {t['investigation']}"
        docs.append({"id": t["id"], "kind": "mitre", "text": text,
                     "source": f"MITRE ATT&CK {t['id']} {t['name']}"})
    pb = json.load(open(PB_PATH))
    for e in pb["entries"]:
        text = f"{e['title']} for {e['category']}. {e['guidance']}"
        docs.append({"id": e["category"], "kind": "playbook", "text": text,
                     "source": f"SOC playbook: {e['title']}"})
    return docs


# ---------- built-in TF-IDF retriever (always available) ----------
def _tokens(s: str) -> List[str]:
    return re.findall(r"[a-z0-9]+", s.lower())


class TfidfRetriever:
    def __init__(self, docs: List[Dict]):
        self.docs = docs
        self.doc_tokens = [_tokens(d["text"]) for d in docs]
        df = Counter()
        for toks in self.doc_tokens:
            for w in set(toks):
                df[w] += 1
        n = len(docs)
        self.idf = {w: math.log((n + 1) / (c + 1)) + 1 for w, c in df.items()}
        self.doc_vecs = [self._vec(toks) for toks in self.doc_tokens]

    def _vec(self, toks: List[str]) -> Dict[str, float]:
        tf = Counter(toks)
        vec = {w: (tf[w] / len(toks)) * self.idf.get(w, 0.0) for w in tf} if toks else {}
        norm = math.sqrt(sum(v * v for v in vec.values())) or 1.0
        return {w: v / norm for w, v in vec.items()}

    def query(self, text: str, k: int = 3) -> List[Dict]:
        qv = self._vec(_tokens(text))
        scored = []
        for d, dv in zip(self.docs, self.doc_vecs):
            score = sum(qv.get(w, 0) * dv.get(w, 0) for w in qv)
            scored.append((score, d))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{**d, "score": round(s, 3)} for s, d in scored[:k] if s > 0]


# ---------- optional Chroma + embeddings retriever ----------
class ChromaRetriever:
    def __init__(self, docs: List[Dict]):
        import chromadb
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer("all-MiniLM-L6-v2")
        self.client = chromadb.Client()
        self.col = self.client.get_or_create_collection("triagemate")
        if self.col.count() == 0:
            embs = self.model.encode([d["text"] for d in docs]).tolist()
            self.col.add(ids=[d["id"] + ":" + d["kind"] for d in docs],
                         documents=[d["text"] for d in docs],
                         embeddings=embs,
                         metadatas=[{"source": d["source"], "kind": d["kind"]} for d in docs])

    def query(self, text: str, k: int = 3) -> List[Dict]:
        emb = self.model.encode([text]).tolist()
        res = self.col.query(query_embeddings=emb, n_results=k)
        out = []
        for doc, meta, dist in zip(res["documents"][0], res["metadatas"][0], res["distances"][0]):
            out.append({"text": doc, "source": meta["source"], "kind": meta["kind"],
                        "score": round(1 - dist, 3)})
        return out


_RETRIEVER = None
_BACKEND = None


def get_retriever():
    """Return a retriever, preferring Chroma if available, else TF-IDF."""
    global _RETRIEVER, _BACKEND
    if _RETRIEVER is not None:
        return _RETRIEVER
    docs = _load_documents()
    if os.environ.get("RAG_BACKEND", "").lower() != "tfidf":
        try:
            _RETRIEVER = ChromaRetriever(docs)
            _BACKEND = "chroma+embeddings"
            return _RETRIEVER
        except Exception:
            pass
    _RETRIEVER = TfidfRetriever(docs)
    _BACKEND = "tfidf (built-in)"
    return _RETRIEVER


def backend_name() -> str:
    get_retriever()
    return _BACKEND


def retrieve(query_text: str, k: int = 3) -> List[Dict]:
    """Retrieve the top-k knowledge passages for an alert."""
    return get_retriever().query(query_text, k=k)
