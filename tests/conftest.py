import pytest

from faultline.kb import KnowledgeBase
from faultline.synth import make_history, runbooks


@pytest.fixture(scope="session")
def kb():
    """BM25-only KB: fast and offline. Hybrid/dense paths are covered in test_graph::test_hybrid_kb_end_to_end."""
    return KnowledgeBase(runbooks(), make_history(300), [{"id": "gh:x/y#1", "repo": "x/y", "number": 1, "title": "pool timeout under load", "body": "QueuePool limit reached", "url": "https://github.com/x/y/issues/1", "labels": [], "state": "open", "source": "github-real"}], mode="bm25")
