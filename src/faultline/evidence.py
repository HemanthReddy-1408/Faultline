"""Evidence references: how to cite a piece of evidence, and how to re-derive its text independently.

The verifier never trusts an excerpt written by the reasoner; it re-resolves the `ref` against the bundle / KB and
compares. A claim is grounded only if every cited ref resolves and its excerpt matches the resolved text.
"""
from __future__ import annotations

import re

from .schema import Bundle
from .signals import parse_diff

_norm = lambda s: re.sub(r"\s+", " ", s).strip()  # noqa: E731


def log_name(b: Bundle) -> str:
    return f"ci_run_{b.incident_id.split('-')[-1]}.log"


def diff_name(b: Bundle) -> str:
    return f"deployment_{b.release.get('deployment', 0)}.diff"


def log_ref(b: Bundle, a: int, z: int) -> str:
    return f"{log_name(b)}:{a}-{z}"


def diff_ref(b: Bundle, file: str, a: int, z: int) -> str:
    return f"{diff_name(b)}#{file}@L{a}-{z}"


def metric_text(b: Bundle, name: str) -> str:
    from .signals import metric_kind

    s = b.metrics[name]
    cap = b.metrics_meta.get(name, {}).get("capacity", 100)
    return f"{name} last8={[round(x, 2) for x in s[-8:]]} capacity={cap} shape={'+'.join(metric_kind(s, cap))}"


def commit_text(b: Bundle, sha: str) -> str | None:
    for c in b.commits:
        if c.sha == sha:
            return f"{c.sha} {c.message} files={','.join(c.files)}"
    return None


def history_text(b: Bundle, test: str) -> str | None:
    h = b.test_history.get(test)
    return f"{test}: {h['failures']}/{h['runs']} recent runs failed" if h else None


def resolve(ev_kind: str, ref: str, b: Bundle, kb) -> str | None:
    """Return the canonical text for `ref`, or None if it does not exist."""
    try:
        if ev_kind == "log":
            name, rng = ref.rsplit(":", 1)
            a, z = map(int, rng.split("-"))
            if name != log_name(b) or a < 1 or z < a or z > len(b.log):
                return None
            return "\n".join(b.log[a - 1: z])
        if ev_kind == "diff":
            name, rest = ref.split("#", 1)
            file, rng = rest.rsplit("@L", 1)
            a, z = map(int, rng.split("-"))
            if name != diff_name(b) or not b.diff:
                return None
            lines = b.diff.split("\n")
            if not any(f["file"] == file and f["start"] <= a <= z <= f["end"] for f in parse_diff(b.diff)):
                return None
            return "\n".join(lines[a - 1: z])
        if ev_kind == "metric":
            name = ref.split(":", 1)[1]
            return metric_text(b, name) if name in b.metrics else None
        if ev_kind == "commit":
            return commit_text(b, ref.split(":", 1)[1])
        if ev_kind == "test_history":
            return history_text(b, ref.split(":", 1)[1])
        if ev_kind in ("incident", "runbook", "github"):
            kind = {"incident": "incidents", "runbook": "runbooks", "github": "issues"}[ev_kind]
            return kb.text_of(kind, ref.split(":", 1)[1] if ev_kind != "github" else ref)
    except (ValueError, KeyError, IndexError):
        return None
    return None


def matches(ev_kind: str, excerpt: str, resolved: str | None) -> bool:
    if resolved is None:
        return False
    if ev_kind in ("incident", "runbook", "github"):
        return _norm(excerpt) in _norm(resolved)   # KB excerpts may be a prefix/slice of the document
    return _norm(excerpt) == _norm(resolved)
