"""Deterministic evidence extraction: log signatures, diff analysis, metric-shape detection.

All regexes here were written against the `dev` phrasings only (see taxonomy.py protocol).
"""
from __future__ import annotations

import re

import numpy as np

from .taxonomy import CAUSES, CLASSES

CAUSE_LOG_SIG = {
    "pool_exhaustion": r"queuepool limit|connections checked out|requests waiting",
    "db_timeout_lowered": r"connect_timeout=\d+s elapsed|slow handshake",
    "db_degradation": r"slow query detected|statement timeout while waiting for lock",
    "db_service_down": r"system is starting up|not accepting connections",
    "db_port_changed": r"dsn=.*:\d{4}|connecting on port",
    "idle_timeout_mismatch": r"recycled connection age|stale connection returned",
    "db_failover": r"terminating connection due to administrator command|replica promoted",
    "memory_limit_reduced": r"out of memory: killed process|memory limit \d+mi",
    "unbounded_cache": r"no eviction configured|gc overhead limit",
    "debug_logging_enabled": r"log file .* is \d+gb|debug logging enabled",
    "artifact_cleanup_removed": r"stale build directories|100% used",
    "service_renamed": r"upstream host .* unknown|resolving [\w.-]+$",
    "dns_outage": r"resolver .* not responding|multiple lookups failed",
    "cert_expired": r"notafter=.* in the past|expired certificate",
    "ca_bundle_removed": r"unable to get local issuer|custom ca path .* not found",
    "secret_rotated": r"last rotated|using secret ref",
    "token_ttl_reduced": r"access token expires in|refresh skipped",
    "unpinned_bump": r"looking at multiple versions|collecting .* downloading",
    "lockfile_removed": r"no lockfile found|resolving from scratch",
    "race_condition": r"without lock|observed stale value",
    "order_dependency": r"randomly-seed|fixture state leaked",
    "retry_storm": r"retrying immediately|backoff=0",
    "quota_reduced": r"quota remaining|x-ratelimit-limit",
    "env_var_renamed": r"not found, no default|loading settings from environment",
    "secret_not_mounted": r"not mounted for this job|/run/secrets is empty",
}
assert set(CAUSE_LOG_SIG) == set(CAUSES)

_TS = re.compile(r"^\[\d\d:\d\d:\d\d\]\s*")
ERRORISH = re.compile(r"error|exception|fail|killed|refused|timed out|timeout|reset|denied|unauthorized|expired|conflict|no space|429|unable|cannot|missing|not set|oom|enospc|econn|resolution|lookup", re.I)
DOC_FILES = re.compile(r"(^|/)(README|CHANGELOG|NOTES)\.|\.md$|version\.py$|/tests?/|^tests?/", re.I)


def strip_ts(line: str) -> str:
    return _TS.sub("", line)


def error_lines(log: list[str]) -> list[tuple[int, str]]:
    """(1-based line number, text) for lines that look like errors; telemetry/deprecation warnings excluded."""
    out = []
    for i, l in enumerate(log, 1):
        t = strip_ts(l)
        if ERRORISH.search(t) and not re.search(r"deprecat|telemetry|unknown config option|##\[error\]", t, re.I):
            out.append((i, t))
    return out


def class_scores(log: list[str]) -> dict[str, float]:
    scores = {c: 0.0 for c in CLASSES}
    for _, t in error_lines(log):
        low = t.lower()
        for cid, c in CLASSES.items():
            if any(re.search(p, low) for p in c["sig"]):
                scores[cid] += 1
    tot = sum(scores.values())
    return {k: v / tot for k, v in scores.items()} if tot else scores


def log_cause_hits(log: list[str]) -> dict[str, list[int]]:
    hits: dict[str, list[int]] = {}
    for i, l in enumerate(log, 1):
        low = strip_ts(l).lower()
        for cid, p in CAUSE_LOG_SIG.items():
            if re.search(p, low):
                hits.setdefault(cid, []).append(i)
    return hits


def parse_diff(diff: str | None) -> list[dict]:
    """-> [{file, start, end, added:[(line_no_in_diff_text, text)], removed:[...]}] with 1-based lines of the diff text."""
    if not diff:
        return []
    files, cur = [], None
    for n, line in enumerate(diff.split("\n"), 1):
        if line.startswith("diff --git"):
            cur = {"file": line.split(" b/")[-1], "start": n, "end": n, "added": [], "removed": []}
            files.append(cur)
        elif cur is not None:
            cur["end"] = n
            if line.startswith("+") and not line.startswith("+++"):
                cur["added"].append((n, line[1:]))
            elif line.startswith("-") and not line.startswith("---"):
                cur["removed"].append((n, line[1:]))
    return files


def diff_cause_hits(diff: str | None) -> dict[str, list[dict]]:
    """cause_id -> [{file, line, text}] for added lines in non-doc files matching the cause's diff signature."""
    hits: dict[str, list[dict]] = {}
    for f in parse_diff(diff):
        if DOC_FILES.search(f["file"]):
            continue
        for n, text in f["added"]:
            for cid, c in CAUSES.items():
                if c["dsig"] and re.search(c["dsig"], text, re.I):
                    hits.setdefault(cid, []).append({"file": f["file"], "line": n, "text": text, "span": (f["start"], f["end"])})
    return hits


def metric_kind(series: list[float], capacity: float) -> list[str]:
    """Shape tags for a metric series: saturated | spike | zero | rising | normal."""
    s = np.asarray(series, dtype=float)
    if len(s) < 8 or capacity <= 0:
        return ["normal"]
    head, tail = s[: len(s) // 2], s[-4:]
    tags = []
    if np.all(tail == 0) and s.max() > 0:
        tags.append("zero")
    if tail.mean() >= 0.9 * capacity and np.ptp(tail) <= 0.1 * capacity:
        tags.append("saturated")
    if head.mean() > 0 and tail.mean() >= 3 * head.mean() and "saturated" not in tags:
        tags.append("spike")
    elif head.mean() > 0 and tail.mean() >= 3 * head.mean():
        tags.append("spike")
    t = np.arange(len(s))
    if np.corrcoef(t, s)[0, 1] > 0.95 and np.ptp(tail) > 0.1 * capacity:
        tags.append("rising")
    return tags or ["normal"]
