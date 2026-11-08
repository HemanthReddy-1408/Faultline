"""Tool runtime: schema-validated, budgeted, audited tools.

Read tools are free to call inside an investigation. Write tools (rerun_tests, open_ticket, rollback_release,
page_oncall) are refused by `call()` unconditionally; they run only through `execute_approved()`, which requires an
approval record for exactly that proposed action. In this build write tools are simulated (they append to an action
log) — wiring them to real systems is a deliberately separate step.
"""
from __future__ import annotations

import re
import time
from typing import Any, Callable

from pydantic import BaseModel, Field, ValidationError

from . import security
from .schema import Bundle
from .signals import parse_diff

MAX_RESULT_CHARS = 6000


class ToolError(Exception):
    pass


class TransientToolError(ToolError):
    """Retryable (timeouts, 5xx from an upstream)."""


class PermissionDenied(ToolError):
    pass


class BudgetExceeded(ToolError):
    pass


class _Q(BaseModel):
    query: str = Field(min_length=1, max_length=800)
    k: int = Field(default=5, ge=1, le=10)


class _Lines(BaseModel):
    start: int = Field(ge=1)
    end: int = Field(ge=1)


class _Grep(BaseModel):
    pattern: str = Field(min_length=1, max_length=120)
    max_hits: int = Field(default=20, ge=1, le=50)


class _Name(BaseModel):
    name: str = Field(min_length=1, max_length=120)


class _Sha(BaseModel):
    sha: str = Field(min_length=4, max_length=40)


class _File(BaseModel):
    file: str | None = None


class _None(BaseModel):
    pass


class _Tests(BaseModel):
    tests: list[str] = Field(min_length=1, max_length=10)


class _Ticket(BaseModel):
    title: str = Field(max_length=200)
    body: str = Field(max_length=4000)


class _Rollback(BaseModel):
    version: str = Field(pattern=r"^\d+\.\d+\.\d+$")


class _Page(BaseModel):
    team: str = Field(max_length=60)


class ToolRuntime:
    def __init__(self, bundle: Bundle, kb, budget: int = 40, disabled: set[str] | None = None, retries: int = 2, on_call: Callable | None = None):
        self.b, self.kb, self.budget, self.calls = bundle, kb, budget, 0
        self.disabled = disabled or set()
        self.retries = retries
        self.on_call = on_call
        self.log: list[dict] = []
        self.actions_executed: list[dict] = []
        self.read: dict[str, tuple[type[BaseModel], Callable]] = {
            "search_runbooks": (_Q, lambda a: self.kb.search("runbooks", a.query, a.k)),
            "search_incidents": (_Q, lambda a: self.kb.search("incidents", a.query, a.k)),
            "search_github_issues": (_Q, lambda a: self.kb.search("issues", a.query, a.k)),
            "get_log_slice": (_Lines, self._log_slice),
            "grep_log": (_Grep, self._grep),
            "list_commits": (_None, lambda a: [c.model_dump() for c in self.b.commits]),
            "get_commit": (_Sha, self._commit),
            "get_diff": (_File, self._diff),
            "list_metrics": (_None, lambda a: sorted(self.b.metrics)),
            "get_metric": (_Name, self._metric),
            "get_test_history": (_Name, lambda a: self.b.test_history.get(a.name) or (_ for _ in ()).throw(ToolError(f"no history for {a.name}"))),
        }
        self.write: dict[str, tuple[type[BaseModel], Callable]] = {
            "rerun_tests": (_Tests, lambda a: {"queued": a.tests}),
            "open_ticket": (_Ticket, lambda a: {"ticket": "SIMULATED-1", "title": a.title}),
            "rollback_release": (_Rollback, self._rollback),
            "page_oncall": (_Page, lambda a: {"paged": a.team}),
        }

    # ---- handlers over the bundle (the bundle is the only thing these read) ----
    def _log_slice(self, a):
        if a.end < a.start or a.end - a.start > 200:
            raise ToolError("invalid or too-large range")
        return {"start": a.start, "end": min(a.end, len(self.b.log)), "lines": [security.sanitize(l) for l in self.b.log[a.start - 1: a.end]]}

    def _grep(self, a):
        try:
            rx = re.compile(a.pattern, re.I)
        except re.error as e:
            raise ToolError(f"bad pattern: {e}")
        return [{"line": i, "text": security.sanitize(l)} for i, l in enumerate(self.b.log, 1) if rx.search(l)][: a.max_hits]

    def _commit(self, a):
        for c in self.b.commits:
            if c.sha.startswith(a.sha):
                return c.model_dump()
        raise ToolError(f"unknown commit {a.sha}")

    def _diff(self, a):
        if not self.b.diff:
            raise ToolError("no deployment diff attached to this incident")
        files = parse_diff(self.b.diff)
        if a.file is None:
            return {"files": [{"file": f["file"], "start": f["start"], "end": f["end"]} for f in files]}
        for f in files:
            if f["file"] == a.file:
                lines = self.b.diff.split("\n")[f["start"] - 1: f["end"]]
                return {"file": f["file"], "start": f["start"], "end": f["end"], "lines": [security.sanitize(l) for l in lines]}
        raise ToolError(f"file {a.file} not in diff")

    def _metric(self, a):
        if a.name not in self.b.metrics:
            raise ToolError(f"unknown metric {a.name}")
        return {"name": a.name, "values": self.b.metrics[a.name], "capacity": self.b.metrics_meta.get(a.name, {}).get("capacity", 100)}

    def _rollback(self, a):
        known = {str(self.b.release.get("version"))}
        if a.version not in known:
            raise ToolError(f"version {a.version} is not a release of this service")
        return {"rolled_back_to": a.version}

    # ---- public API ----
    def call(self, name: str, /, **args) -> Any:
        if name in self.write:
            raise PermissionDenied(f"{name} is a write tool and requires human approval")
        if name not in self.read or name in self.disabled:
            raise PermissionDenied(f"tool {name!r} is not available")
        if self.calls >= self.budget:
            raise BudgetExceeded(f"tool budget of {self.budget} calls exhausted")
        self.calls += 1
        schema, fn = self.read[name]
        try:
            parsed = schema(**args)
        except ValidationError as e:
            self._record(name, args, ok=False, err="invalid arguments")
            raise ToolError(f"invalid arguments for {name}: {e.errors()[0]['msg']}")
        t0, last = time.perf_counter(), None
        for attempt in range(self.retries + 1):
            try:
                out = fn(parsed)
                self._record(name, args, ok=True, ms=(time.perf_counter() - t0) * 1000, attempt=attempt)
                return out
            except TransientToolError as e:
                last = e
                self._record(name, args, ok=False, err=f"transient: {e}", attempt=attempt)
        raise ToolError(f"{name} failed after {self.retries + 1} attempts: {last}")

    def execute_approved(self, action: dict, approval: dict | None) -> dict:
        """Run a write tool. Requires an approval for this exact action id + args; anything else is refused."""
        if not approval or approval.get("action_id") != action["id"] or approval.get("decision") != "approved":
            raise PermissionDenied("no matching human approval for this action")
        if approval.get("args_digest") not in (None, _digest(action)):
            raise PermissionDenied("approved action was modified after approval")
        name = action["tool"]
        if name not in self.write:
            raise PermissionDenied(f"{name!r} is not a registered write tool")
        schema, fn = self.write[name]
        try:
            res = fn(schema(**action["args"]))
        except ValidationError as e:
            raise ToolError(f"invalid arguments: {e.errors()[0]['msg']}")
        rec = {"action_id": action["id"], "tool": name, "args": action["args"], "result": res, "simulated": True}
        self.actions_executed.append(rec)
        return rec

    def _record(self, name, args, ok, err=None, ms=0.0, attempt=0):
        rec = {"tool": name, "args": args, "ok": ok, "error": err, "ms": ms, "attempt": attempt}
        self.log.append(rec)
        if self.on_call:
            self.on_call(rec)

    @staticmethod
    def truncate(obj: Any) -> Any:
        s = str(obj)
        return obj if len(s) <= MAX_RESULT_CHARS else s[:MAX_RESULT_CHARS] + "…[truncated]"


def _digest(action: dict) -> str:
    import hashlib, json

    return hashlib.sha256(json.dumps([action["tool"], action["args"]], sort_keys=True).encode()).hexdigest()[:16]


action_digest = _digest
