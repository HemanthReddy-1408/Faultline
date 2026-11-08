"""Typed contracts shared by the graph, API, verifier and benchmark."""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class Commit(BaseModel):
    sha: str
    author: str
    message: str
    ts: str
    files: list[str] = []


class Bundle(BaseModel):
    """A CI failure bundle. Everything in it is UNTRUSTED input (logs and commit messages are attacker-influenced)."""
    incident_id: str
    service: str
    release: dict = {}
    log: list[str]
    diff: str | None = None
    commits: list[Commit] = []
    failed_tests: list[str] = []
    test_history: dict[str, dict] = {}
    metrics: dict[str, list[float]] = {}
    metrics_meta: dict[str, dict] = {}


class Evidence(BaseModel):
    id: str
    kind: Literal["log", "diff", "commit", "metric", "test_history", "incident", "runbook", "github"]
    ref: str                       # e.g. ci_run_1042.log:84-96 | deployment_238.diff#config/database.yml@L10-14 | incident:INC-0891
    excerpt: str                   # verbatim text the claim rests on
    trust: Literal["untrusted", "curated"] = "untrusted"
    flags: list[str] = []


class Claim(BaseModel):
    text: str
    evidence_ids: list[str] = Field(default_factory=list)
    must_include: list[str] = []   # substrings that must appear in the cited excerpts (entailment check)


class Hypothesis(BaseModel):
    rank: int = 0
    cause_id: str
    title: str
    component: str
    confidence: float
    status: Literal["supported", "plausible"]
    independent_evidence: list[str] = []
    claims: list[Claim] = []
    evidence_against: list[str] = []
    missing_evidence: list[str] = []


class ProposedAction(BaseModel):
    id: str
    tool: str
    args: dict
    rationale: str
    requires_approval: bool = True


class Report(BaseModel):
    incident_id: str
    status: Literal["diagnosed", "insufficient_evidence"]
    failure_class: dict
    confirmed_facts: list[Claim]
    hypotheses: list[Hypothesis]
    missing_evidence: list[str]
    alternatives_considered: list[str]
    recommended_investigations: list[str]
    regression_tests: list[dict]
    related_incidents: list[dict]
    related_issues: list[dict]
    proposed_actions: list[ProposedAction]
    security_flags: list[dict]
    dropped_claims: list[dict] = []
    evidence: dict[str, Evidence]
    trace: dict = {}
