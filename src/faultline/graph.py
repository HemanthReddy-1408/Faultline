"""The investigation workflow as a LangGraph state machine.

ingest -> classify -> gather -> hypothesize -> verify --(insufficient & budget left)--> gather (widened)
                                                   \\--> recommend -> report

Bounded: max_iterations, a tool-call budget and LangGraph's recursion limit. No node can execute a write tool.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import TypedDict

from langgraph.graph import END, StateGraph

from . import evidence as E
from . import security
from .kb import KnowledgeBase
from .reasoner import HeuristicReasoner, build_claims, score_candidates, status_and_confidence
from .schema import Bundle, Claim, Evidence, Hypothesis, ProposedAction, Report
from .signals import CAUSE_LOG_SIG, class_scores, diff_cause_hits, error_lines, log_cause_hits, metric_kind, parse_diff, strip_ts
from .taxonomy import CAUSE_BY_CLASS, CAUSES, CLASSES
from .tools import ToolError, ToolRuntime, action_digest

PLACEHOLDER = "[REDACTED: instruction-like content quarantined]"


@dataclass
class Config:
    max_iterations: int = 2
    tool_budget: int = 40
    use_retrieval: bool = True
    disabled_tools: set = field(default_factory=set)
    reasoner: object = field(default_factory=HeuristicReasoner)


class State(TypedDict, total=False):
    iteration: int
    class_p: dict
    class_ranked: list
    hist_votes: dict
    candidates: list
    hypotheses: list
    sufficient: bool
    status: str
    tests: list
    report: object


class Investigator:
    def __init__(self, bundle: Bundle, kb: KnowledgeBase, cfg: Config | None = None):
        self.cfg = cfg or Config()
        self.orig, self.kb = bundle, kb
        self.ev: dict[str, Evidence] = {}
        self._ev_key: dict[tuple, str] = {}
        self.flags: list[dict] = []
        self.trace: dict = {"nodes": [], "tool_calls": 0, "tool_errors": []}
        self.findings = {"log_cause": {}, "diff": {}, "metric": {}, "commits": {}, "flaky": []}
        self.kb_hits: dict = {"runbooks": [], "incidents": [], "issues": []}
        self.dropped: list[dict] = []
        self.class_spans, self.class_ev, self.class_needle = [], [], ""
        self.b = self._quarantine(bundle)
        self.rt = ToolRuntime(self.b, kb, budget=self.cfg.tool_budget, disabled=self.cfg.disabled_tools)

    # ---------------- helpers ----------------
    def add_ev(self, kind, ref, excerpt, trust="untrusted") -> str:
        key = (kind, ref)
        if key not in self._ev_key:
            eid = f"E{len(self.ev) + 1}"
            self._ev_key[key] = eid
            self.ev[eid] = Evidence(id=eid, kind=kind, ref=ref, excerpt=excerpt, trust=trust)
        return self._ev_key[key]

    def tool(self, tool_name, /, **kw):
        try:
            self.trace["tool_calls"] += 1
            return self.rt.call(tool_name, **kw)
        except ToolError as e:
            self.trace["tool_errors"].append({"tool": tool_name, "error": str(e)})
            return None

    def _quarantine(self, b: Bundle) -> Bundle:
        """Sanitise bundle text and replace instruction-like lines with a placeholder (line numbers are preserved)."""
        new = b.model_copy(deep=True)
        for i, l in enumerate(b.log, 1):
            s = security.sanitize(l)
            pats = security.scan_injection(s)
            if pats:
                self.flags.append({"where": "log", "ref": E.log_ref(b, i, i), "patterns": pats, "excerpt": s})
                s = PLACEHOLDER
            new.log[i - 1] = s
        for c in new.commits:
            pats = security.scan_injection(c.message)
            if pats:
                self.flags.append({"where": "commit", "ref": f"commit:{c.sha}", "patterns": pats, "excerpt": security.sanitize(c.message)})
                c.message = PLACEHOLDER
        if b.diff:
            out = []
            for i, l in enumerate(b.diff.split("\n"), 1):
                s = security.sanitize(l, 400)
                pats = security.scan_injection(s)
                if pats:
                    self.flags.append({"where": "diff", "ref": f"{E.diff_name(b)}:L{i}", "patterns": pats, "excerpt": s})
                    s = "+" + PLACEHOLDER if l.startswith("+") else PLACEHOLDER
                out.append(s)
            new.diff = "\n".join(out)
        return new

    def timed(self, name, fn):
        def wrapped(state):
            t0 = time.perf_counter()
            out = fn(state)
            self.trace["nodes"].append({"node": name, "ms": round((time.perf_counter() - t0) * 1000, 2)})
            return out
        return wrapped

    # ---------------- nodes ----------------
    def n_ingest(self, state):
        return {"iteration": 0}

    def err_query(self) -> str:
        seen, out = set(), []
        for _, t in error_lines(self.b.log):
            if re.search(r"FAILED |Process completed|REDACTED", t) or t in seen:
                continue
            seen.add(t); out.append(t[:160])
        return " ; ".join(out[:6])

    def n_classify(self, state):
        sig = class_scores(self.b.log)
        vote_c: dict = {}
        hist: dict = {}
        if self.cfg.use_retrieval:
            q = self.err_query()
            if q:
                rb = self.tool("search_runbooks", query=q, k=5) or []
                inc = self.tool("search_incidents", query=q, k=8) or []
                self.kb_hits["runbooks"], self.kb_hits["incidents"] = rb, inc
                for rank, h in enumerate(inc):
                    w = 1.0 / (rank + 1)
                    vote_c[h["class_id"]] = vote_c.get(h["class_id"], 0) + w
                    hist[h["cause_id"]] = hist.get(h["cause_id"], 0) + w
                for rank, h in enumerate(rb):
                    w = 1.5 / (rank + 1)
                    vote_c[h["class_id"]] = vote_c.get(h["class_id"], 0) + w
                    hist[h["cause_id"]] = hist.get(h["cause_id"], 0) + w
        norm = lambda d: {k: v / sum(d.values()) for k, v in d.items()} if d and sum(d.values()) else {}  # noqa: E731
        vote_c, hist = norm(vote_c), norm(hist)
        if sum(sig.values()) > 0 and vote_c:
            p = {c: 0.6 * sig.get(c, 0) + 0.4 * vote_c.get(c, 0) for c in CLASSES}
        else:
            p = dict(sig) if sum(sig.values()) > 0 else {c: vote_c.get(c, 0.0) for c in CLASSES}
        ranked = sorted(p.items(), key=lambda x: -x[1])
        return {"class_p": p, "class_ranked": ranked, "hist_votes": hist}

    def _candidates(self, state) -> list[str]:
        ranked = state["class_ranked"]
        if state["iteration"] == 0:
            top = [c for c, p in ranked[:2] if p >= 0.25] or [ranked[0][0]]
        else:
            top = [c for c, _ in ranked[:3]]
        return [cid for c in top for cid in CAUSE_BY_CLASS[c]]

    def n_gather(self, state):
        widen = state["iteration"] > 0
        cands = self._candidates(state)
        f = self.findings
        # --- cause-specific log lines ---
        for cid in (CAUSES if widen else cands):
            pat = CAUSE_LOG_SIG[cid]
            hits = self.tool("grep_log", pattern=pat, max_hits=5) or []
            if hits and cid not in f["log_cause"]:
                h = hits[0]
                m = re.search(pat, h["text"].lower())
                eid = self.add_ev("log", E.log_ref(self.b, h["line"], h["line"]), self.b.log[h["line"] - 1])
                f["log_cause"][cid] = [(eid, m.group(0) if m else h["text"][:20])]
        # --- release diff ---
        if self.b.diff and (not f.get("diff_scanned") or (widen and f["diff_scanned"] != "all")):
            files = (self.tool("get_diff") or {}).get("files", [])
            for fi in files:
                if re.search(r"(^|/)(README|CHANGELOG|NOTES)\.|\.md$|version\.py$|/tests?/|^tests?/", fi["file"], re.I):
                    continue
                d = self.tool("get_diff", file=fi["file"])
                if not d:
                    continue
                text = "\n".join(d["lines"])
                hits = diff_cause_hits("diff --git a/x b/" + d["file"] + "\n" + "\n".join(d["lines"]))
                for cid, hl in hits.items():
                    if cid in cands or widen:
                        eid = self.add_ev("diff", E.diff_ref(self.b, d["file"], d["start"], d["end"]), text)
                        f["diff"].setdefault(cid, [])
                        if not any(e == eid for e, _ in f["diff"][cid]):
                            f["diff"][cid].append((eid, {"file": d["file"], "text": hl[0]["text"]}))
            f["diff_scanned"] = "all" if widen else True
            commits = self.tool("list_commits") or []
            touched = {fl for lst in f["diff"].values() for _, h in lst for fl in [h["file"]]}
            for c in commits:
                for fl in set(c["files"]) & touched:
                    eid = self.add_ev("commit", f"commit:{c['sha']}", E.commit_text(self.b, c["sha"]))
                    f["commits"].setdefault(fl, []).append((eid, c["sha"]))
        # --- metrics ---
        wanted = {m for cid in (CAUSES if widen else cands) for m in CAUSES[cid]["met"]}
        have = self.tool("list_metrics") or []
        for m in sorted(wanted & set(have)):
            if m in f["metric"]:
                continue
            md = self.tool("get_metric", name=m)
            if md:
                tags = metric_kind(md["values"], md["capacity"])
                eid = self.add_ev("metric", f"metrics:{m}", E.metric_text(self.b, m))
                f["metric"][m] = (eid, tags)
        # --- test history ---
        if not f.get("tests_done"):
            for t in self.b.failed_tests[:3]:
                h = self.tool("get_test_history", name=t)
                if h and h["failures"] >= 3:
                    eid = self.add_ev("test_history", f"test_history:{t}", E.history_text(self.b, t))
                    f["flaky"].append((eid, f"{h['failures']}/{h['runs']}"))
            f["tests_done"] = True
        # --- class evidence (error spans) + KB evidence ---
        self._class_evidence(state)
        if self.cfg.use_retrieval and widen:
            q = self.err_query() + " " + " ".join(CLASSES[c]["name"] for c, _ in state["class_ranked"][:2])
            self.kb_hits["incidents"] = self.tool("search_incidents", query=q, k=10) or self.kb_hits["incidents"]
        if self.cfg.use_retrieval and not self.kb_hits["issues"]:
            self.kb_hits["issues"] = self.tool("search_github_issues", query=self.err_query() or "ci failure", k=3) or []
        return {"candidates": cands}

    def _class_evidence(self, state):
        top = state["class_ranked"][0][0] if state["class_ranked"] and state["class_ranked"][0][1] > 0 else None
        if not top:
            return
        sig = [re.compile(p) for p in CLASSES[top]["sig"]]
        lines = [(i, t) for i, t in error_lines(self.b.log) if any(r.search(t.lower()) for r in sig)]
        spans, cur = [], []
        for i, t in lines:
            if cur and i - cur[-1] > 1:
                spans.append((cur[0], cur[-1])); cur = []
            cur.append(i)
        if cur:
            spans.append((cur[0], cur[-1]))
        self.class_spans = spans
        self.class_ev = [self.add_ev("log", E.log_ref(self.b, a, z), "\n".join(self.b.log[a - 1: z])) for a, z in spans[:3]]
        self.class_needle = strip_ts(self.b.log[spans[0][0] - 1]).strip()[:40] if spans else ""

    def n_hypothesize(self, state):
        f = self.findings
        scored = score_candidates(f, dict(state["class_p"]), state["hist_votes"], state["candidates"] if state["iteration"] == 0 else list(CAUSES))
        scored = [s for s in scored if s["score"] > 0.12 or s["independent"]]
        scored = self.cfg.reasoner.refine(scored, self.ev, f)
        hyps = []
        for s in scored[:3]:
            claims = build_claims(s["cause_id"], f, s, self.ev) + s.get("llm_claims", [])
            c = CAUSES[s["cause_id"]]
            hyps.append({"cand": s, "title": c["name"], "component": c["comp"], "claims": claims})
        return {"hypotheses": hyps}

    def n_verify(self, state):
        from .verify import verify_claims

        out, kinds_of = [], lambda cl: {self.ev[e].kind for e in cl.evidence_ids if e in self.ev}  # noqa: E731
        for h in state["hypotheses"]:
            kept, dropped = verify_claims(h["claims"], self.ev, self.b, self.kb)
            self.dropped += [{**d, "hypothesis": h["cand"]["cause_id"]} for d in dropped]
            verified_kinds = set().union(*[kinds_of(c) for c in kept]) if kept else set()
            h["cand"]["independent"] = [k for k in ("log", "diff", "metric") if k in verified_kinds and k in h["cand"]["independent"]]
            h["claims"] = kept
            h["status"], h["confidence"] = status_and_confidence(h["cand"])
            out.append(h)
        out.sort(key=lambda h: (-(h["status"] == "supported"), -h["cand"]["score"]))
        sufficient = bool(out) and out[0]["status"] == "supported" and (len(out) == 1 or out[0]["cand"]["score"] - out[1]["cand"]["score"] >= 0.08)
        return {"hypotheses": out, "sufficient": sufficient}

    def after_verify(self, state):
        if state["sufficient"] or state["iteration"] + 1 >= self.cfg.max_iterations:
            return "recommend"
        return "widen"

    def n_widen(self, state):
        return {"iteration": state["iteration"] + 1}

    def n_recommend(self, state):
        hyps = state["hypotheses"]
        top = hyps[0] if hyps else None
        scores: dict[str, float] = {}
        why: dict[str, list[str]] = {}

        def bump(t, w, reason):
            scores[t] = scores.get(t, 0) + w
            why.setdefault(t, []).append(reason)

        top_cause = top["cand"]["cause_id"] if top and state.get("sufficient") else None
        for r in self.kb_hits["runbooks"]:
            for t in r.get("tests", []):
                if top_cause and r["cause_id"] == top_cause:
                    bump(t, 3.0, f"listed in runbook {r['id']} for the leading hypothesis")
                elif not top_cause and state["class_ranked"][0][1] > 0 and r["class_id"] == state["class_ranked"][0][0]:
                    bump(t, 1.0, f"listed in runbook {r['id']} for this failure class")
        for h in self.kb_hits["incidents"][:5]:
            if not top_cause or h["cause_id"] == top_cause:
                for t in h.get("tests_run", []):
                    bump(t, 1.0, f"run during similar incident {h['id']}")
        for t in self.b.failed_tests:
            bump(t, 1.5, "failed in this CI run (confirm after any fix)")
        tests = [{"test": t, "score": round(s, 2), "why": "; ".join(why[t][:2]) + (f" (+{len(why[t]) - 2} more signals)" if len(why[t]) > 2 else "")} for t, s in sorted(scores.items(), key=lambda x: (-x[1], x[0]))[:5]]
        return {"tests": tests}

    def n_report(self, state):
        from .report import assemble

        return {"report": assemble(self, state)}

    def graph(self):
        g = StateGraph(State)
        for name, fn in [("ingest", self.n_ingest), ("classify", self.n_classify), ("gather", self.n_gather), ("hypothesize", self.n_hypothesize),
                         ("verify", self.n_verify), ("widen", self.n_widen), ("recommend", self.n_recommend), ("report", self.n_report)]:
            g.add_node(name, self.timed(name, fn))
        g.set_entry_point("ingest")
        for a, b in [("ingest", "classify"), ("classify", "gather"), ("gather", "hypothesize"), ("hypothesize", "verify"), ("widen", "gather"), ("report", END)]:
            g.add_edge(a, b)
        g.add_conditional_edges("verify", self.after_verify, {"widen": "widen", "recommend": "recommend"})
        g.add_edge("recommend", "report")
        return g.compile()


def investigate(bundle: Bundle, kb: KnowledgeBase, cfg: Config | None = None) -> Report:
    inv = Investigator(bundle, kb, cfg)
    t0 = time.perf_counter()
    # recommend merges its partial output into state["report"], which report then replaces with the final Report
    out = inv.graph().invoke({}, config={"recursion_limit": 30})
    rep = out["report"]
    rep.trace = {**inv.trace, "total_ms": round((time.perf_counter() - t0) * 1000, 2), "iterations": out["iteration"] + 1, "reasoner": inv.cfg.reasoner.name,
                 "tokens_in": inv.cfg.reasoner.tokens_in, "tokens_out": inv.cfg.reasoner.tokens_out, "cost_usd": getattr(inv.cfg.reasoner, "cost_usd", 0.0)}
    return rep
