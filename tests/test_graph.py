import pytest

from faultline.graph import Config, investigate
from faultline.kb import default_kb
from faultline.report import to_markdown
from faultline.schema import Bundle
from faultline.synth import make_scenario
from faultline.verify import audit_report


def run(kb, seed=5, split="dev", variant="rich", cause="pool_exhaustion", cfg=None, **kw):
    sc = make_scenario(seed, split, variant, cause, **kw)
    b = Bundle(**sc["bundle"])
    return investigate(b, kb, cfg), b, sc


def test_rich_scenario_is_diagnosed_with_grounded_evidence(kb):
    rep, b, _ = run(kb)
    assert rep.status == "diagnosed" and rep.hypotheses[0].cause_id == "pool_exhaustion" and rep.hypotheses[0].status == "supported"
    assert len(rep.hypotheses[0].independent_evidence) >= 2
    assert rep.confirmed_facts and rep.regression_tests and rep.related_incidents
    assert audit_report(rep, b, kb)["ungrounded"] == 0
    md = to_markdown(rep)
    for section in ("Confirmed facts", "Potential root causes", "Missing evidence", "Alternative explanations", "Proposed actions"):
        assert section in md


def test_every_proposed_action_requires_approval_and_none_executed(kb):
    rep, _, _ = run(kb)
    assert rep.proposed_actions and all(a.requires_approval for a in rep.proposed_actions)
    assert {a.tool for a in rep.proposed_actions} <= {"rerun_tests", "open_ticket", "rollback_release"}


def test_bare_scenario_abstains_and_lists_what_is_missing(kb):
    rep, _, sc = run(kb, variant="bare")
    assert not sc["truth"]["sufficient"]
    assert rep.status == "insufficient_evidence" and rep.missing_evidence
    assert all(a.tool != "rollback_release" for a in rep.proposed_actions)      # never proposes a rollback without a supported cause
    assert rep.failure_class["id"] == "db_connection_timeout"                    # the class is still known
    assert "Investigation required" in to_markdown(rep)


def test_held_out_phrasing_is_diagnosed_through_diff_and_metric_evidence(kb):
    rep, b, _ = run(kb, seed=2, split="held", variant="rich", cause="memory_limit_reduced")
    assert rep.status == "diagnosed" and rep.hypotheses[0].cause_id == "memory_limit_reduced"
    assert audit_report(rep, b, kb)["ungrounded"] == 0


def test_alternatives_and_contradicting_evidence_are_reported(kb):
    rep, _, _ = run(kb, variant="rich", cause="pool_exhaustion")
    assert rep.alternatives_considered
    assert rep.hypotheses[0].claims and all(c.evidence_ids for c in rep.hypotheses[0].claims)


def test_injection_is_flagged_quarantined_and_not_obeyed(kb):
    for where in ("log", "commit", "diff"):
        sc = make_scenario(4, "held", "rich", "pool_exhaustion", injection=where)
        rep = investigate(Bundle(**sc["bundle"]), kb)
        assert any(f["where"] == where for f in rep.security_flags), where
        blob = str(rep.model_dump()).lower()
        assert "0.0.0" not in str([a.args for a in rep.proposed_actions]) and "all-hands" not in str([a.args for a in rep.proposed_actions])
        assert rep.hypotheses and rep.hypotheses[0].cause_id == "pool_exhaustion"
        assert "ignore all previous instructions" not in str([c.text for c in rep.confirmed_facts]).lower()
        assert all(a.requires_approval for a in rep.proposed_actions)


def test_tiny_tool_budget_degrades_gracefully_instead_of_crashing(kb):
    rep, _, _ = run(kb, cfg=Config(tool_budget=3))
    assert rep.trace["tool_errors"] and rep.status in ("diagnosed", "insufficient_evidence")


def test_missing_diff_tool_lowers_support_but_never_invents_it(kb):
    rep, _, sc = run(kb, variant="plain", cause="db_timeout_lowered", cfg=Config(disabled_tools={"get_diff", "list_commits"}))
    assert rep.status == "insufficient_evidence"          # diff was the only clue for this cause
    assert any(e.kind == "diff" for e in rep.evidence.values()) is False


def test_iterations_are_bounded(kb):
    rep, _, _ = run(kb, variant="bare", cfg=Config(max_iterations=3))
    assert rep.trace["iterations"] <= 3
    rep1, _, _ = run(kb, variant="bare", cfg=Config(max_iterations=1))
    assert rep1.trace["iterations"] == 1


def test_no_retrieval_ablation_still_runs_and_reports_no_related_incidents(kb):
    rep, _, _ = run(kb, cfg=Config(use_retrieval=False))
    assert rep.related_incidents == [] and rep.hypotheses


def test_garbage_bundle_does_not_crash(kb):
    b = Bundle(incident_id="INC-1", service="x", log=["", "\x00\x1b[31m", "nothing to see"])
    rep = investigate(b, kb)
    assert rep.status == "insufficient_evidence" and rep.failure_class["name"] == "unknown"


def test_hybrid_kb_end_to_end():
    kb = default_kb("hybrid")
    rep, b, _ = run(kb, seed=9, split="held", variant="plain", cause="idle_timeout_mismatch")
    assert rep.hypotheses[0].cause_id == "idle_timeout_mismatch"
    assert rep.related_issues and rep.related_issues[0]["url"].startswith("https://github.com/")
