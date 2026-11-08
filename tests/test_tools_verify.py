import pytest

from faultline import evidence as E
from faultline.schema import Bundle, Claim, Evidence
from faultline.synth import make_scenario
from faultline.tools import BudgetExceeded, PermissionDenied, ToolError, ToolRuntime, TransientToolError, action_digest
from faultline.verify import audit_report, check_claim, verify_claims


@pytest.fixture
def bundle():
    return Bundle(**make_scenario(3, "dev", "rich", "pool_exhaustion")["bundle"])


def test_read_tools_validate_arguments(bundle, kb):
    rt = ToolRuntime(bundle, kb)
    assert rt.call("get_log_slice", start=1, end=3)["lines"]
    with pytest.raises(ToolError):
        rt.call("get_log_slice", start=5, end=1)
    with pytest.raises(ToolError):
        rt.call("search_runbooks", query="")           # schema: min_length
    with pytest.raises(ToolError):
        rt.call("grep_log", pattern="(")               # bad regex
    with pytest.raises(ToolError):
        rt.call("get_metric", name="nope")


def test_write_tools_can_never_be_called_directly(bundle, kb):
    rt = ToolRuntime(bundle, kb)
    for t in ("rerun_tests", "open_ticket", "rollback_release", "page_oncall"):
        with pytest.raises(PermissionDenied):
            rt.call(t, version="1.0.0")
    with pytest.raises(PermissionDenied):
        rt.call("delete_branch")                       # unknown tools are not callable either
    assert rt.actions_executed == []


def test_tool_budget_is_enforced(bundle, kb):
    rt = ToolRuntime(bundle, kb, budget=2)
    rt.call("list_metrics"); rt.call("list_metrics")
    with pytest.raises(BudgetExceeded):
        rt.call("list_metrics")


def test_transient_errors_are_retried_then_surface(bundle, kb):
    rt = ToolRuntime(bundle, kb, retries=2)
    n = {"c": 0}

    def flaky(a):
        n["c"] += 1
        if n["c"] < 3:
            raise TransientToolError("503")
        return ["ok"]
    rt.read["list_metrics"] = (rt.read["list_metrics"][0], flaky)
    assert rt.call("list_metrics") == ["ok"] and n["c"] == 3
    rt.read["list_metrics"] = (rt.read["list_metrics"][0], lambda a: (_ for _ in ()).throw(TransientToolError("down")))
    with pytest.raises(ToolError, match="failed after 3 attempts"):
        rt.call("list_metrics")


def test_execute_approved_requires_exact_matching_approval(bundle, kb):
    rt = ToolRuntime(bundle, kb)
    act = {"id": "A1", "tool": "rerun_tests", "args": {"tests": ["tests/a.py"]}}
    for bad in (None, {"action_id": "A2", "decision": "approved"}, {"action_id": "A1", "decision": "rejected"},
                {"action_id": "A1", "decision": "approved", "args_digest": "deadbeef"}):
        with pytest.raises(PermissionDenied):
            rt.execute_approved(act, bad)
    ok = rt.execute_approved(act, {"action_id": "A1", "decision": "approved", "args_digest": action_digest(act)})
    assert ok["simulated"] and rt.actions_executed == [ok]


def test_rollback_only_to_a_real_release_version(bundle, kb):
    rt = ToolRuntime(bundle, kb)
    bad = {"id": "A3", "tool": "rollback_release", "args": {"version": "0.0.0"}}
    with pytest.raises(ToolError, match="not a release"):
        rt.execute_approved(bad, {"action_id": "A3", "decision": "approved"})
    good = {"id": "A3", "tool": "rollback_release", "args": {"version": bundle.release["version"]}}
    assert rt.execute_approved(good, {"action_id": "A3", "decision": "approved"})["result"]["rolled_back_to"] == bundle.release["version"]


def _ev(b, kind="log", a=1, z=2, excerpt=None):
    ref = E.log_ref(b, a, z)
    return Evidence(id="E1", kind=kind, ref=ref, excerpt=excerpt if excerpt is not None else "\n".join(b.log[a - 1: z]))


def test_verifier_accepts_real_citation_and_rejects_every_kind_of_fabrication(bundle, kb):
    ev = {"E1": _ev(bundle)}
    first = bundle.log[0].split("] ", 1)[-1][:12]
    assert check_claim(Claim(text="t", evidence_ids=["E1"], must_include=[first]), ev, bundle, kb)[0]
    assert not check_claim(Claim(text="no citation"), ev, bundle, kb)[0]
    assert not check_claim(Claim(text="x", evidence_ids=["E9"]), ev, bundle, kb)[0]
    assert not check_claim(Claim(text="x", evidence_ids=["E1"], must_include=["pool_size: 999"]), ev, bundle, kb)[0]
    tampered = {"E1": _ev(bundle, excerpt="QueuePool limit of size 5 reached")}
    assert "does not match" in check_claim(Claim(text="x", evidence_ids=["E1"]), tampered, bundle, kb)[1]
    out_of_range = {"E1": Evidence(id="E1", kind="log", ref=E.log_ref(bundle, 9000, 9001), excerpt="x")}
    assert not check_claim(Claim(text="x", evidence_ids=["E1"]), out_of_range, bundle, kb)[0]
    wrong_file = {"E1": Evidence(id="E1", kind="log", ref="other.log:1-2", excerpt="x")}
    assert not check_claim(Claim(text="x", evidence_ids=["E1"]), wrong_file, bundle, kb)[0]


def test_verify_claims_splits_kept_and_dropped_with_reasons(bundle, kb):
    ev = {"E1": _ev(bundle)}
    kept, dropped = verify_claims([Claim(text="ok", evidence_ids=["E1"]), Claim(text="made up", evidence_ids=["E404"])], ev, bundle, kb)
    assert [c.text for c in kept] == ["ok"] and "unknown evidence id" in dropped[0]["reason"]
