import asyncio
import json
import time

import httpx
import pytest
from fastapi.testclient import TestClient

from faultline import api as api_mod
from faultline.api import create_app
from faultline.eval import agg, run_config, score_one, wilson
from faultline.graph import Config, investigate
from faultline.reasoner import GroqClient, LLMReasoner
from faultline.schema import Bundle
from faultline.security import Auth
from faultline.store import Store
from faultline.synth import build_benchmark, make_scenario

KEYS = {"kv": "viewer", "ki": "investigator", "ka": "approver"}


# ---------------- LLM reasoner (mocked transport; no network, no key needed) ----------------
def llm(handler):
    client = GroqClient(api_key="test", transport=httpx.MockTransport(handler))
    return LLMReasoner(client, price_in_per_m=1.0, price_out_per_m=2.0)


def completion(payload, pin=100, pout=50):
    return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps(payload)}}], "usage": {"prompt_tokens": pin, "completion_tokens": pout}})


def test_llm_hallucinated_claims_are_dropped_by_the_verifier(kb):
    seen = {}

    def handler(req):
        seen["body"] = json.loads(req.content)
        return completion({"ranking": [{"cause_id": "pool_exhaustion", "claims": [
            {"text": "The pool was set to 1.", "evidence_ids": ["E999"], "quote": "pool_size: 1"},
            {"text": "Invented quote.", "evidence_ids": ["E1"], "quote": "this text is not in the evidence"}]}]})
    r = llm(handler)
    sc = make_scenario(5, "dev", "rich", "pool_exhaustion")
    rep = investigate(Bundle(**sc["bundle"]), kb, Config(reasoner=r))
    reasons = " ".join(d["reason"] for d in rep.dropped_claims)
    assert "unknown evidence id" in reasons and "does not contain" in reasons
    assert all("pool was set to 1" not in c.text for h in rep.hypotheses for c in h.claims)
    assert rep.trace["tokens_in"] == 100 and rep.trace["tokens_out"] == 50 and rep.trace["cost_usd"] == pytest.approx(200 / 1e6)
    user = seen["body"]["messages"][1]["content"]
    assert "<untrusted id=" in user and seen["body"]["messages"][0]["role"] == "system"


def test_llm_cannot_outrank_clearly_stronger_evidence(kb):
    handler = lambda req: completion({"ranking": [{"cause_id": "db_degradation"}, {"cause_id": "pool_exhaustion"}]})  # noqa: E731
    sc = make_scenario(5, "dev", "rich", "pool_exhaustion")
    rep = investigate(Bundle(**sc["bundle"]), kb, Config(reasoner=llm(handler)))
    assert rep.hypotheses[0].cause_id == "pool_exhaustion"


def test_llm_garbage_output_falls_back_to_evidence_order(kb):
    handler = lambda req: httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}], "usage": {}})  # noqa: E731
    sc = make_scenario(5, "dev", "rich", "pool_exhaustion")
    assert investigate(Bundle(**sc["bundle"]), kb, Config(reasoner=llm(handler))).hypotheses[0].cause_id == "pool_exhaustion"


def test_groq_client_requires_key_and_retries_rate_limits(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GROQ_API_KEY"):
        GroqClient()
    monkeypatch.setattr(time, "sleep", lambda s: None)
    calls = {"n": 0}

    def h(req):
        calls["n"] += 1
        return httpx.Response(429) if calls["n"] < 3 else completion({"ranking": []})
    GroqClient("k", transport=httpx.MockTransport(h)).complete([{"role": "user", "content": "x"}])
    assert calls["n"] == 3


# ---------------- API ----------------
@pytest.fixture
def client(kb):
    app = create_app(Store(), kb, Auth(dict(KEYS)))
    return TestClient(app), app


def H(k):
    return {"X-API-Key": k}


def wait(c, inv_id, key="kv"):
    for _ in range(100):
        inv = c.get(f"/investigations/{inv_id}", headers=H(key)).json()
        if inv["status"] != "running":
            return inv
        time.sleep(0.1)
    raise AssertionError("investigation did not finish")


def start(c, variant="rich", cause="pool_exhaustion"):
    b = make_scenario(5, "dev", variant, cause)["bundle"]
    assert c.post("/bundles", json=b, headers=H("ki")).status_code == 201
    r = c.post(f"/investigations?incident_id={b['incident_id']}", headers=H("ki"))
    assert r.status_code == 202
    return r.json()["id"]


def test_authn_and_authz(client):
    c, _ = client
    b = make_scenario(5, "dev")["bundle"]
    assert c.post("/bundles", json=b).status_code == 401
    assert c.post("/bundles", json=b, headers=H("wrong")).status_code == 401
    assert c.post("/bundles", json=b, headers=H("kv")).status_code == 403
    assert c.get("/audit", headers=H("ki")).status_code == 403
    assert c.post("/investigations?incident_id=nope", headers=H("ki")).status_code == 404


def test_full_flow_with_human_approval_gate(client):
    c, app = client
    inv_id = start(c)
    inv = wait(c, inv_id)
    assert inv["status"] == "awaiting_approval" and inv["report"]["status"] == "diagnosed"
    assert all(a["state"] == "proposed" and a["result"] is None for a in inv["actions"])      # nothing runs on its own
    assert c.get(f"/investigations/{inv_id}/report.md", headers=H("kv")).text.startswith("# Incident")
    url = f"/investigations/{inv_id}/actions/A1"
    assert c.post(url, json={"decision": "approved"}, headers=H("ki")).status_code == 403    # investigators cannot approve
    assert c.post(url, json={"decision": "maybe"}, headers=H("ka")).status_code == 422
    ok = c.post(url, json={"decision": "approved", "note": "go"}, headers=H("ka"))
    assert ok.status_code == 200 and ok.json()["state"] == "executed" and ok.json()["result"]["simulated"]
    assert c.post(url, json={"decision": "approved"}, headers=H("ka")).status_code == 409    # no double execution
    rej = c.post(f"/investigations/{inv_id}/actions/A2", json={"decision": "rejected"}, headers=H("ka"))
    assert rej.json()["state"] == "rejected"
    states = {a["id"]: a["state"] for a in c.get(f"/investigations/{inv_id}", headers=H("kv")).json()["actions"]}
    assert states["A1"] == "executed" and states["A2"] == "rejected"
    events = [e["event"] for e in c.get("/audit", headers=H("ka")).json()]
    assert {"action_approved", "action_rejected", "action_executed", "investigation_finished", "forbidden"} <= set(events)
    m = c.get("/metrics/summary", headers=H("kv")).json()
    assert m["investigations_finished"] >= 1 and "gather" in m["avg_node_ms"]


def test_tampered_action_in_store_is_refused(client):
    c, app = client
    inv_id = start(c)
    wait(c, inv_id)
    st = app.state.store
    st._x("UPDATE actions SET body=? WHERE id='A1' AND investigation_id=?", (json.dumps({"id": "A1", "tool": "page_oncall", "args": {"team": "all"}}), inv_id))
    r = c.post(f"/investigations/{inv_id}/actions/A1", json={"decision": "approved"}, headers=H("ka"))
    assert r.status_code == 422 and "modified after approval" in r.json()["detail"]


def test_failed_job_is_recorded_not_lost(kb, monkeypatch):
    monkeypatch.setattr(api_mod, "investigate", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    c = TestClient(create_app(Store(), kb, Auth(dict(KEYS))))
    inv = wait(c, start(c))
    assert inv["status"] == "failed" and "boom" in inv["error"]


def test_demo_bundle_endpoint_validates_input(client):
    c, _ = client
    assert c.get("/demo/bundle?cause=dns_outage&variant=bare", headers=H("ki")).json()["incident_id"].startswith("INC-")
    assert c.get("/demo/bundle?cause=nope", headers=H("ki")).status_code == 422


# ---------------- MCP ----------------
def test_mcp_exposes_read_only_tools_and_serves_calls(kb):
    from faultline.mcp_server import build_server
    store = Store()
    b = make_scenario(5, "dev", "rich", "pool_exhaustion")["bundle"]
    store.put_bundle(b)
    mcp = build_server(store, kb)
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert {"search_runbooks", "get_diff", "grep_log", "get_metric"} <= names
    assert not names & {"rerun_tests", "open_ticket", "rollback_release", "page_oncall"}
    out = asyncio.run(mcp.call_tool("grep_log", {"incident_id": b["incident_id"], "pattern": "QueuePool"}))
    assert "QueuePool" in str(out)


# ---------------- evaluation harness ----------------
def test_wilson_interval_sanity():
    lo, hi = wilson(50, 100)
    assert 0.40 < lo < 0.5 < hi < 0.60 and wilson(0, 0) == (0.0, 0.0)


def test_harness_scores_a_small_slice(kb):
    scs = build_benchmark(10, 10, 2)["scenarios"]
    r = run_config("t", kb, scs)
    o = r["overall"]
    assert o["n"] == 20 and o["ungrounded_claim_rate"] == 0.0 and 0 <= o["class_ok"]["value"] <= 1
    assert r["dev"]["n"] == 10 and r["held"]["n"] == 10 and "variant_bare" in r
