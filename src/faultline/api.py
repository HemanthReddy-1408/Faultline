"""FastAPI service: create investigations (async), read reports, approve/reject proposed actions.

Roles: viewer (read) < investigator (create) < approver (decide on actions). Send `X-API-Key`.
"""
from __future__ import annotations

import os
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from .graph import Config, investigate
from .kb import KnowledgeBase, default_kb
from .report import action_with_digest, to_markdown
from .schema import Bundle, Report
from .security import Auth
from .store import Store
from .tools import PermissionDenied, ToolError, ToolRuntime

STATIC = Path(__file__).parent / "static"


class Decision(BaseModel):
    decision: str  # approved | rejected
    note: str = ""


def create_app(store: Store | None = None, kb: KnowledgeBase | None = None, auth: Auth | None = None, cfg_factory=None, workers: int = 2) -> FastAPI:
    store = store or Store(os.environ.get("FAULTLINE_DB", ":memory:"))
    auth = auth or Auth()
    kb_box = {"kb": kb}
    pool = ThreadPoolExecutor(max_workers=workers)
    app = FastAPI(title="Faultline", version="0.1.0")
    app.state.store, app.state.auth, app.state.pool = store, auth, pool
    if not os.environ.get("FAULTLINE_API_KEYS") and kb is None and auth.keys:
        print("Faultline dev keys (no FAULTLINE_API_KEYS set):", {r: k for k, r in auth.keys.items()})

    def get_kb() -> KnowledgeBase:
        if kb_box["kb"] is None:
            kb_box["kb"] = default_kb()
        return kb_box["kb"]

    def need(role: str):
        def dep(x_api_key: str | None = Header(default=None)):
            if auth.role(x_api_key) is None:
                raise HTTPException(401, "missing or invalid API key")
            if not auth.allows(x_api_key, role):
                store.audit(auth.role(x_api_key), "forbidden", {"needed": role})
                raise HTTPException(403, f"role {auth.role(x_api_key)!r} cannot perform this action (needs {role!r})")
            return auth.role(x_api_key)
        return dep

    def run_job(inv_id: int, bundle: Bundle):
        try:
            cfg = cfg_factory() if cfg_factory else Config()
            rep = investigate(bundle, get_kb(), cfg)
            acts = [action_with_digest(a) for a in rep.proposed_actions]
            store.add_actions(inv_id, acts)
            store.add_spans(inv_id, rep.trace)
            store.finish_investigation(inv_id, "awaiting_approval" if acts else "done", rep.model_dump())
            store.audit("system", "investigation_finished", {"id": inv_id, "status": rep.status, "trace": {k: rep.trace[k] for k in ("total_ms", "tool_calls", "tokens_in", "tokens_out", "cost_usd")}})
        except Exception as e:  # noqa: BLE001 - a failed job must be recorded, never lost
            store.finish_investigation(inv_id, "failed", error=f"{type(e).__name__}: {e}")
            store.audit("system", "investigation_failed", {"id": inv_id, "error": str(e)})

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html")

    @app.get("/healthz")
    def health():
        return {"ok": True}

    @app.get("/demo/bundle")
    def demo_bundle(cause: str = "pool_exhaustion", variant: str = "rich", seed: int = 7, split: str = "held", role: str = Depends(need("investigator"))):
        """A generated SYNTHETIC bundle, for trying the UI without a real CI system."""
        from .synth import make_scenario
        from .taxonomy import CAUSES

        if cause not in CAUSES or variant not in ("rich", "plain", "bare") or split not in ("dev", "held"):
            raise HTTPException(422, "unknown cause/variant/split")
        return make_scenario(seed, split, variant=variant, cause_id=cause)["bundle"]

    @app.post("/bundles", status_code=201)
    def upload_bundle(bundle: Bundle, role: str = Depends(need("investigator"))):
        store.put_bundle(bundle.model_dump())
        store.audit(role, "bundle_uploaded", {"incident_id": bundle.incident_id})
        return {"incident_id": bundle.incident_id}

    @app.post("/investigations", status_code=202)
    def start(incident_id: str, role: str = Depends(need("investigator"))):
        raw = store.get_bundle(incident_id)
        if raw is None:
            raise HTTPException(404, f"unknown incident {incident_id!r}; upload a bundle first")
        inv_id = store.new_investigation(incident_id)
        store.audit(role, "investigation_started", {"id": inv_id, "incident_id": incident_id})
        pool.submit(run_job, inv_id, Bundle(**raw))
        return {"id": inv_id, "status": "running"}

    @app.get("/investigations/{inv_id}")
    def get(inv_id: int, role: str = Depends(need("viewer"))):
        inv = store.get_investigation(inv_id)
        if not inv:
            raise HTTPException(404, "unknown investigation")
        inv["actions"] = store.list_actions(inv_id)
        return inv

    @app.get("/investigations/{inv_id}/report.md", response_class=PlainTextResponse)
    def report_md(inv_id: int, role: str = Depends(need("viewer"))):
        inv = store.get_investigation(inv_id)
        if not inv or not inv["report"]:
            raise HTTPException(404, "report not ready")
        return to_markdown(Report(**inv["report"]))

    @app.post("/investigations/{inv_id}/actions/{action_id}")
    def decide(inv_id: int, action_id: str, d: Decision, role: str = Depends(need("approver")), x_api_key: str | None = Header(default=None)):
        if d.decision not in ("approved", "rejected"):
            raise HTTPException(422, "decision must be 'approved' or 'rejected'")
        row = store.get_action(inv_id, action_id)
        if not row:
            raise HTTPException(404, "no such proposed action")
        if row["state"] != "proposed":
            raise HTTPException(409, f"action already {row['state']}")
        action = __import__("json").loads(row["body"])
        store.audit(role, f"action_{d.decision}", {"investigation": inv_id, "action": action_id, "tool": action["tool"], "note": d.note})
        if d.decision == "rejected":
            store.set_action_state(inv_id, action_id, "rejected", by=role)
            return {"state": "rejected"}
        inv = store.get_investigation(inv_id)
        rt = ToolRuntime(Bundle(**store.get_bundle(inv["incident_id"])), get_kb())
        try:
            res = rt.execute_approved(action, {"action_id": action_id, "decision": "approved", "args_digest": row["digest"]})
        except (PermissionDenied, ToolError) as e:
            store.set_action_state(inv_id, action_id, "failed", by=role, result={"error": str(e)})
            raise HTTPException(422, str(e))
        store.set_action_state(inv_id, action_id, "executed", by=role, result=res)
        store.audit("system", "action_executed", {"investigation": inv_id, "action": action_id, "simulated": True})
        return {"state": "executed", "result": res}

    @app.get("/metrics/summary")
    def metrics(role: str = Depends(need("viewer"))):
        return store.metrics()

    @app.get("/audit")
    def audit(role: str = Depends(need("approver"))):
        return store.audit_log()

    return app
