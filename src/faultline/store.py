"""SQLite persistence: bundles, investigations, proposed/approved actions, audit log and per-node spans."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS bundles(incident_id TEXT PRIMARY KEY, body TEXT NOT NULL, created REAL);
CREATE TABLE IF NOT EXISTS investigations(id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, status TEXT, report TEXT, error TEXT, created REAL, finished REAL);
CREATE TABLE IF NOT EXISTS actions(id TEXT, investigation_id INTEGER, body TEXT, digest TEXT, state TEXT, decided_by TEXT, decided_at REAL, result TEXT, PRIMARY KEY(id, investigation_id));
CREATE TABLE IF NOT EXISTS audit(ts REAL, actor TEXT, event TEXT, detail TEXT);
CREATE TABLE IF NOT EXISTS spans(investigation_id INTEGER, node TEXT, ms REAL, meta TEXT);
"""


class Store:
    def __init__(self, path: str | Path = ":memory:"):
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        with self.lock:
            self.db.executescript(SCHEMA)

    def _x(self, sql, args=()):
        with self.lock:
            cur = self.db.execute(sql, args)
            self.db.commit()
            return cur

    def audit(self, actor: str, event: str, detail: dict | None = None):
        self._x("INSERT INTO audit VALUES(?,?,?,?)", (time.time(), actor, event, json.dumps(detail or {})))

    def put_bundle(self, bundle: dict):
        self._x("INSERT OR REPLACE INTO bundles VALUES(?,?,?)", (bundle["incident_id"], json.dumps(bundle), time.time()))

    def get_bundle(self, incident_id: str) -> dict | None:
        r = self._x("SELECT body FROM bundles WHERE incident_id=?", (incident_id,)).fetchone()
        return json.loads(r["body"]) if r else None

    def new_investigation(self, incident_id: str) -> int:
        return self._x("INSERT INTO investigations(incident_id,status,created) VALUES(?,?,?)", (incident_id, "running", time.time())).lastrowid

    def finish_investigation(self, inv_id: int, status: str, report: dict | None = None, error: str | None = None):
        self._x("UPDATE investigations SET status=?, report=?, error=?, finished=? WHERE id=?", (status, json.dumps(report) if report else None, error, time.time(), inv_id))

    def get_investigation(self, inv_id: int) -> dict | None:
        r = self._x("SELECT * FROM investigations WHERE id=?", (inv_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["report"] = json.loads(d["report"]) if d["report"] else None
        return d

    def add_actions(self, inv_id: int, actions: list[dict]):
        for a in actions:
            self._x("INSERT OR REPLACE INTO actions VALUES(?,?,?,?,?,?,?,?)", (a["id"], inv_id, json.dumps(a), a["digest"], "proposed", None, None, None))

    def get_action(self, inv_id: int, action_id: str) -> dict | None:
        r = self._x("SELECT * FROM actions WHERE investigation_id=? AND id=?", (inv_id, action_id)).fetchone()
        return dict(r) if r else None

    def list_actions(self, inv_id: int) -> list[dict]:
        return [{**json.loads(r["body"]), "state": r["state"], "decided_by": r["decided_by"], "result": json.loads(r["result"]) if r["result"] else None}
                for r in self._x("SELECT * FROM actions WHERE investigation_id=? ORDER BY id", (inv_id,)).fetchall()]

    def set_action_state(self, inv_id: int, action_id: str, state: str, by: str | None = None, result: dict | None = None):
        self._x("UPDATE actions SET state=?, decided_by=COALESCE(?,decided_by), decided_at=?, result=? WHERE investigation_id=? AND id=?",
                (state, by, time.time(), json.dumps(result) if result else None, inv_id, action_id))

    def add_spans(self, inv_id: int, trace: dict):
        for n in trace.get("nodes", []):
            self._x("INSERT INTO spans VALUES(?,?,?,?)", (inv_id, n["node"], n["ms"], "{}"))

    def metrics(self) -> dict:
        r = self._x("SELECT COUNT(*) n, AVG(finished-created) avg_s FROM investigations WHERE finished IS NOT NULL").fetchone()
        nodes = {x["node"]: round(x["avg"], 2) for x in self._x("SELECT node, AVG(ms) avg FROM spans GROUP BY node").fetchall()}
        by_status = {x["status"]: x["n"] for x in self._x("SELECT status, COUNT(*) n FROM investigations GROUP BY status").fetchall()}
        return {"investigations_finished": r["n"], "avg_seconds": r["avg_s"], "avg_node_ms": nodes, "by_status": by_status}

    def audit_log(self, limit: int = 100) -> list[dict]:
        return [dict(r) for r in self._x("SELECT * FROM audit ORDER BY ts DESC LIMIT ?", (limit,)).fetchall()]
