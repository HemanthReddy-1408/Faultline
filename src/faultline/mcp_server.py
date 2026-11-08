"""MCP server exposing Faultline's READ-ONLY investigation tools to any MCP client.

Write tools (rerun_tests, open_ticket, rollback_release, page_oncall) are intentionally not exposed: an MCP client
cannot cause side effects through this server.  Run: `python -m faultline.mcp_server --db faultline.db`
"""
from __future__ import annotations

import argparse

from mcp.server.fastmcp import FastMCP

from .kb import default_kb
from .schema import Bundle
from .store import Store
from .tools import ToolRuntime


def build_server(store: Store, kb=None) -> FastMCP:
    mcp = FastMCP("faultline")
    box = {"kb": kb}

    def _kb():
        box["kb"] = box["kb"] or default_kb()
        return box["kb"]

    def rt(incident_id: str) -> ToolRuntime:
        raw = store.get_bundle(incident_id)
        if raw is None:
            raise ValueError(f"unknown incident {incident_id}")
        return ToolRuntime(Bundle(**raw), _kb(), budget=20)

    @mcp.tool()
    def search_runbooks(query: str, k: int = 5) -> list:
        """Search engineering runbooks (hybrid BM25 + dense retrieval)."""
        return _kb().search("runbooks", query, min(max(k, 1), 10))

    @mcp.tool()
    def search_incidents(query: str, k: int = 5) -> list:
        """Search past incident postmortems."""
        return _kb().search("incidents", query, min(max(k, 1), 10))

    @mcp.tool()
    def search_github_issues(query: str, k: int = 5) -> list:
        """Search real public GitHub issues for similar failures."""
        return _kb().search("issues", query, min(max(k, 1), 10))

    @mcp.tool()
    def get_log_slice(incident_id: str, start: int, end: int) -> dict:
        """Return lines start..end (1-based, max 200) of an incident's CI log."""
        return rt(incident_id).call("get_log_slice", start=start, end=end)

    @mcp.tool()
    def grep_log(incident_id: str, pattern: str) -> list:
        """Regex search an incident's CI log."""
        return rt(incident_id).call("grep_log", pattern=pattern)

    @mcp.tool()
    def get_diff(incident_id: str, file: str | None = None) -> dict:
        """List files in the deployment diff, or return one file's hunk."""
        return rt(incident_id).call("get_diff", file=file)

    @mcp.tool()
    def list_commits(incident_id: str) -> list:
        """Recent commits included in the failing release."""
        return rt(incident_id).call("list_commits")

    @mcp.tool()
    def get_metric(incident_id: str, name: str) -> dict:
        """Return a metric series attached to the incident."""
        return rt(incident_id).call("get_metric", name=name)

    return mcp


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default="faultline.db")
    build_server(Store(ap.parse_args().db)).run()
