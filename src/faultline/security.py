"""Untrusted-input handling and authorization.

Logs, commit messages and diffs are attacker-influenced. They are (1) sanitised, (2) scanned for instruction-like
content, which is flagged and quoted as evidence rather than obeyed, and (3) only ever placed in prompts inside
explicit data delimiters. No code path derives an action from bundle text: actions come from fixed rules plus
human approval.
"""
from __future__ import annotations

import os
import re
import secrets

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")
INJECTION_PATTERNS = {
    "override-instructions": r"ignore (all )?(previous|prior|above) instructions|disregard (the )?(above|previous)",
    "addresses-assistant": r"(note|notice|message) (to|for) (the )?(ai|assistant|llm|agent)|\bai (reviewer|assistant)\b|assistant must",
    "tool-invocation": r"\b(call|run|execute|invoke)\s+(rollback_release|open_ticket|page_oncall|rerun_tests|delete_\w+|disable_\w+)\b",
    "approval-bypass": r"without (asking|approval|confirmation)|approve everything|mark (this )?(incident )?(as )?resolved",
    "exfiltration": r"environment variables|\bapi[_ ]?key\b.*(body|send|include)|send .* to http",
}


def sanitize(text: str, max_len: int = 500) -> str:
    return _CTRL.sub("", _ANSI.sub("", text))[:max_len]


def scan_injection(text: str) -> list[str]:
    low = text.lower()
    return [name for name, pat in INJECTION_PATTERNS.items() if re.search(pat, low)]


def wrap_untrusted(label: str, text: str) -> str:
    """Delimit untrusted text for an LLM prompt. The delimiter id is random per call so content cannot close it."""
    tag = secrets.token_hex(4)
    return f"<untrusted id={tag} source={label}>\n{text}\n</untrusted id={tag}>"


ROLES = {"viewer": 0, "investigator": 1, "approver": 2}


class Auth:
    """API-key -> role map. Keys come from FAULTLINE_API_KEYS=key:role,key:role; otherwise random keys are minted."""

    def __init__(self, keys: dict[str, str] | None = None):
        if keys is None:
            env = os.environ.get("FAULTLINE_API_KEYS")
            keys = dict(p.split(":") for p in env.split(",")) if env else {secrets.token_urlsafe(12): r for r in ROLES}
        assert all(r in ROLES for r in keys.values()), "unknown role"
        self.keys = keys

    def role(self, key: str | None) -> str | None:
        return self.keys.get(key or "")

    def allows(self, key: str | None, needed: str) -> bool:
        r = self.role(key)
        return r is not None and ROLES[r] >= ROLES[needed]
