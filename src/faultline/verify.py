"""Evidence-grounding verifier. Independent of the reasoner: re-resolves every citation against the source data."""
from __future__ import annotations

from .evidence import _norm, matches, resolve
from .schema import Bundle, Claim, Evidence


def check_claim(claim: Claim, evidence: dict[str, Evidence], b: Bundle, kb) -> tuple[bool, str]:
    if not claim.evidence_ids:
        return False, "no evidence cited"
    texts = []
    for eid in claim.evidence_ids:
        ev = evidence.get(eid)
        if ev is None:
            return False, f"unknown evidence id {eid}"
        resolved = resolve(ev.kind, ev.ref, b, kb)
        if not matches(ev.kind, ev.excerpt, resolved):
            return False, f"{eid}: excerpt does not match source at {ev.ref}"
        texts.append(_norm(ev.excerpt).lower())
    blob = " ".join(texts)
    for needle in claim.must_include:
        if _norm(needle).lower() not in blob:
            return False, f"cited evidence does not contain {needle!r}"
    return True, "ok"


def verify_claims(claims: list[Claim], evidence: dict[str, Evidence], b: Bundle, kb) -> tuple[list[Claim], list[dict]]:
    kept, dropped = [], []
    for c in claims:
        ok, why = check_claim(c, evidence, b, kb)
        (kept if ok else dropped).append(c if ok else {"claim": c.text, "reason": why})
    return kept, dropped


def audit_report(report, b: Bundle, kb) -> dict:
    """Independent audit of a finished report (used by the benchmark): fraction of claims that fail grounding."""
    total = bad = 0
    for c in list(report.confirmed_facts) + [c for h in report.hypotheses for c in h.claims]:
        total += 1
        if not check_claim(c, report.evidence, b, kb)[0]:
            bad += 1
    return {"claims": total, "ungrounded": bad, "rate": bad / total if total else 0.0}
