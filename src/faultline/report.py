"""Assemble the final Report (facts vs hypotheses vs missing evidence vs alternatives) and render it as Markdown."""
from __future__ import annotations

from . import evidence as E
from .schema import Claim, Hypothesis, ProposedAction, Report
from .taxonomy import CAUSES, CLASSES
from .tools import action_digest
from .verify import verify_claims


def assemble(inv, state) -> Report:
    b = inv.b
    ranked = state["class_ranked"]
    top_cls, p_top = ranked[0] if ranked else (None, 0.0)
    if p_top <= 0:
        top_cls = None  # no signal at all: say 'unknown' instead of naming an arbitrary class
    f = inv.findings
    facts: list[Claim] = []
    if top_cls and p_top > 0 and inv.class_ev:
        n = sum(z - a + 1 for a, z in inv.class_spans)
        facts.append(Claim(text=f"The CI log contains {n} error lines consistent with '{CLASSES[top_cls]['name']}' in {len(inv.class_spans)} place(s).",
                           evidence_ids=inv.class_ev, must_include=[inv.class_needle.lower()] if inv.class_needle else []))
    fl = next((i for i, l in enumerate(b.log, 1) if l.split("] ", 1)[-1].startswith("FAILED ")), None)
    if fl:
        t = b.log[fl - 1].split("] ", 1)[-1].split(" ")[1]
        facts.append(Claim(text=f"Test `{t}` failed in this run.", evidence_ids=[inv.add_ev("log", E.log_ref(b, fl, fl), b.log[fl - 1])], must_include=[t]))
    shown = {h["cand"]["cause_id"] for h in state["hypotheses"][:3]}
    for cid in shown:
        for eid, hit in f["diff"].get(cid, [])[:1]:
            facts.append(Claim(text=f"The release diff modifies `{hit['file']}` (added: `{hit['text'].strip()}`).", evidence_ids=[eid], must_include=[hit["text"].strip()]))
        for m in CAUSES[cid]["met"]:
            if m in f["metric"]:
                eid, tags = f["metric"][m]
                facts.append(Claim(text=f"Metric `{m}` shape is {'/'.join(tags)}.", evidence_ids=[eid], must_include=[tags[0]]))
    for eid, t in f["flaky"][:1]:
        facts.append(Claim(text=f"A failing test has an elevated recent failure rate ({t}).", evidence_ids=[eid], must_include=["recent runs failed"]))
    seen, uniq = set(), []
    for c in facts:
        if c.text not in seen:
            seen.add(c.text); uniq.append(c)
    facts, dropped = verify_claims(uniq, inv.ev, b, inv.kb)
    inv.dropped += dropped

    hyps, missing_all, alts = [], [], []
    insufficient = not state.get("sufficient")
    for rank, h in enumerate(state["hypotheses"], 1):
        cid, c = h["cand"]["cause_id"], CAUSES[h["cand"]["cause_id"]]
        miss, against = [], []
        if c["diff"]:
            if not b.diff:
                miss.append(f"The deployment diff is not attached; it is needed to confirm or rule out '{c['name']}'.")
            elif cid not in f["diff"]:
                miss.append(f"The attached diff contains no change matching '{c['name']}' (looked for `{c['dsig']}`).")
        for m, kind in c["met"].items():
            if m not in b.metrics:
                miss.append(f"Metric `{m}` was not provided (expected a {kind} pattern if this cause is real).")
            elif m in f["metric"] and kind not in f["metric"][m][1]:
                against.append(f"Metric `{m}` shows '{'/'.join(f['metric'][m][1])}', not the expected {kind} pattern. [{f['metric'][m][0]}]")
        if not f["log_cause"].get(cid):
            miss.append(f"No cause-specific log lines for '{c['name']}' were found.") if rank == 1 or insufficient else None
        hyps.append(Hypothesis(rank=rank, cause_id=cid, title=c["name"], component=c["comp"], confidence=h["confidence"], status=h["status"],
                               independent_evidence=h["cand"]["independent"], claims=h["claims"], evidence_against=against, missing_evidence=[m for m in miss if m]))
    if hyps:
        lead = hyps[0]
        if insufficient:
            missing_all = [m for h in hyps[:2] for m in h.missing_evidence]
            missing_all.insert(0, "The available evidence does not single out one root cause; the listed hypotheses are unconfirmed.")
        else:
            missing_all = list(lead.missing_evidence)
        for h in hyps[1:] if not insufficient else hyps:
            why = h.evidence_against[0] if h.evidence_against else (h.missing_evidence[0] if h.missing_evidence else "weaker support than the leading hypothesis")
            alts.append(f"{h.title} (confidence {h.confidence:.2f}, {h.status}): {why}")
    else:
        missing_all = ["No candidate root cause could be derived from the evidence provided."]

    invest = []
    for h in hyps[:2]:
        invest.append(f"[{h.title}] {CAUSES[h.cause_id]['rb'][1]}")
    invest += [f"Collect: {m}" for m in missing_all[1:3]] if insufficient else []

    tests = state.get("tests", [])
    actions: list[ProposedAction] = []
    if tests:
        actions.append(ProposedAction(id="A1", tool="rerun_tests", args={"tests": [t["test"] for t in tests[:3]]}, rationale="Re-run the recommended regression tests to confirm the diagnosis or verify a fix."))
    summary = f"Incident {b.incident_id}: {CLASSES[top_cls]['name'] if top_cls else 'unclassified failure'}; " + (f"leading hypothesis: {hyps[0].title} (conf {hyps[0].confidence:.2f})" if hyps and not insufficient else "root cause undetermined, see missing evidence")
    actions.append(ProposedAction(id="A2", tool="open_ticket", args={"title": f"[{b.incident_id}] {summary}"[:200], "body": summary}, rationale="Track the investigation outcome."))
    if hyps and not insufficient and f["diff"].get(hyps[0].cause_id) and b.release.get("version"):
        actions.append(ProposedAction(id="A3", tool="rollback_release", args={"version": str(b.release["version"])}, rationale=f"The leading, supported hypothesis is a change shipped in release {b.release['version']}; rolling back is a candidate mitigation (human decision)."))

    rel_inc = [{"id": h["id"], "similarity": h["score"], "cause_id": h["cause_id"], "class_id": h["class_id"], "service": h["service"], "summary": h["text"][:200]} for h in inv.kb_hits["incidents"][:5]]
    rel_iss = [{"id": h["id"], "title": h["title"][:120], "url": h["url"]} for h in inv.kb_hits["issues"][:3]]
    used = {e for c in facts for e in c.evidence_ids} | {e for h in hyps for c in h.claims for e in c.evidence_ids}
    return Report(incident_id=b.incident_id, status="insufficient_evidence" if insufficient else "diagnosed",
                  failure_class={"id": top_cls, "name": CLASSES[top_cls]["name"] if top_cls else "unknown", "component": CLASSES[top_cls]["comp"] if top_cls else None,
                                 "confidence": round(p_top, 3), "alternatives": [{"id": c, "name": CLASSES[c]["name"], "p": round(p, 3)} for c, p in ranked[1:3] if p > 0.1]},
                  confirmed_facts=facts, hypotheses=hyps, missing_evidence=missing_all, alternatives_considered=alts, recommended_investigations=invest,
                  regression_tests=tests, related_incidents=rel_inc, related_issues=rel_iss, proposed_actions=actions,
                  security_flags=inv.flags, dropped_claims=inv.dropped, evidence={k: v for k, v in inv.ev.items() if k in used})


def action_with_digest(a: ProposedAction) -> dict:
    d = a.model_dump()
    d["digest"] = action_digest(d)
    return d


def to_markdown(r: Report) -> str:
    L = [f"# Incident {r.incident_id} — {'Investigation complete' if r.status == 'diagnosed' else 'Investigation required: evidence insufficient'}", "",
         f"**Failure classification:** {r.failure_class['name']} (confidence {r.failure_class['confidence']:.2f})"
         + (f" · alternatives: {', '.join(a['name'] for a in r.failure_class['alternatives'])}" if r.failure_class["alternatives"] else ""), ""]
    if r.security_flags:
        L += ["> ⚠ **Untrusted content flagged:** " + "; ".join(f"{x['where']} {x['ref']} ({', '.join(x['patterns'])})" for x in r.security_flags) + ". Quarantined and not acted on.", ""]
    L += ["## Confirmed facts", *[f"- {c.text} " + " ".join(f"[{e}]" for e in c.evidence_ids) for c in r.confirmed_facts], "", "## Potential root causes"]
    for h in r.hypotheses:
        L.append(f"{h.rank}. **{h.title}** — {h.status}, confidence {h.confidence:.2f} (independent evidence: {', '.join(h.independent_evidence) or 'none'})")
        L += [f"   - {c.text} " + " ".join(f"[{e}]" for e in c.evidence_ids) for c in h.claims]
        L += [f"   - ✗ {a}" for a in h.evidence_against]
    L += ["", "## Missing evidence", *([f"- {m}" for m in r.missing_evidence] or ["- none"]), "", "## Alternative explanations", *([f"- {a}" for a in r.alternatives_considered] or ["- none"]),
          "", "## Recommended investigations", *[f"- {i}" for i in r.recommended_investigations], "", "## Regression tests", *[f"- `{t['test']}` — {t['why']}" for t in r.regression_tests],
          "", "## Related incidents", *[f"- {i['id']} ({i['cause_id']}, sim {i['similarity']}) — {i['summary'][:110]}" for i in r.related_incidents],
          "", "## Related public issues", *[f"- {i['title']} — {i['url']}" for i in r.related_issues],
          "", "## Proposed actions (require human approval)", *[f"- **{a.id}** `{a.tool}({a.args})` — {a.rationale}" for a in r.proposed_actions],
          "", "## Evidence", *[f"- **{e.id}** ({e.kind}) `{e.ref}`: `{e.excerpt[:140].replace(chr(10), ' ⏎ ')}`" for e in r.evidence.values()],
          "", "_Synthetic benchmark data is labelled as such; real GitHub issues carry their source URL._"]
    return "\n".join(L)
