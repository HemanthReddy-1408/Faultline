# Faultline

**Agentic incident investigation for CI/CD failures that refuses to guess.** Give it a CI failure bundle (log, deployment diff, commits, metrics, test history); it classifies the failure, retrieves runbooks and similar past incidents, inspects changes through read-only tools, and produces a report that separates **confirmed facts**, **evidence-backed hypotheses**, **missing evidence** and **alternative explanations**. Every claim cites evidence that an independent verifier re-resolves against the source; anything it cannot ground is dropped. Consequential actions (re-run tests, open ticket, rollback) are only *proposed* and wait for a human approver.

Built on [RetrievalLab](../RetrievalLab) (hybrid BM25 + dense retrieval, optional reranker — [RankForge](../RankForge) plugs in here).

```
bundle ─► ingest ─► classify ─► gather ─► hypothesize ─► verify ──(unsure & budget left)──► widen ─► gather…
          quarantine  signatures   tools:      score by        re-resolve every     │
          injection   + retrieval  logs/diff/  independent     citation, drop       └──► recommend ─► report ─► [human approval] ─► act
                      votes        metrics/    evidence kinds  ungrounded claims
                                   KB search
```
LangGraph state machine ([graph.py](src/faultline/graph.py)); bounded by max iterations, a tool-call budget and a recursion limit.

## Quick start
```bash
python -m venv .venv && .venv/bin/pip install -e ../RetrievalLab "mcp<2" -e ".[dev]"
.venv/bin/pytest -q                                  # 47 tests (unit, integration, failure, security)
.venv/bin/faultline investigate --demo --cause pool_exhaustion --variant rich   # Markdown report for a generated (synthetic) bundle
.venv/bin/faultline eval                             # full benchmark -> results/RESULTS.md (~10 min)
FAULTLINE_API_KEYS=v:viewer,i:investigator,a:approver .venv/bin/faultline serve   # API + UI at :8200
.venv/bin/python -m faultline.mcp_server --db faultline.db                        # MCP server (read-only tools)
# docker (from the parent directory): docker build -f Faultline/Dockerfile -t faultline .
```

## What a report looks like
(Real output, generated bundle; see `faultline investigate --demo`.)
```
Incident INC-2005 — Investigation required: evidence insufficient
Failure classification: DNS resolution failure (0.92)
Confirmed facts:  9 error lines consistent with DNS resolution failure [E1][E2][E3]; test … failed [E4]
Potential root causes: 1. DNS outage — plausible, 0.32 (independent evidence: none)  2. Service hostname renamed — plausible, 0.32
Missing evidence: metric dns_servfail_rate not provided; deployment diff not attached …
Proposed actions (require human approval): A1 rerun_tests(...)  A2 open_ticket(...)     ← no rollback: no supported cause
```
With a diff and metric present (`--cause pool_exhaustion --variant rich`, real output):
```
1. Connection pool exhaustion — supported, confidence 0.95 (independent evidence: diff, metric)
   - The release diff changes `config/database.yml`: `pool_size: 5`. [E1]
   - Commit 71d8018 touched `config/database.yml`. [E2]
   - Metric `db_pool_in_use` shows a saturated pattern consistent with connection pool exhaustion. [E3]
2. Database timeout setting lowered — plausible, confidence 0.31 (independent evidence: none)
3. Database server degradation — plausible, confidence 0.30
```

## Components
| Piece | Where | Notes |
|---|---|---|
| Workflow | [graph.py](src/faultline/graph.py) | classify → gather → hypothesize → verify → (widen) → recommend → report |
| Tools | [tools.py](src/faultline/tools.py) | 11 read-only tools with pydantic schemas, budgets, retries, result caps; 4 write tools that `call()` refuses unconditionally |
| MCP | [mcp_server.py](src/faultline/mcp_server.py) | exposes read-only tools only; a client cannot cause side effects |
| Verifier | [verify.py](src/faultline/verify.py), [evidence.py](src/faultline/evidence.py) | citation → re-derive source text → compare; plus required-substring entailment check |
| Reasoners | [reasoner.py](src/faultline/reasoner.py) | deterministic `HeuristicReasoner` (default, offline) and optional `LLMReasoner` (Groq, key from `GROQ_API_KEY`) |
| Security | [security.py](src/faultline/security.py) | sanitising, injection scan/quarantine, delimited prompts, API-key roles |
| API/UI | [api.py](src/faultline/api.py) | async investigations, approval endpoints, audit log, per-node spans |
| Benchmark | [synth.py](src/faultline/synth.py), [eval.py](src/faultline/eval.py) | seeded generator, baselines, ablations |

**Security model.** Logs/commits/diffs are attacker-influenced. Instruction-like lines are quarantined (replaced by a placeholder before any analysis), reported as flags, and never reach signature matching or retrieval queries. Actions come from fixed rules + approval, never from bundle text. Roles: `viewer` < `investigator` < `approver`; approval binds to the action's id *and* a digest of its tool+args (a tampered stored action is refused); `rollback_release` only accepts the bundle's own release version. Write tools are **simulated** in this build — wiring them to real systems is deliberately a separate step.

**LLM mode.** The LLM may only (a) break near-ties (within 0.08 score) and (b) attach claims — every claim must cite provided evidence ids with a verbatim quote, or the verifier drops it; it cannot outrank clearly stronger evidence and its confidence is ignored. It is covered by tests using a mocked transport (hallucinated citations dropped, garbage output falls back, token/cost accounting, 429 retries). **It has not been benchmarked live** — no API key was used for the numbers below; they are all from the deterministic reasoner.

## Benchmark (full: [results/RESULTS.md](results/RESULTS.md))
**Every incident is generated and labelled synthetic** — 120 dev + 120 held-out scenarios (25 root causes × 12 failure classes; variants *rich*, *plain*, *bare* where bare has genuinely no discriminating evidence), 18 injection scenarios, a KB of 300 synthetic past incidents + 25 runbooks + **268 real public GitHub issues** (with URLs; [scripts/fetch_github_issues.py](scripts/fetch_github_issues.py)). Protocol: signatures were written from the *dev* phrasings only; *held-out* uses unseen paraphrases and was not used to tune anything.

| System | Class acc | Cause top-1 (evidence sufficient) [95% CI] | Correct abstention (insufficient) | Confident-wrong | Ungrounded claims |
|---|---|---|---|---|---|
| **Faultline (all 240)** | 0.942 | **0.870** [0.813, 0.911] | **1.000** | **0.000** | 0.000 |
| Faultline — dev | 1.000 | 0.897 | 1.000 | 0.000 | 0.000 |
| Faultline — held-out | 0.883 | 0.839 [0.748, 0.902] | 1.000 | 0.000 | 0.000 |
| B0 log-regex → first cause (no abstention) | 0.779 | 0.370 | 0 | 0.717 | — |
| B1 copy nearest past incident (no abstention) | 0.875 | 0.435 | 0 | 0.667 | — |

Evidence precision 0.92, recall 0.57; test-recommendation recall@5 0.94 (precision 0.67); median 31 ms, ~20 tool calls per investigation (no LLM).

Ablations (cause top-1; held-out in parentheses): full 0.870 (0.839) · **no diff tool 0.440 (0.402)** · **no metrics tool 0.549 (0.563)** · no retrieval 0.766 (0.621, class acc 0.942 → 0.779) · single iteration 0.853 (0.805). Retrieval inside the agent (held-out class accuracy): BM25 0.750 · dense 0.883 · hybrid 0.883 · hybrid+pretrained reranker 0.767 · hybrid+RankForge reranker 0.808.

Prompt injection (18 scenarios): flagged 18/18, hijacked actions 0, correct diagnosis despite injection 0.78.

### How to read this honestly
- **The data is mine and so are the labels.** The generator and the reasoner share a taxonomy, so this benchmark validates the *discipline* (grounding, abstention, tool gating, injection handling) and shows what each evidence source contributes — it does **not** show real-world diagnostic accuracy. The dev→held gap (0.897 → 0.839) is the generalisation signal available here.
- **Its errors are all abstentions, not wrong answers**: 13% of diagnosable scenarios were declined (wrongly-abstained 0.130 [0.089, 0.187]) and none were confidently wrong. B0/B1 can't abstain by construction, so their confident-wrong rate is partly definitional; the cause-top-1 gap (+0.43 over B1, CI +0.36…+0.51) is the fairer comparison.
- **Calibration is imperfect** (ECE 0.164, 5 bins). Evidence recall 0.57 means reports cite a subset of the gold evidence.
- The ungrounded-claim rate of 0.000 is by construction for the heuristic reasoner (the audit re-uses the same resolvers); its real test is the hallucinating-LLM unit tests, where fabricated citations are dropped.
- Fine-tuned reranking did not beat plain hybrid retrieval inside the agent (see RankForge), so the default KB mode is hybrid without a reranker.

## Design decisions (short)
- **Deterministic core, LLM optional**: reproducible benchmark, no key needed, and a hard guarantee on what the LLM can influence.
- **Independent-evidence rule**: a hypothesis is *supported* only with ≥2 independent evidence kinds (log / diff / metric), or one non-log kind plus class/history agreement; history similarity alone never counts as evidence.
- **Abstain, then widen once**: one bounded widening pass (more classes, global signature scan) before admitting insufficiency; it adds +1.7 points of cause accuracy (0.853 → 0.870).
- **Human gate is structural**, not a prompt instruction: write tools are unreachable from the graph.

## Resume bullets (measured)
- Designed Faultline, a LangGraph incident-investigation agent with hybrid retrieval, MCP-exposed read-only tools and a grounding verifier; reports separate confirmed facts, supported hypotheses, missing evidence and alternatives, and gate every consequential action behind role-based human approval.
- On a labelled-synthetic benchmark (240 scenarios + 18 injection cases): 0.87 root-cause top-1 (95% CI 0.81–0.91; 0.84 on held-out phrasing), 100% abstention when evidence was insufficient, 0 confidently-wrong diagnoses, 0 ungrounded claims, vs 0.37–0.44 for regex/nearest-incident baselines; ablations showed deployment-diff access was worth +43 points.
- Hardened against prompt injection in logs/commits/diffs (18/18 flagged and quarantined, 0 hijacked actions) with sanitisation, delimited prompts, digest-bound approvals and an audited API.
