# Faultline benchmark results

**All incidents are labelled synthetic** (120 dev + 120 held-out scenarios, 18 injection scenarios) against a knowledge base of 300 synthetic past incidents, 25 runbooks and 268 real public GitHub issues. Signatures were written from the dev phrasings only; held-out uses unseen paraphrases.

## Systems

| System | Class acc | Cause top-1 (evidence sufficient) | Correct abstention (insufficient) | Confident-wrong rate | Evidence P | Evidence R | Ungrounded claims |
|---|---|---|---|---|---|---|---|
| **overall** | | | | | | | |
| Faultline (full) | 0.942 | 0.870 [0.813, 0.911] | 1.000 | 0.000 | 0.924 | 0.565 | 0.000 |
| B0 log-regex → first cause | 0.779 | 0.370 [0.303, 0.441] | 0.000 | 0.717 | — | — | — |
| B1 copy nearest past incident | 0.875 | 0.435 [0.365, 0.507] | 0.000 | 0.667 | — | — | — |
| **dev** | | | | | | | |
| Faultline (full) | 1.000 | 0.897 [0.821, 0.943] | 1.000 | 0.000 | 0.969 | 0.674 | 0.000 |
| B0 log-regex → first cause | 1.000 | 0.464 [0.368, 0.563] | 0.000 | 0.625 | — | — | — |
| B1 copy nearest past incident | 1.000 | 0.454 [0.358, 0.553] | 0.000 | 0.633 | — | — | — |
| **held** | | | | | | | |
| Faultline (full) | 0.883 | 0.839 [0.748, 0.902] | 1.000 | 0.000 | 0.874 | 0.444 | 0.000 |
| B0 log-regex → first cause | 0.558 | 0.264 [0.183, 0.366] | 0.000 | 0.808 | — | — | — |
| B1 copy nearest past incident | 0.750 | 0.414 [0.316, 0.519] | 0.000 | 0.700 | — | — | — |

## Ablations (overall)

| Variant | Class acc | Cause top-1 | Correct abstention | Confident-wrong | held-out cause top-1 | tool calls | p50 ms |
|---|---|---|---|---|---|---|---|
| faultline-full | 0.942 | 0.870 | 1.000 | 0.000 | 0.839 | 20.5 | 31 |
| no-retrieval | 0.779 | 0.766 | 1.000 | 0.000 | 0.621 | 19.8 | 4 |
| no-diff-tool | 0.942 | 0.440 | 1.000 | 0.000 | 0.402 | 29.1 | 39 |
| no-metrics-tool | 0.942 | 0.549 | 1.000 | 0.000 | 0.563 | 27.1 | 39 |
| single-iteration | 0.942 | 0.853 | 1.000 | 0.000 | 0.805 | 10.7 | 29 |

## Retrieval architecture inside the agent

| KB retrieval | Class acc (held-out) | Cause top-1 (held-out) | Related-incident NDCG@5 | Same-cause hit@5 | Test recall@5 | p50 ms |
|---|---|---|---|---|---|---|
| bm25 | 0.750 | 0.713 | 0.513 | 0.696 | 0.897 | 5 |
| dense | 0.883 | 0.816 | 0.507 | 0.762 | 0.914 | 30 |
| hybrid | 0.883 | 0.839 | 0.534 | 0.746 | 0.940 | 30 |
| hybrid+rerank(pretrained) | 0.767 | 0.782 | 0.506 | 0.708 | 0.910 | 672 |
| hybrid+rerank(RankForge fine-tuned) | 0.808 | 0.839 | 0.565 | 0.713 | 0.924 | 696 |

## Prompt-injection scenarios

18 scenarios with instruction-like text planted in logs / commit messages / diffs: flagged **1.00**, actions hijacked **0.00**, correct diagnosis despite injection **0.78**.

Calibration (ECE, 5 bins): 0.164.
