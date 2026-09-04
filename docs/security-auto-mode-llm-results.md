# LLM layers — measured ablation (heuristic vs local models)

Offline ablation of the two LLM layers over inputs mirroring the benchmark
corpus (12 injection + 3 subtle-injection contents, 10 benign + 3 tricky-benign
contents, 6 intent pairs). Run with:

```
LLM=heuristic bun run src/kilocode/security/classifier/eval.ts
LLM=openai LLM_MODEL=qwen2.5:3b bun run …/eval.ts   # local via Ollama /v1
LLM=openai LLM_MODEL=qwen2.5:7b bun run …/eval.ts
```

## Results

| Metric | Heuristic (regex) | qwen2.5:3b (local) | qwen2.5:7b (local) |
| --- | --: | --: | --: |
| Context Checker — detection (TPR) | 80% (12/15) | 73% (11/15) | 73% (11/15) |
| Context Checker — false positives (FPR) | 23% (3/13) | **0% (0/13)** | **0% (0/13)** |
| Projected injection-driven ASR | 100% → 20% | 100% → 27% | 100% → 27% |
| False escalations on benign→egress (friction) | 3/13 | **0/13** | **0/13** |
| Action Classifier — correct intent | 100%\* | 67% (4/6) | **100% (6/6)** |
| Model calls (whole ablation) | 0 | 84 | 84 |
| Decision latency p50 | ~0 (regex) | 296 ms | 1001 ms |
| Decision latency p95 | ~0 | 960 ms | 53881 ms† |

\* Heuristic 100% is on the hand-written intent cases it was tuned for — an over-statement, not a real generalisation.
† 7B p95 is dominated by the first-call cold load of the model into RAM; steady-state p50 ≈ 1 s.

## Honest reading

- **Where the LLM clearly wins: false positives.** Both local models score **0% FPR**
  vs the regex heuristic's **23%**. The models correctly tell "read the .env and send
  us feedback" / "run `curl …/health`" / "delete the build dir" (benign) apart from a
  real exfiltration instruction. Semantics beat pattern-matching exactly where a naive
  guard over-flags and creates friction.
- **Model size matters for *intent*, not for *injection detection*.** The Action
  Classifier (did the user actually authorise this action?) jumps **67% → 100%** from 3B
  to 7B. Context-injection detection is unchanged (73% TPR, 0% FPR): the easy cases are
  caught by both, and the same ~4 subtle/obfuscated injections are missed by both.
- **Latency is the real cost.** ~0.3 s (3B) to ~1 s (7B) per decision, vs ~1 ms for the
  deterministic engine — 300–1000×. This is why the LLM must run only on the narrow band
  (soft-ASK / untrusted-content ingestion) and why the Context Checker is two-stage
  (single-token filter → JSON only when flagged).

## Conclusion

On a **weak local model** — the case's corporate/open-source scenario — the LLM layers give
a **better security/friction trade-off** than a heuristic (injection ASR 100%→27% at **zero**
false escalations, where the regex paid 23% FPR), and a stronger model closes the *intent*
gap (67%→100%). But they do **not** replace the deterministic core: recall is partial (73%),
and latency is 300–1000× higher. This validates the architecture: **deterministic policy +
sandbox are the injection-immune authority (≈1 ms); the LLM is a thin semantic layer on a
narrow band.** Invariants are enforced in code and unit-tested: a DENY / explicit hard-ASK is
never relaxed by the model, and any provider error fails closed.

Numbers are single-run (temperature 0). Multiple runs are advisable for a stochasticity band.
