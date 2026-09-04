/**
 * The LLM advisory layer.
 *
 * Security Auto Mode's authority is the deterministic engine. This layer is a *witness*: it looks at
 * an action the engine could not settle and may say "this still looks like data leaving the machine".
 * What it says never becomes a decision on its own — it becomes one more piece of evidence, folded
 * through the same monotone reducer every other layer uses.
 *
 * That is the whole design, and it is why the invariants are not a list of `if` statements here:
 *
 *   `Decision.reduce` folds evidence with `stricter()`, starting from ALLOW. Appending evidence can
 *   move a decision towards ASK or DENY and can never move it back. So a layer that only ever
 *   *appends* is, structurally, incapable of relaxing anything.
 *
 * Concretely, and provably rather than by convention:
 *   - a deterministic DENY stays DENY, whatever the model says;
 *   - a hard ASK stays a hard ASK;
 *   - the model can never produce ALLOW, because ALLOW is the identity of the fold, not a value this
 *     layer can contribute;
 *   - the model can never produce DENY either. It contributes an ASK. A layer whose input is a model
 *     is not allowed to end a task on its own judgement; it is allowed to insist on a human.
 *
 * The predecessor of this file returned a `Decision` and mapped `soft-ask + model says fine` to
 * ALLOW. That is the one shape the project's premise rules out — it makes the model load-bearing for
 * *permission*, so a repository that can talk to the model can talk its way out of an ask. It is
 * gone, together with the "does this match the user's request?" question that motivated it: the
 * user's request is not an input the security gate has (see `SecurityGate.evaluate`), so that
 * question could only ever have been answered from invented data.
 */
import { Effect } from "effect"
import { Decision } from "../decision"
import type { NormalizedAction, SecurityDecision, SecurityEvidence } from "../types"
import type { ActionSummary, ClassifierProvider } from "./provider"

export namespace ClassifierAdvisory {
  /** Counters for the ablation: cost and reliability are reported, never inferred. */
  export interface Stats {
    calls: number
    risky: number
    errors: number
    timeouts: number
    latencies: number[]
  }

  const stats: Stats = { calls: 0, risky: 0, errors: 0, timeouts: 0, latencies: [] }

  export function snapshot(): Stats {
    return { ...stats, latencies: [...stats.latencies] }
  }
  export function reset() {
    stats.calls = 0
    stats.risky = 0
    stats.errors = 0
    stats.timeouts = 0
    stats.latencies = []
  }

  /**
   * The band the advisory is allowed to look at: cases the deterministic layers did *not* settle.
   *
   * A DENY is settled. A hard ASK is settled — it already stops an autonomous run, so a model call
   * could only add latency. What is left is ALLOW and soft ASK, and of those only the actions that
   * put data on the network: everything else is ordinary local work the engine already understands,
   * and paying a model round-trip for it would be the "call the LLM on every action" design the
   * deterministic core exists to avoid.
   */
  export function considers(decision: SecurityDecision, action: NormalizedAction): boolean {
    if (decision.action === "deny") return false
    if (decision.action === "ask" && decision.hard) return false
    if (action.kind !== "shell") return false
    return action.command.commands.some((process) => process.network)
  }

  /** Structured, path-free description of the action. Returns undefined when there is nothing to judge. */
  export function summarize(action: NormalizedAction, readSecret: boolean): ActionSummary | undefined {
    if (action.kind !== "shell") return undefined
    const process = action.command.commands.find((item) => item.network)
    if (!process) return undefined
    return {
      ...(process.executable !== undefined ? { executable: process.executable } : {}),
      network: true,
      ...(process.effect !== undefined ? { effect: process.effect } : {}),
      readSecret,
      operands: process.operands.map((operand) => ({
        // Basename only: the directory layout carries the user's identity and none of the meaning.
        basename: operand.path.canonical.split("/").pop() ?? "",
        relation: operand.path.relation,
        labels: operand.path.labels,
        effect: operand.effect,
      })),
    }
  }

  const EVIDENCE: SecurityEvidence = Decision.evidence({
    rule: "advisory.classifier.egress",
    // `hard` so the ask survives a permissive rule and stops an unattended run. It is still an ASK:
    // the layer asks for a person, it does not decide for them.
    source: "hard",
    action: "ask",
    reasonCode: "NETWORK_EGRESS",
    message: "An advisory review flagged this outbound action for a person to confirm.",
    attributes: { advisory: true },
  })

  /**
   * Ask the advisory about one action. Yields evidence to fold, or nothing at all.
   *
   * Every failure path yields nothing: no provider, a timeout, a transport error, an answer outside
   * the vocabulary. "Nothing" means the deterministic decision stands exactly as it was — which is
   * the same behaviour as running with the layer switched off. That is the property the frozen
   * guarantee rests on: this layer can add friction, and its absence can never add risk.
   */
  export const assess = Effect.fn("ClassifierAdvisory.assess")(function* (input: {
    provider: ClassifierProvider | undefined
    summary: ActionSummary | undefined
    timeoutMs: number
  }) {
    if (!input.provider || !input.summary) return [] as SecurityEvidence[]
    const { provider, summary, timeoutMs } = input
    const started = performance.now()
    const outcome = yield* Effect.promise(async () => {
      const controller = new AbortController()
      const timer = setTimeout(() => controller.abort(), timeoutMs)
      try {
        const verdict = await provider.classify(summary, controller.signal)
        return { kind: "ok" as const, risky: verdict.risky }
      } catch {
        return { kind: controller.signal.aborted ? ("timeout" as const) : ("error" as const), risky: false }
      } finally {
        clearTimeout(timer)
      }
    })
    stats.calls += 1
    stats.latencies.push(performance.now() - started)
    if (outcome.kind === "timeout") stats.timeouts += 1
    if (outcome.kind === "error") stats.errors += 1
    if (outcome.kind !== "ok" || !outcome.risky) return [] as SecurityEvidence[]
    stats.risky += 1
    return [EVIDENCE]
  })
}
