/**
 * The semantic security layer.
 *
 * Security Auto Mode's authority is the deterministic engine. This layer is a *witness*: it looks at
 * a decision the engine could not settle and may say "the text that led here was telling the agent to
 * do this". What it says never becomes a decision on its own — it becomes one more piece of evidence,
 * folded through the same monotone reducer every other layer uses.
 *
 * That is the whole design, and it is why the invariants are not a list of `if` statements:
 *
 *   `Decision.reduce` folds evidence with `stricter()`, starting from ALLOW. Appending evidence can
 *   move a decision towards ASK or DENY and can never move it back. A layer that only ever *appends*
 *   is, structurally, incapable of relaxing anything.
 *
 * Concretely, and provably rather than by convention:
 *   - a deterministic DENY stays DENY, whatever the model says;
 *   - a hard ASK stays a hard ASK;
 *   - the model can never produce ALLOW, because ALLOW is the identity of the fold, not a value this
 *     layer can contribute. `BENIGN_CONTEXT` is in the vocabulary so the model has somewhere to put
 *     "I looked and this is fine", and it maps to no evidence at all — the only representation of a
 *     benign verdict that cannot be turned into permission;
 *   - the model can never produce DENY either. It contributes an ASK. A layer whose input is a model
 *     may insist on a person; it may not end the task on its own judgement.
 *
 * What changed from the action-only version: that one judged the command. It caught an upload whose
 * *file name* looked like a secret and missed every case where the secret was staged through a file
 * called `staged.dat` first — because the name is all it had. This one is given the untrusted text
 * the session actually read, which is where the meaning was the whole time.
 */
import { Effect } from "effect"
import { Decision } from "../decision"
import { SecuritySessionState } from "../state/store"
import type { NormalizedAction, NormalizedPath, SecurityDecision, SecurityEvidence } from "../types"
import type { ClassifierProvider } from "./provider"
import type { SemanticInput, Verdict } from "./schema"

export namespace SemanticEvidence {
  /** Counters for the ablation: cost and reliability are reported, never inferred. */
  export interface Stats {
    calls: number
    flagged: number
    errors: number
    timeouts: number
    considered: number
    latencies: number[]
    byCategory: Record<string, number>
  }

  const stats: Stats = {
    calls: 0,
    flagged: 0,
    errors: 0,
    timeouts: 0,
    considered: 0,
    latencies: [],
    byCategory: {},
  }

  export function snapshot(): Stats {
    return { ...stats, latencies: [...stats.latencies], byCategory: { ...stats.byCategory } }
  }

  export function reset() {
    consecutiveFailures = 0
    stats.calls = 0
    stats.flagged = 0
    stats.errors = 0
    stats.timeouts = 0
    stats.considered = 0
    stats.latencies = []
    stats.byCategory = {}
  }

  /**
   * Routing: which decisions are even eligible for a model call.
   *
   * Three conditions, all required. A DENY or a hard ASK is settled — the engine already stopped the
   * action, and a model call could only add latency. The action has to actually move data outward or
   * run through delegated authority — an `ls` is not a semantics problem. And the session has to have
   * read something untrusted, or have a recorded goal to compare against: with neither, there is no
   * semantic question to ask, only a command, and the engine reads commands better than a model does.
   */
  export function considers(input: {
    decision: SecurityDecision
    action: NormalizedAction
    sessionID: string
  }): boolean {
    const { decision, action } = input
    if (decision.action === "deny") return false
    if (decision.action === "ask" && decision.hard) return false
    const interesting =
      (action.kind === "shell" && action.command.commands.some((process) => process.network)) ||
      (action.kind === "permission" && action.permission.startsWith("mcp"))
    if (!interesting) return false
    const hasContext =
      SecuritySessionState.ingestedOf(input.sessionID).length > 0 ||
      SecuritySessionState.goalOf(input.sessionID) !== undefined
    if (!hasContext) return false
    stats.considered += 1
    return true
  }

  /**
   * Which credential store a sensitive path belongs to, as the word a person would use: `aws`, `ssh`,
   * `kube`. Derived from the single dot-directory the path sits under, so it is a class and never a
   * location — `~/.aws/credentials` yields `aws` and nothing else.
   *
   * This is what makes "did the request mention what this action touches?" answerable. Without it the
   * only thing the layer knows about `~/.aws/config` is that its base name is `config`, and a request
   * saying "set up the AWS deployment" looks unrelated to it.
   */
  function storeOf(target: NormalizedPath): string | undefined {
    if (target.relation !== "home-sensitive") return undefined
    const segment = target.canonical.split("/").find((part) => part.startsWith(".") && part.length > 1)
    return segment ? segment.slice(1).toLowerCase() : undefined
  }

  /** Assemble what the model is shown. Structure and bounded excerpts; never a command line. */
  export function summarize(action: NormalizedAction, sessionID: string): SemanticInput | undefined {
    const readSecret = SecuritySessionState.hasSecretContext(sessionID)
    const provenance = SecuritySessionState.ingestedOf(sessionID).map((item) => ({
      source: item.source,
      name: item.name,
      excerpt: item.excerpt,
    }))
    const goal = SecuritySessionState.goalOf(sessionID)
    if (action.kind === "permission")
      return {
        action: { network: false, delegated: action.permission, readSecret, operands: [] },
        provenance,
        ...(goal ? { goal } : {}),
      }
    if (action.kind !== "shell") return undefined
    const process = action.command.commands.find((item) => item.network)
    if (!process) return undefined
    return {
      action: {
        ...(process.executable !== undefined ? { executable: process.executable } : {}),
        network: true,
        ...(process.effect !== undefined ? { effect: process.effect } : {}),
        readSecret,
        operands: process.operands.map((operand) => ({
          // Basename only: the directory carries the user's identity and none of the meaning.
          basename: operand.path.canonical.split("/").pop() ?? "",
          relation: operand.path.relation,
          labels: operand.path.labels,
          effect: operand.effect,
          ...(storeOf(operand.path) ? { store: storeOf(operand.path)! } : {}),
        })),
      },
      provenance,
      ...(goal ? { goal } : {}),
    }
  }

  /**
   * A provider that is misconfigured fails the same way every time, and paying the deadline for it on
   * every decision is a latency bug wearing a safety hat. After three consecutive failures the layer
   * stops asking for the rest of the process, which lands it in exactly the state it is designed to
   * be safe in: contributing nothing.
   */
  const FAILURE_LIMIT = 3
  let consecutiveFailures = 0

  function tripped() {
    return consecutiveFailures >= FAILURE_LIMIT
  }

  /** Test seam: forget a tripped breaker. */
  export function resetBreaker() {
    consecutiveFailures = 0
  }

  function evidenceFor(verdict: Verdict, hard: boolean): SecurityEvidence {
    return Decision.evidence({
      rule: hard ? "advisory.semantic.escalate" : "advisory.semantic.flag",
      // `hard` survives a permissive rule and stops an unattended run. Still an ASK either way: the
      // layer asks for a person, it does not decide for them.
      source: hard ? "hard" : "default",
      action: "ask",
      reasonCode: verdict.category === "USER_GOAL_MISMATCH" ? "UNCLASSIFIED_ACTION" : "NETWORK_EGRESS",
      message: "A semantic review flagged this outbound action for a person to confirm.",
      attributes: { advisory: true, category: verdict.category, confidence: verdict.confidence },
    })
  }

  /**
   * How much of a hedged verdict to act on.
   *
   * `conservative` (the default) acts only on a verdict the provider is willing to stand behind.
   * `balanced` also acts on a middling SUSPICIOUS, as a soft ask.
   *
   * This exists because the measurement said the threshold matters more than anything else about the
   * layer. On the held-out evaluation set the offline provider reaches 50% recall at 14% false
   * escalation under `balanced` and 0% at 0% under `conservative` — the signal is there, and a
   * provider that hedges on unfamiliar phrasing loses all of it to the stricter rule. Which is right
   * depends on how well a given provider's confidence is calibrated, and that is a property of the
   * provider, not something this file can know. So it is a setting with a safe default, not a
   * constant tuned until a benchmark looked good.
   */
  export type Sensitivity = "conservative" | "balanced"

  function sensitivity(): Sensitivity {
    return process.env["KILO_SECURITY_AUTO_CLASSIFIER_SENSITIVITY"] === "balanced" ? "balanced" : "conservative"
  }

  /**
   * Turn a verdict into evidence, conservatively.
   *
   * The confidence label is the model's opinion of its own opinion, so it gates how far a verdict
   * carries and never stands alone: only `HIGH_RISK` reaches a hard ask, and only when the model is
   * not hedging. Everything softer contributes a soft ask, which changes what a person sees without
   * stopping an unattended run. `ORDINARY` — including `BENIGN_CONTEXT` — contributes nothing.
   *
   * No threshold on a self-reported number. Three labels, three coarse outcomes.
   */
  export function policy(verdict: Verdict, mode: Sensitivity = sensitivity()): SecurityEvidence[] {
    if (verdict.risk === "SUSPICIOUS" && verdict.confidence === "MEDIUM" && mode === "balanced")
      return [evidenceFor(verdict, false)]
    if (verdict.risk === "HIGH_RISK" && (verdict.confidence === "HIGH" || verdict.confidence === "MEDIUM"))
      return [evidenceFor(verdict, true)]
    if (verdict.risk === "HIGH_RISK") return [evidenceFor(verdict, false)]
    if (verdict.risk === "SUSPICIOUS" && verdict.confidence === "HIGH") return [evidenceFor(verdict, false)]
    return []
  }

  /**
   * Run a provider call under a real deadline.
   *
   * The `AbortSignal` asks the provider to stop; this decides how long the *decision* waits, which is
   * not the same thing and the difference was measurable. Resolving a model goes through the provider
   * service, and an unauthenticated resolution spends about a second fetching a model catalogue —
   * work no abort signal interrupts. Awaiting it meant a layer that cannot relax a decision could
   * still change one through latency: with no model configured, one benchmark scenario ran past its
   * own timeout and succeeded.
   *
   * So the deadline stops the waiting, not the work. Whatever the provider is still doing settles
   * into a handler that discards it.
   */
  async function bounded<T>(call: () => Promise<T>, timeoutMs: number): Promise<Outcome<T>> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const deadline = new Promise<Outcome<T>>((resolve) => {
      timer = setTimeout(() => resolve({ kind: "timeout" }), timeoutMs)
    })
    const work = call().then(
      (value): Outcome<T> => ({ kind: "ok", value }),
      (): Outcome<T> => ({ kind: "error" }),
    )
    try {
      return await Promise.race([work, deadline])
    } finally {
      clearTimeout(timer)
      // The loser of the race must not surface later as an unhandled rejection.
      void work.catch(() => undefined)
    }
  }

  type Outcome<T> = { kind: "ok"; value: T } | { kind: "timeout" } | { kind: "error" }

  /**
   * Ask the layer about one action. Yields evidence to fold, or nothing at all.
   *
   * Every failure path yields nothing: no provider, a timeout, a transport error, an answer outside
   * the vocabulary. "Nothing" means the deterministic decision stands exactly as it was — the same
   * behaviour as running with the layer switched off. That is the property the frozen guarantee rests
   * on: this layer can add friction, and its absence can never add risk.
   */
  export const assess = Effect.fn("SemanticEvidence.assess")(function* (input: {
    provider: ClassifierProvider | undefined
    summary: SemanticInput | undefined
    timeoutMs: number
  }) {
    if (!input.provider || !input.summary || tripped()) return [] as SecurityEvidence[]
    const { provider, summary, timeoutMs } = input
    const started = performance.now()
    const outcome = yield* Effect.promise(() => {
      // The signal still travels to the provider so a well-behaved one stops early; the race decides
      // how long this decision waits either way.
      const controller = new AbortController()
      setTimeout(() => controller.abort(), timeoutMs)
      return bounded(() => provider.classify(summary, controller.signal), timeoutMs)
    })
    stats.calls += 1
    stats.latencies.push(performance.now() - started)
    if (outcome.kind === "timeout") stats.timeouts += 1
    if (outcome.kind === "error") stats.errors += 1
    if (outcome.kind === "ok") consecutiveFailures = 0
    else consecutiveFailures += 1
    if (outcome.kind !== "ok") return [] as SecurityEvidence[]
    const evidence = policy(outcome.value)
    if (evidence.length > 0) {
      stats.flagged += 1
      stats.byCategory[outcome.value.category] = (stats.byCategory[outcome.value.category] ?? 0) + 1
    }
    return evidence
  })
}
