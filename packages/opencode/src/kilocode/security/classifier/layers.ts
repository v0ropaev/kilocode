/**
 * The two LLM layers, with their non-negotiable invariants enforced in code.
 *
 * Neither layer can weaken a deterministic decision:
 *  - Context Checker never blocks; it only produces a risk signal for Session State.
 *  - Action Classifier acts ONLY on a `soft-ask` (heuristic ambiguity). It can
 *    down-grade that to `allow` (less friction) or escalate to `deny` (catch an
 *    overeager / intent-mismatched action). It can never turn a `deny` or an
 *    explicit `hard-ask` into `allow`, and on any provider error it fails closed.
 */
import type { ClassifierProvider, ContextInput, ActionInput } from "./provider"

export type Decision = "allow" | "soft-ask" | "hard-ask" | "deny"

export interface RiskSignal {
  sawSuspiciousContent: boolean
  categories: string[]
  source: ContextInput["source"]
}

/** Context Checker: scan untrusted input, emit a signal. NEVER blocks. Fail-open (a missed signal
 *  just leaves the deterministic layer in charge — it cannot make anything less safe). */
export async function runContextChecker(provider: ClassifierProvider, input: ContextInput): Promise<RiskSignal> {
  try {
    const v = await provider.checkContext(input)
    return { sawSuspiciousContent: v.suspicious, categories: v.categories, source: input.source }
  } catch {
    return { sawSuspiciousContent: false, categories: [], source: input.source }
  }
}

/**
 * The escalation rule that turns a Context-Checker signal into stricter enforcement.
 * This is deterministic: once suspicious content has been seen in the session, an
 * outbound / secret-touching action that the engine would otherwise ALLOW is raised
 * to at least a hard-ask. Applied only to actions that actually leave the machine or
 * read a secret, so routine work is unaffected.
 */
export function escalateWithContext(det: Decision, action: string, signal: { sawSuspiciousContent: boolean }): Decision {
  if (!signal.sawSuspiciousContent) return det
  const outboundOrSecret = /(curl|wget|post|upload|send|http|\.ssh|\.aws|\.env|credential|secret|token)/i.test(action)
  if (!outboundOrSecret) return det
  // Never relax; only tighten. allow/soft-ask -> hard-ask; deny/hard-ask stay.
  if (det === "allow" || det === "soft-ask") return "hard-ask"
  return det
}

export interface ActionAdjustment {
  decision: Decision
  reason: "immutable" | "not-ambiguous" | "intent-match" | "intent-mismatch" | "fail-closed"
}

/** Action Classifier: only touches `soft-ask`. Enforces the asymmetry in code. */
export async function adjustDecision(
  provider: ClassifierProvider,
  deterministic: Decision,
  input: ActionInput,
): Promise<ActionAdjustment> {
  // INVARIANT: deterministic DENY / explicit hard-ASK are immutable.
  if (deterministic === "deny" || deterministic === "hard-ask") return { decision: deterministic, reason: "immutable" }
  // The classifier is deliberately NOT invoked on plain ALLOW (that is the fast path).
  if (deterministic !== "soft-ask") return { decision: deterministic, reason: "not-ambiguous" }

  try {
    const v = await provider.classifyAction(input)
    if (v.matchesIntent && v.confidence >= 0.7) return { decision: "allow", reason: "intent-match" } // less friction
    return { decision: "deny", reason: "intent-mismatch" } // catch overeager
  } catch {
    // INVARIANT: any error keeps the human-in-the-loop decision. Never opens up.
    return { decision: "soft-ask", reason: "fail-closed" }
  }
}
