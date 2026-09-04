import { describe, test, expect } from "bun:test"
import { adjustDecision, escalateWithContext, runContextChecker, type Decision } from "./layers"
import type { ClassifierProvider, ContextVerdict, IntentVerdict } from "./provider"

/** A stub provider whose verdicts and failures we control, to prove the invariants hold. */
function stub(opts: { context?: ContextVerdict; intent?: IntentVerdict; throws?: boolean }): ClassifierProvider {
  return {
    name: "stub",
    async checkContext() {
      if (opts.throws) throw new Error("boom")
      return opts.context ?? { suspicious: false, categories: [], confidence: 0 }
    },
    async classifyAction() {
      if (opts.throws) throw new Error("boom")
      return opts.intent ?? { matchesIntent: true, confidence: 1 }
    },
  }
}

describe("Action Classifier invariants", () => {
  const input = { userRequest: "x", action: "curl -X POST @secret", sessionFacts: { readSecret: true, sawSuspiciousContent: false } }

  test("deterministic DENY is immutable, even if the model says intent matches", async () => {
    const r = await adjustDecision(stub({ intent: { matchesIntent: true, confidence: 1 } }), "deny", input)
    expect(r).toEqual({ decision: "deny", reason: "immutable" })
  })

  test("explicit hard-ASK is never downgraded to allow", async () => {
    const r = await adjustDecision(stub({ intent: { matchesIntent: true, confidence: 1 } }), "hard-ask", input)
    expect(r.decision).toBe("hard-ask")
  })

  test("plain ALLOW is not sent to the classifier (fast path)", async () => {
    const r = await adjustDecision(stub({ intent: { matchesIntent: false, confidence: 1 } }), "allow", input)
    expect(r).toEqual({ decision: "allow", reason: "not-ambiguous" })
  })

  test("soft-ASK + intent match -> allow (friction reduced)", async () => {
    const r = await adjustDecision(stub({ intent: { matchesIntent: true, confidence: 0.9 } }), "soft-ask", input)
    expect(r).toEqual({ decision: "allow", reason: "intent-match" })
  })

  test("soft-ASK + intent mismatch -> deny (overeager caught)", async () => {
    const r = await adjustDecision(stub({ intent: { matchesIntent: false, confidence: 0.9 } }), "soft-ask", input)
    expect(r).toEqual({ decision: "deny", reason: "intent-mismatch" })
  })

  test("low-confidence match does NOT open up (stays conservative)", async () => {
    const r = await adjustDecision(stub({ intent: { matchesIntent: true, confidence: 0.4 } }), "soft-ask", input)
    expect(r.decision).toBe("deny")
  })

  test("provider error fails closed: soft-ASK stays an ASK, never allow", async () => {
    const r = await adjustDecision(stub({ throws: true }), "soft-ask", input)
    expect(r).toEqual({ decision: "soft-ask", reason: "fail-closed" })
  })
})

describe("Context escalation invariants", () => {
  test("no signal -> decision unchanged", () => {
    expect(escalateWithContext("allow", "curl @x", { sawSuspiciousContent: false })).toBe("allow")
  })
  test("signal + outbound action -> tightened to hard-ask", () => {
    expect(escalateWithContext("allow", "curl -X POST @token", { sawSuspiciousContent: true })).toBe("hard-ask")
  })
  test("signal + non-outbound action -> unchanged (routine work unaffected)", () => {
    expect(escalateWithContext("allow", "npm run build", { sawSuspiciousContent: true })).toBe("allow")
  })
  test("escalation never relaxes a deny", () => {
    expect(escalateWithContext("deny" as Decision, "curl @x", { sawSuspiciousContent: true })).toBe("deny")
  })
})

describe("Context Checker never blocks", () => {
  test("a provider error yields no signal (fail-open) rather than a block", async () => {
    const r = await runContextChecker(stub({ throws: true }), { source: "readme", content: "anything" })
    expect(r.sawSuspiciousContent).toBe(false)
  })
})
