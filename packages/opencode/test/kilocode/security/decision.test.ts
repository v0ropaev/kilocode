import { describe, expect, test } from "bun:test"
import { Decision } from "../../../src/kilocode/security/decision"
import { SecurityEngine } from "../../../src/kilocode/security/engine"
import type { NormalizedAction, SecurityContext, SecurityEvidence } from "../../../src/kilocode/security/types"

const ctx: SecurityContext = {
  sessionID: "ses_test",
  agent: "build",
  workspace: { directory: "/tmp/ws", worktree: "/tmp/ws" },
  cwd: "/tmp/ws",
  home: "/tmp/home",
  sandbox: { enabled: false },
}

function item(
  action: SecurityEvidence["action"],
  source: SecurityEvidence["source"],
  rule = `${source}.${action}`,
): SecurityEvidence {
  return {
    rule,
    source,
    action,
    reasonCode:
      action === "deny" ? "DESTRUCTIVE_FILESYSTEM" : action === "ask" ? "UNKNOWN_SHELL_SYNTAX" : "SAFE_COMMAND",
    message: rule,
  }
}

const fallback = item("ask", "default", "engine.default")

describe("security decision reducer", () => {
  test("severity is monotonic: deny > ask > allow", () => {
    expect(Decision.stricter("allow", "ask")).toBe("ask")
    expect(Decision.stricter("ask", "allow")).toBe("ask")
    expect(Decision.stricter("ask", "deny")).toBe("deny")
    expect(Decision.stricter("deny", "allow")).toBe("deny")
    expect(Decision.stricter("allow", "allow")).toBe("allow")
  })

  test("DENY + ALLOW = DENY regardless of order", () => {
    expect(Decision.reduce([item("deny", "hard"), item("allow", "default")], fallback).action).toBe("deny")
    expect(Decision.reduce([item("allow", "default"), item("deny", "hard")], fallback).action).toBe("deny")
    expect(Decision.reduce([item("allow", "default"), item("deny", "hard")], fallback).hard).toBe(true)
  })

  test("ASK + ALLOW = ASK and a later allow never relaxes it", () => {
    const decision = Decision.reduce(
      [item("ask", "hard"), item("allow", "default"), item("allow", "default")],
      fallback,
    )
    expect(decision.action).toBe("ask")
    expect(decision.hard).toBe(true)
  })

  test("a soft ask stays soft, a hard ask makes the decision hard", () => {
    expect(Decision.reduce([item("ask", "default"), item("allow", "default")], fallback).hard).toBe(false)
    expect(Decision.reduce([item("ask", "default"), item("ask", "hard")], fallback).hard).toBe(true)
  })

  test("deny is always hard and cannot be retried as-is", () => {
    const decision = Decision.reduce([item("deny", "hard")], fallback)
    expect(decision.hard).toBe(true)
    expect(decision.canRetry).toBe(true)
    expect(decision.guidance.length).toBeGreaterThan(0)
  })

  test("no evidence falls back to the supplied ask, never to allow", () => {
    expect(Decision.reduce([], fallback).action).toBe("ask")
  })

  test("engine failure is a hard ask with a stable reason code", () => {
    const decision = Decision.failure(new TypeError("boom"))
    expect(decision.action).toBe("ask")
    expect(decision.hard).toBe(true)
    expect(decision.reasonCode).toBe("SECURITY_ENGINE_ERROR")
    expect(JSON.stringify(decision)).not.toContain("boom")
  })

  test("SecurityEngine never returns allow when the rules throw", () => {
    const broken = { kind: "shell", permission: "bash", command: undefined } as unknown as NormalizedAction
    const decision = SecurityEngine.evaluate(broken, ctx)
    expect(decision.action).toBe("ask")
    expect(decision.hard).toBe(true)
    expect(decision.reasonCode).toBe("SECURITY_ENGINE_ERROR")
  })

  test("unclassified permissions are a soft ask, not an allow", () => {
    const decision = SecurityEngine.evaluate(
      { kind: "permission", permission: "some_custom_tool", patterns: ["*"] },
      ctx,
    )
    expect(decision.action).toBe("ask")
    expect(decision.hard).toBe(false)
    expect(decision.reasonCode).toBe("UNCLASSIFIED_ACTION")
  })

  test("sandbox escalation is always a hard ask", () => {
    const decision = SecurityEngine.evaluate(
      { kind: "permission", permission: "sandbox_escalation", patterns: ["git commit"] },
      ctx,
    )
    expect(decision.action).toBe("ask")
    expect(decision.hard).toBe(true)
    expect(decision.reasonCode).toBe("SANDBOX_ESCALATION")
  })
})
