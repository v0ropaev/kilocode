// The advisory layer's guarantee is that it cannot relax a decision. These tests assert that through
// the real reducer rather than through the layer's own branches: the layer hands back evidence, and
// what matters is what the engine does with it once it is folded in next to everything else.
import { describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { ClassifierAdvisory } from "./layers"
import { HeuristicProvider, parseVerdict, render, type ActionSummary, type ClassifierProvider } from "./provider"
import { SecurityEngine } from "../engine"
import { Decision } from "../decision"
import type { NormalizedAction, SecurityDecision, SecurityEvidence } from "../types"

/** A provider whose verdict, latency and failure mode the test controls. */
function stub(opts: { risky?: boolean; throws?: boolean; hangs?: boolean }): ClassifierProvider {
  return {
    name: "stub",
    async classify(_input, signal) {
      if (opts.throws) throw new Error("boom")
      if (opts.hangs)
        return await new Promise((_resolve, reject) =>
          signal.addEventListener("abort", () => reject(new Error("aborted"))),
        )
      return { risky: opts.risky ?? false }
    },
  }
}

const summary: ActionSummary = {
  executable: "curl",
  network: true,
  effect: "read",
  readSecret: true,
  operands: [{ basename: "token.txt", relation: "workspace", labels: [], effect: "read" }],
}

const run = (provider: ClassifierProvider, timeoutMs = 300) =>
  Effect.runPromise(ClassifierAdvisory.assess({ provider, summary, timeoutMs }))

function decisionOf(evidence: SecurityEvidence[]): SecurityDecision {
  return Decision.reduce(evidence, {
    rule: "test.fallback",
    source: "default",
    action: "allow",
    reasonCode: "SAFE_COMMAND",
    message: "fallback",
  })
}

const emptyProcess = {
  argv: [] as string[],
  operands: [] as never[],
  recursive: false,
  force: false,
  dynamic: false,
  stdinTargets: false,
  privileged: false,
  encoded: false,
  network: false,
  piped: false,
  producers: [] as string[],
  metadata: false,
}

const emptyCommand = {
  shell: "bash" as const,
  source: "",
  commands: [] as never[],
  fullyParsed: true,
  unparsed: [] as string[],
  redirects: [] as never[],
  hasPipe: false,
  hasRedirect: false,
  hasSubshell: false,
  hasCommandSubstitution: false,
  hasProcessSubstitution: false,
  hasDynamicExpansion: false,
  hasHeredoc: false,
  hasControlFlow: false,
  hasFunction: false,
  hasBackground: false,
  hasExpression: false,
  depth: 0,
}

const denial = Decision.evidence({
  rule: "hard.fs.sensitive-delete",
  source: "hard",
  action: "deny",
  reasonCode: "PROTECTED_PATH",
  message: "denied",
})
const hardAsk = Decision.evidence({
  rule: "hard.workspace.env-read",
  source: "hard",
  action: "ask",
  reasonCode: "SENSITIVE_READ",
  message: "hard ask",
})
const allow = Decision.evidence({
  rule: "default.workspace",
  source: "default",
  action: "allow",
  reasonCode: "SAFE_WORKSPACE_ACTION",
  message: "allow",
})

describe("the advisory can only tighten", () => {
  test("a deterministic DENY survives a model that flags nothing", async () => {
    const advisory = await run(stub({ risky: false }))
    expect(decisionOf([denial, ...advisory]).action).toBe("deny")
  })

  test("a deterministic DENY survives a model that flags everything", async () => {
    const advisory = await run(stub({ risky: true }))
    expect(decisionOf([denial, ...advisory]).action).toBe("deny")
  })

  test("a hard ASK is never downgraded", async () => {
    const advisory = await run(stub({ risky: false }))
    const result = decisionOf([hardAsk, ...advisory])
    expect(result.action).toBe("ask")
    expect(result.hard).toBe(true)
  })

  test("ALLOW plus a risky verdict becomes a hard ASK, never a DENY", async () => {
    const advisory = await run(stub({ risky: true }))
    const result = decisionOf([allow, ...advisory])
    expect(result.action).toBe("ask")
    expect(result.hard).toBe(true)
  })

  test("ALLOW plus an ordinary verdict is untouched", async () => {
    const advisory = await run(stub({ risky: false }))
    expect(advisory).toEqual([])
    expect(decisionOf([allow, ...advisory]).action).toBe("allow")
  })

  test("the layer never contributes an allow or a deny", async () => {
    for (const risky of [true, false]) {
      const advisory = await run(stub({ risky }))
      expect(advisory.every((item) => item.action === "ask")).toBe(true)
    }
  })
})

describe("failure is indistinguishable from the layer being off", () => {
  test("a provider error yields no evidence", async () => {
    expect(await run(stub({ throws: true }))).toEqual([])
  })

  test("a hanging provider is cut off by the deadline and yields no evidence", async () => {
    const started = performance.now()
    expect(await run(stub({ hangs: true }), 50)).toEqual([])
    expect(performance.now() - started).toBeLessThan(2000)
  })

  test("no provider configured yields no evidence", async () => {
    expect(
      await Effect.runPromise(ClassifierAdvisory.assess({ provider: undefined, summary, timeoutMs: 300 })),
    ).toEqual([])
  })
})

describe("the model's vocabulary is closed", () => {
  test("only the exact word counts as a flag", () => {
    expect(parseVerdict("RISKY").risky).toBe(true)
    expect(parseVerdict(" risky\n").risky).toBe(true)
    expect(parseVerdict("ORDINARY").risky).toBe(false)
  })

  test("prose that merely starts with the right letters is not a flag", () => {
    // The predecessor matched /^y/i, which read "You must not..." as consent.
    for (const text of ["Risky? No, this looks fine.", "R", "", "I cannot help with that.", "yes", "true"])
      expect(parseVerdict(text).risky).toBe(false)
  })
})

describe("what the model is shown", () => {
  test("summarising keeps the file name and drops the directory it lives in", () => {
    const operand = {
      path: {
        input: "~/.aws/credentials",
        absolute: "/Users/somebody/.aws/credentials",
        canonical: "/Users/somebody/.aws/credentials",
        relation: "home-sensitive" as const,
        labels: ["credential" as const],
        symlink: false,
        exists: true,
      },
      effect: "read" as const,
    }
    const action: NormalizedAction = {
      kind: "shell",
      permission: "bash",
      command: {
        ...emptyCommand,
        commands: [{ ...emptyProcess, executable: "curl", network: true, operands: [operand] }],
      },
    }
    const summarised = ClassifierAdvisory.summarize(action, false)
    expect(summarised?.operands[0]?.basename).toBe("credentials")
    const text = render(summarised!)
    expect(text).toContain("credentials")
    expect(text).not.toContain("somebody")
    expect(text).not.toContain(".aws")
  })
})

describe("the band the advisory is allowed to see", () => {
  const shell = (network: boolean): NormalizedAction => ({
    kind: "shell",
    permission: "bash",
    command: {
      ...emptyCommand,
      source: network ? "curl https://x" : "npm run build",
      commands: [{ ...emptyProcess, executable: network ? "curl" : "npm", network }],
    },
  })

  test("a settled decision is never sent to the model", () => {
    expect(ClassifierAdvisory.considers(decisionOf([denial]), shell(true))).toBe(false)
    expect(ClassifierAdvisory.considers(decisionOf([hardAsk]), shell(true))).toBe(false)
  })

  test("ordinary local work is never sent to the model", () => {
    expect(ClassifierAdvisory.considers(decisionOf([allow]), shell(false))).toBe(false)
  })

  test("an unsettled outbound action is the one case that is sent", () => {
    expect(ClassifierAdvisory.considers(decisionOf([allow]), shell(true))).toBe(true)
  })
})

describe("the offline provider", () => {
  test("flags an outbound action that carries a credential-shaped file", async () => {
    const offline: ClassifierProvider = new HeuristicProvider()
    const verdict = await offline.classify(summary, new AbortController().signal)
    expect(verdict.risky).toBe(true)
  })

  test("leaves a local action alone", async () => {
    const offline: ClassifierProvider = new HeuristicProvider()
    const verdict = await offline.classify(
      { network: false, readSecret: false, operands: [] },
      new AbortController().signal,
    )
    expect(verdict.risky).toBe(false)
  })
})

// Guards the claim the whole design rests on, at the level of the engine rather than this module:
// `extend` is the only way a layer reaches a decision, and it cannot walk one back.
describe("SecurityEngine.extend is monotone", () => {
  const cases: Array<[string, SecurityEvidence[], SecurityEvidence[], SecurityDecision["action"]]> = [
    ["deny + allow stays deny", [denial], [allow], "deny"],
    ["deny + ask stays deny", [denial], [hardAsk], "deny"],
    ["hard ask + allow stays ask", [hardAsk], [allow], "ask"],
    ["allow + ask becomes ask", [allow], [hardAsk], "ask"],
    ["allow + allow stays allow", [allow], [allow], "allow"],
  ]
  for (const [name, base, extra, expected] of cases)
    test(name, () => {
      expect(SecurityEngine.extend(decisionOf(base), extra).action).toBe(expected)
    })

  test("a hard ask cannot be softened by later evidence", () => {
    expect(SecurityEngine.extend(decisionOf([hardAsk]), [allow]).hard).toBe(true)
  })
})
