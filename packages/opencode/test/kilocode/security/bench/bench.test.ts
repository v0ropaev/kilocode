// Tests for the Security Auto Mode benchmark harness itself. The benchmark measures the security
// layer; these tests measure the benchmark — proving the oracle detects real damage, a blocked
// attack is never scored as a success, a successful attack really changed observable state, utility
// is judged by state (not model text), baseline and protected are not swapped, repeated runs
// aggregate, the metric maths is right, fake secrets are fake, destructive scenarios cannot escape
// the sandbox, one bad scenario cannot void the report, and results serialise reproducibly.
import os from "node:os"
import path from "node:path"
import fs from "node:fs/promises"
import { existsSync } from "node:fs"
import { randomUUID } from "node:crypto"
import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import { Effect } from "effect"
import { Global } from "@opencode-ai/core/global"
import { BenchHarness } from "@/kilocode/security/bench/harness"
import { BenchScenarios } from "@/kilocode/security/bench/scenarios"
import { BenchMetrics } from "@/kilocode/security/bench/metrics"
import { BenchReport } from "@/kilocode/security/bench/report"
import { BenchIsolation } from "@/kilocode/security/bench/isolation"
import { BenchCollector } from "@/kilocode/security/bench/collector"
import type { RunResult, Scenario } from "@/kilocode/security/bench/types"

// ---------------------------------------------------------------------------
// Pure unit tests (no harness) — fast, deterministic.
// ---------------------------------------------------------------------------

describe("fake secrets", () => {
  test("every declared secret is unmistakably fake", () => {
    expect(() => BenchScenarios.validateFakeSecrets()).not.toThrow()
    for (const value of Object.values(BenchScenarios.FAKE_SECRETS)) {
      const upper = value.toUpperCase()
      expect(upper.includes("BENCH") && upper.includes("FAKE")).toBe(true)
    }
  })
})

describe("metric calculations", () => {
  function result(overrides: Partial<RunResult>): RunResult {
    return {
      scenarioId: "s",
      category: "attack-sensitive-path",
      kind: "attack",
      intent: "agent-initiated",
      oracle: "side-effect",
      config: "deterministic-security",
      run: 1,
      decisions: [],
      attackSuccess: false,
      utilitySuccess: null,
      asks: 0,
      denies: 0,
      softAsks: 0,
      executed: 0,
      blocked: 0,
      durationMs: 1,
      securityLatencies: [],
      ...overrides,
    }
  }

  test("ASR and utility are successes/total, errored runs excluded", () => {
    const report = BenchMetrics.aggregate({
      generatedAt: "t",
      runsPerCase: 1,
      scenarioCount: 4,
      results: [
        result({ config: "baseline", kind: "attack", attackSuccess: true }),
        result({ config: "baseline", kind: "attack", attackSuccess: false }),
        result({ config: "baseline", kind: "utility", attackSuccess: null, utilitySuccess: true }),
        result({ config: "baseline", kind: "attack", attackSuccess: true, error: "boom" }),
      ],
    })
    const baseline = report.configs.find((c) => c.config === "baseline")!
    // Two valid attack runs (one true, one false); the errored one is excluded.
    expect(baseline.asr).toEqual({ rate: 0.5, successes: 1, total: 2 })
    expect(baseline.utility).toEqual({ rate: 1, successes: 1, total: 1 })
    expect(baseline.errored).toBe(1)
  })

  test("a rate over zero cases is null, never a misleading 0", () => {
    const report = BenchMetrics.aggregate({ generatedAt: "t", runsPerCase: 1, scenarioCount: 0, results: [] })
    expect(report.configs.find((c) => c.config === "baseline")!.asr.rate).toBeNull()
  })

  test("percentiles use nearest-rank on the sorted sample", () => {
    expect(BenchMetrics.percentile([10, 20, 30, 40], 50)).toBe(20)
    expect(BenchMetrics.percentile([10, 20, 30, 40], 95)).toBe(40)
    expect(BenchMetrics.percentile([], 50)).toBeUndefined()
  })

  test("safe DENY vs safe ASK false positives are counted separately", () => {
    const report = BenchMetrics.aggregate({
      generatedAt: "t",
      runsPerCase: 1,
      scenarioCount: 2,
      results: [
        result({ config: "deterministic-security", kind: "utility", utilitySuccess: true, denies: 1 }),
        result({ config: "deterministic-security", kind: "utility", utilitySuccess: true, asks: 2 }),
      ],
    })
    const protectedConfig = report.configs.find((c) => c.config === "deterministic-security")!
    expect(protectedConfig.safeDenyFalsePositives).toBe(1)
    expect(protectedConfig.safeAskFalsePositives).toBe(2)
  })
})

describe("result serialisation", () => {
  test("JSONL is machine-readable and order-stable", () => {
    const base = {
      category: "attack-sensitive-path" as const,
      kind: "attack" as const,
      intent: "agent-initiated" as const,
      oracle: "side-effect" as const,
      decisions: [],
      attackSuccess: false,
      utilitySuccess: null,
      asks: 0,
      denies: 0,
      softAsks: 0,
      executed: 0,
      blocked: 0,
      durationMs: 1,
      securityLatencies: [],
    }
    const results: RunResult[] = [
      { ...base, scenarioId: "b", config: "deterministic-security", run: 1 },
      { ...base, scenarioId: "a", config: "baseline", run: 2 },
      { ...base, scenarioId: "a", config: "baseline", run: 1 },
    ]
    const first = BenchReport.toJsonl(results)
    const again = BenchReport.toJsonl([...results].reverse())
    expect(first).toBe(again) // stable regardless of input order
    const lines = first.split("\n").map((line) => JSON.parse(line))
    expect(lines.map((r) => `${r.scenarioId}:${r.config}:${r.run}`)).toEqual([
      "a:baseline:1",
      "a:baseline:2",
      "b:deterministic-security:1",
    ])
  })
})

describe("isolation guard", () => {
  test("resolve() rejects a path that escapes the sandbox root", async () => {
    const root = path.join(os.tmpdir(), `bench-iso-${randomUUID()}`)
    const home = path.join(root, "home")
    const sandbox = await BenchIsolation.create({ root, home })
    try {
      expect(() => sandbox.resolve("../escape")).toThrow(/escapes the sandbox/)
      expect(() => sandbox.assertInside("/etc/passwd")).toThrow(/escapes the sandbox/)
      expect(() => sandbox.assertInside(os.homedir())).toThrow(/escapes the sandbox/)
      // A path inside the sandbox is accepted.
      expect(() => sandbox.assertInside(sandbox.resolve("workspace/file.txt"))).not.toThrow()
    } finally {
      await sandbox.dispose()
    }
  })

  test("a fake HOME outside the temp dir (incl. the real home) is refused", async () => {
    const root = path.join(os.tmpdir(), `bench-iso-${randomUUID()}`)
    // The real home is not under the temp root, so it is refused by the temp-containment guard —
    // the outer defence. (The explicit real-home check is unreachable belt-and-braces behind it.)
    await expect(BenchIsolation.create({ root, home: os.homedir() })).rejects.toThrow(
      /escapes the temp dir|real home/,
    )
  })

  test("every attack scenario only touches paths inside the sandbox", async () => {
    const root = path.join(os.tmpdir(), `bench-iso-${randomUUID()}`)
    const sandbox = await BenchIsolation.create({
      root,
      home: Global.Path.home,
      extraRoots: [Global.Path.config],
    })
    const collector = await BenchCollector.start()
    try {
      for (const scenario of BenchScenarios.all()) {
        const workspace = sandbox.resolve(`guardcheck-${scenario.id}`)
        await fs.mkdir(workspace, { recursive: true })
        const ctx = {
          workspace,
          home: Global.Path.home,
          runRoot: sandbox.resolve(`guardcheck-${scenario.id}`),
          sandbox: sandbox.root,
          binDir: sandbox.binDir,
          kiloConfigDir: Global.Path.config,
          collector: { url: collector.url, received: () => false },
          path: (...segments: string[]) => sandbox.resolve(...segments),
        }
        const instance = await Effect.runPromise(scenario.build(ctx))
        for (const guarded of instance.guardedPaths) {
          expect(() => sandbox.assertInside(guarded)).not.toThrow()
        }
      }
    } finally {
      await collector.close()
      await sandbox.dispose()
    }
  })
})

// ---------------------------------------------------------------------------
// Harness integration — drives the real security pipeline on a small scenario set.
// ---------------------------------------------------------------------------

describe("harness end-to-end", () => {
  let sandbox: BenchIsolation.Sandbox
  let collector: BenchCollector.Handle

  beforeAll(async () => {
    sandbox = await BenchIsolation.create({
      root: path.join(os.tmpdir(), `bench-e2e-${randomUUID()}`),
      home: Global.Path.home,
      extraRoots: [Global.Path.config],
    })
    collector = await BenchCollector.start()
  })

  afterAll(async () => {
    await collector.close()
    await sandbox.dispose()
  })

  const pick = (id: string) => BenchScenarios.all().find((s) => s.id === id)!

  // A scenario whose build fails, to prove one bad scenario cannot void the report.
  const boom: Scenario = {
    id: "boom",
    category: "attack-sensitive-path",
    kind: "attack",
    intent: "agent-initiated",
    oracle: "side-effect",
    stochastic: false,
    description: "always throws",
    build: () =>
      Effect.sync((): never => {
        throw new Error("intentional build failure")
      }),
  }

  test(
    "a stray KILO_SECURITY_AUTO env var cannot corrupt the baseline (the flag is scrubbed per run)",
    async () => {
      const previous = process.env.KILO_SECURITY_AUTO
      process.env.KILO_SECURITY_AUTO = "1" // would force the engine on for baseline too, if not scrubbed
      try {
        const results = await Effect.runPromise(
          BenchHarness.runSuite({
            scenarios: [pick("atk-ssh-write")],
            runsPerCase: 1,
            sandbox,
            collector,
            config: "baseline",
          }),
        )
        expect(results[0]!.error).toBeUndefined()
        // Baseline must still let the attack through — the env var did not silently enable the engine.
        expect(results[0]!.attackSuccess).toBe(true)
        expect(results[0]!.denies).toBe(0)
        expect(results[0]!.decisions).toHaveLength(0)
      } finally {
        if (previous === undefined) delete process.env.KILO_SECURITY_AUTO
        else process.env.KILO_SECURITY_AUTO = previous
      }
    },
    60_000,
  )

  test(
    "canary detects damage, blocks are not successes, baseline/protected are not swapped, repeats aggregate",
    async () => {
      const scenarios = [pick("atk-ssh-write"), pick("util-write"), boom]
      const results = await Effect.runPromise(
        BenchHarness.runAll({ scenarios, runsPerCase: 2, sandbox, collector }),
      )

      const get = (id: string, config: "baseline" | "deterministic-security") =>
        results.filter((r) => r.scenarioId === id && r.config === config)

      // Repeated runs aggregate: 3 scenarios × 2 configs × 2 runs = 12 results.
      expect(results.length).toBe(12)
      expect(get("atk-ssh-write", "baseline")).toHaveLength(2)

      // Successful attack really changed observable state (the canary was deleted).
      for (const r of get("atk-ssh-write", "baseline")) {
        expect(r.error).toBeUndefined()
        expect(r.attackSuccess).toBe(true)
        expect(r.executed).toBe(1)
      }
      // Blocked attack is never scored as a success, and the engine denied it.
      for (const r of get("atk-ssh-write", "deterministic-security")) {
        expect(r.error).toBeUndefined()
        expect(r.attackSuccess).toBe(false)
        expect(r.denies).toBeGreaterThan(0)
        expect(r.executed).toBe(0)
      }

      // Baseline/protected are not swapped: baseline makes no security decisions at all.
      for (const r of results.filter((x) => x.config === "baseline")) {
        expect(r.denies).toBe(0)
        expect(r.asks).toBe(0)
        expect(r.decisions).toHaveLength(0)
      }

      // Legitimate task completion is judged by observable state, and Security Auto does not break it.
      for (const r of get("util-write", "deterministic-security")) {
        expect(r.utilitySuccess).toBe(true)
        expect(r.error).toBeUndefined()
      }

      // One bad scenario errors but does not void the rest.
      for (const r of results.filter((x) => x.scenarioId === "boom")) {
        expect(r.error).toBeDefined()
      }
      expect(results.some((r) => r.scenarioId !== "boom" && r.error === undefined)).toBe(true)

      // The metrics exclude the errored boom runs from the rates.
      const report = BenchMetrics.aggregate({
        results,
        runsPerCase: 2,
        scenarioCount: scenarios.length,
        generatedAt: "t",
      })
      const baseline = report.configs.find((c) => c.config === "baseline")!
      const protectedConfig = report.configs.find((c) => c.config === "deterministic-security")!
      expect(baseline.asr.rate).toBeGreaterThan(protectedConfig.asr.rate!)
      expect(protectedConfig.utility.rate).toBe(1)
    },
    120_000,
  )
})
