// kilocode_change - new file
//
// Security Auto Mode benchmark runner.
//
// Runs the same scripted coding-agent trajectories in the baseline (Security Auto OFF) and protected
// (Security Auto ON) configurations, in a disposable sandbox under the OS temp dir, and reports the
// measured Attack Success Rate, utility, friction, and security-decision latency.
//
// Isolation env is set BEFORE any Kilo import (Global reads XDG/KILO_TEST_HOME at import time), exactly
// like test/preload.ts. Destructive scenarios execute for real, but only inside the sandbox.
//
// Usage: bun run script/security-bench.ts [--runs N] [--scenario <id|prefix*|a,b,c>] [--out <dir>]
//        [--configs baseline,deterministic-security,package-security] [--tag <label>]
//
// The configurations form an ablation ladder (each adds one layer to the previous one); `--configs`
// selects a subset, e.g. the first three rungs of the ladder.

import os from "node:os"
import path from "node:path"
import fs from "node:fs/promises"
import { randomUUID } from "node:crypto"

function arg(name: string, fallback?: string): string | undefined {
  const index = process.argv.indexOf(`--${name}`)
  return index >= 0 && index + 1 < process.argv.length ? process.argv[index + 1] : fallback
}

const runsPerCase = Math.max(1, Number(arg("runs", "3")) || 3)
const scenarioFilter = arg("scenario")
const configsArg = arg("configs")
const tag = arg("tag")

// ---------------------------------------------------------------------------
// Isolation env — must run before importing anything from src/.
// ---------------------------------------------------------------------------
const base = path.join(os.tmpdir(), `kilo-sec-bench-${process.pid}-${randomUUID()}`)
const home = path.join(base, "home")
// Deliberately NOT named "sandbox"/"config"/"permission": the engine's KILO_ROUTES rule matches those
// substrings in any network-command argument, so a workspace path containing one would falsely trip
// hard.network.kilo-route. Keeping the root neutral avoids contaminating every network scenario.
const sandboxRoot = path.join(base, "arena")
await fs.mkdir(home, { recursive: true })
await fs.mkdir(sandboxRoot, { recursive: true })
await fs.mkdir(path.join(base, "cache", "kilo"), { recursive: true })
await fs.writeFile(path.join(base, "cache", "kilo", "version"), "21")

process.env.XDG_DATA_HOME = path.join(base, "share")
process.env.XDG_CACHE_HOME = path.join(base, "cache")
process.env.XDG_CONFIG_HOME = path.join(base, "config")
process.env.XDG_STATE_HOME = path.join(base, "state")
process.env.KILO_TEST_HOME = home
process.env.HOME = home
process.env.KILO_DB = ":memory:"
process.env.KILO_DISABLE_MODELS_FETCH = "1"
process.env.KILO_DISABLE_DEFAULT_PLUGINS = "true"
process.env.KILO_TELEMETRY_LEVEL = "off"
process.env.KILO_MODELS_PATH = path.join(import.meta.dir, "..", "test", "tool", "fixtures", "models-api.json")
process.env.KILO_EXPERIMENTAL_EVENT_SYSTEM = "true"
process.env.KILO_EXPERIMENTAL_WORKSPACES = "true"
process.env.KILO_EXPERIMENTAL_DISABLE_FILEWATCHER = "true"
// Never let the model shell inherit real provider credentials.
for (const key of Object.keys(process.env)) {
  if (/_API_KEY$|^AWS_|^ANTHROPIC|^OPENAI|^OPENROUTER/.test(key)) delete process.env[key]
}
// Critical for a fair comparison: SecurityFlag.enabled reads KILO_SECURITY_AUTO *before* the config
// flag, so a stray env var would force baseline and protected identical. Scrub it (the harness also
// clears it per run) so the config layer is the only thing that toggles the engine.
delete process.env.KILO_SECURITY_AUTO

// ---------------------------------------------------------------------------
// Now it is safe to import Kilo + the harness.
// ---------------------------------------------------------------------------
const { Effect } = await import("effect")
const { Global } = await import("@opencode-ai/core/global")
const { BenchHarness } = await import("@/kilocode/security/bench/harness")
const { BenchScenarios } = await import("@/kilocode/security/bench/scenarios")
const { BenchMetrics } = await import("@/kilocode/security/bench/metrics")
const { BenchReport } = await import("@/kilocode/security/bench/report")
const { BenchCollector } = await import("@/kilocode/security/bench/collector")
const { BenchIsolation } = await import("@/kilocode/security/bench/isolation")

// Fail closed: if the isolation env did not take, do not run destructive scenarios.
if (Global.Path.home !== home) {
  throw new Error(`fake HOME did not take: Global.Path.home=${Global.Path.home}, expected ${home}`)
}

const sandbox = await BenchIsolation.create({
  root: sandboxRoot,
  home,
  extraRoots: [Global.Path.config],
})
const collector = await BenchCollector.start()

const { BENCH_CONFIGS } = await import("@/kilocode/security/bench/types")

// `--scenario atk-package-*` selects by prefix; an exact id selects one scenario; several
// comma-separated patterns select their union.
const patterns =
  scenarioFilter
    ?.split(",")
    .map((item) => item.trim())
    .filter(Boolean) ?? []
const scenarios = BenchScenarios.all().filter((scenario) => {
  if (patterns.length === 0) return true
  return patterns.some((pattern) =>
    pattern.endsWith("*") ? scenario.id.startsWith(pattern.slice(0, -1)) : scenario.id === pattern,
  )
})
if (scenarios.length === 0) throw new Error(`no scenarios matched --scenario ${scenarioFilter}`)
const configs = (configsArg ? configsArg.split(",") : [...BENCH_CONFIGS]).map((name) => {
  const found = BENCH_CONFIGS.find((config) => config === name.trim())
  if (!found) throw new Error(`unknown config ${name}; expected one of ${BENCH_CONFIGS.join(", ")}`)
  return found
})

// eslint-disable-next-line no-console
console.error(
  `running ${scenarios.length} scenarios × ${runsPerCase} runs × ${configs.length} configs = ${scenarios.length * runsPerCase * configs.length} runs`,
)

const results = await Effect.runPromise(BenchHarness.runAll({ scenarios, runsPerCase, sandbox, collector, configs }))

const report = BenchMetrics.aggregate({
  results,
  runsPerCase,
  scenarioCount: scenarios.length,
  generatedAt: new Date().toISOString(),
  configs,
})
const advisory = [...BenchHarness.classifierStats().entries()].filter(([, stats]) => stats.calls > 0)
const advisorySection = advisory.length
  ? [
      "",
      "## LLM advisory cost (opt-in layer)",
      "",
      "| Configuration | Model calls | Calls per attack step | Flagged | Errors | Timeouts | Advisory p50 | Advisory p95 |",
      "| --- | --: | --: | --: | --: | --: | --: | --: |",
      ...advisory.map(([config, stats]) => {
        const sorted = [...stats.latencies].sort((a, b) => a - b)
        const q = (p: number) =>
          sorted.length ? sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))]! : 0
        const decisions = results.filter((r) => r.config === config).reduce((n, r) => n + r.decisions.length, 0)
        const rate = decisions > 0 ? (stats.calls / decisions).toFixed(2) : "n/a"
        return `| ${config} | ${stats.calls} | ${rate} | ${stats.risky} | ${stats.errors} | ${stats.timeouts} | ${q(50).toFixed(2)} ms | ${q(95).toFixed(2)} ms |`
      }),
      "",
      `_Provider: ${process.env["KILO_SECURITY_AUTO_CLASSIFIER_PROVIDER"] ?? "heuristic"}._`,
    ].join("\n")
  : ""

const markdown = BenchReport.toMarkdown(report) + advisorySection
const jsonl = BenchReport.toJsonl(results)

const outDir = arg("out", path.join(import.meta.dir, "..", ".artifacts", "security-bench", tag ?? "latest"))!
await fs.mkdir(outDir, { recursive: true })
await fs.writeFile(path.join(outDir, "results.jsonl"), jsonl + "\n")
await fs.writeFile(path.join(outDir, "summary.json"), JSON.stringify(report, null, 2) + "\n")
await fs.writeFile(path.join(outDir, "summary.md"), markdown + "\n")

// eslint-disable-next-line no-console
console.log(markdown)
const errored = results.filter((result) => result.error !== undefined)
if (errored.length > 0) {
  // eslint-disable-next-line no-console
  console.error(`\n⚠ ${errored.length}/${results.length} runs errored (excluded from rates):`)
  for (const result of errored.slice(0, 10)) {
    // eslint-disable-next-line no-console
    console.error(`  - ${result.scenarioId} [${result.config}]: ${result.error}`)
  }
}
// eslint-disable-next-line no-console
console.error(`\nartifacts written to ${outDir}`)

await collector.close()
await sandbox.dispose()
await fs.rm(base, { recursive: true, force: true }).catch(() => {})

const { AppRuntime } = await import("@/effect/app-runtime")
await AppRuntime.dispose().catch(() => {})
process.exit(0)
