#!/usr/bin/env bun
// kilocode_change - new file
/**
 * Scores the semantic security layer against the development and held-out corpora.
 *
 * Offline, no key, no network (the default `heuristic` stand-in):
 *
 *   bun run script/security-semantic-eval.ts
 *
 * Against the model Kilo is already configured with — this is the real-model run:
 *
 *   KILO_SECURITY_AUTO_CLASSIFIER_PROVIDER=kilo bun run script/security-semantic-eval.ts
 *
 * Against a local OpenAI-compatible server (Ollama, LM Studio, llama.cpp), no key needed:
 *
 *   KILO_SECURITY_AUTO_CLASSIFIER_PROVIDER=openai \
 *   KILO_SECURITY_AUTO_CLASSIFIER_URL=http://localhost:11434/v1 \
 *   KILO_SECURITY_AUTO_CLASSIFIER_MODEL=qwen2.5:3b \
 *   bun run script/security-semantic-eval.ts
 *
 * Against a hosted small model:
 *
 *   KILO_SECURITY_AUTO_CLASSIFIER_PROVIDER=anthropic \
 *   KILO_SECURITY_AUTO_CLASSIFIER_KEY=... \
 *   bun run script/security-semantic-eval.ts
 *
 * Flags: `--sensitivity conservative|balanced|both` (default both), `--json`, `--repeat N`.
 *
 * What is scored is the *layer*, not the raw model: each case runs through the real provider and the
 * real `policy()` mapping, so a verdict the policy would ignore counts as no escalation.
 */
import { HeuristicProvider, providerFromEnv } from "@/kilocode/security/classifier/provider"
import { SemanticEvidence } from "@/kilocode/security/classifier/layers"
import { DEVELOPMENT, HELD_OUT } from "@/kilocode/security/classifier/eval/corpus"
import { byGroup, score } from "@/kilocode/security/classifier/eval/run"

const argv = process.argv.slice(2)
const flag = (name: string, fallback?: string) => {
  const index = argv.indexOf(`--${name}`)
  return index >= 0 ? (argv[index + 1] ?? fallback) : fallback
}
const asJson = argv.includes("--json")
const repeat = Number(flag("repeat", "1")) || 1
const requested = flag("sensitivity", "both")!
const ALL_MODES: SemanticEvidence.Sensitivity[] = ["conservative", "balanced"]
const modes = requested === "both" ? ALL_MODES : ALL_MODES.filter((mode) => mode === requested)
if (modes.length === 0) throw new Error(`--sensitivity expects conservative, balanced or both`)

// Offline by default, like the benchmark: a scored run must be reproducible with no key and no
// network. The product's default provider is the model the user configured, and with none reachable
// it correctly contributes nothing — which would print as a page of zeroes and read like a result.
process.env["KILO_SECURITY_AUTO_CLASSIFIER_PROVIDER"] ??= "heuristic"
const provider = providerFromEnv() ?? new HeuristicProvider()
const sets = { development: DEVELOPMENT, "held-out": HELD_OUT } as const
const pct = (value: number) => `${Math.round(value * 100)}%`

interface Row {
  set: string
  mode: string
  cases: number
  recall: number
  precision: number
  falseEscalation: number
  latencyP50: number
  latencyP95: number
  misses: string[]
  falseAlarms: string[]
  groups: Record<string, string>
}

const rows: Row[] = []

for (const mode of modes) {
  for (const [name, cases] of Object.entries(sets)) {
    const latencies: number[] = []
    const measure = async () => {
      const started = performance.now()
      const result = await score(provider, cases, mode)
      latencies.push((performance.now() - started) / cases.length)
      return result
    }
    let scored = await measure()
    for (let attempt = 1; attempt < repeat; attempt++) scored = await measure()
    const sorted = [...latencies].sort((a, b) => a - b)
    const quantile = (p: number) => sorted[Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length))] ?? 0
    rows.push({
      set: name,
      mode,
      cases: scored.total,
      recall: scored.recall,
      precision: scored.precision,
      falseEscalation: scored.falseEscalation,
      latencyP50: quantile(50),
      latencyP95: quantile(95),
      misses: scored.outcomes.filter((item) => item.expected === "escalate" && !item.escalated).map((item) => item.id),
      falseAlarms: scored.outcomes.filter((item) => item.expected === "quiet" && item.escalated).map((item) => item.id),
      groups: Object.fromEntries(
        [...byGroup(scored).entries()]
          .sort((a, b) => a[0].localeCompare(b[0]))
          .map(([group, entry]) => [group, `${entry.caught}/${entry.total}`]),
      ),
    })
  }
}

if (asJson) {
  // eslint-disable-next-line no-console
  console.log(JSON.stringify({ provider: provider.name, repeat, rows }, null, 2))
} else {
  const out: string[] = []
  out.push(`# Semantic layer eval — provider: ${provider.name}`)
  out.push("")
  out.push("| Set | Policy | Cases | Recall | Precision | False escalation | Mean latency per case |")
  out.push("|---|---|---:|---:|---:|---:|---:|")
  for (const row of rows)
    out.push(
      `| ${row.set} | ${row.mode} | ${row.cases} | ${pct(row.recall)} | ${pct(row.precision)} | ${pct(row.falseEscalation)} | ${row.latencyP50.toFixed(1)} ms |`,
    )
  for (const row of rows) {
    out.push("")
    out.push(`## ${row.set} [${row.mode}]`)
    out.push(
      Object.entries(row.groups)
        .map(([group, value]) => `  ${group.padEnd(20)} ${value}`)
        .join("\n"),
    )
    if (row.misses.length) out.push(`  missed: ${row.misses.join(", ")}`)
    if (row.falseAlarms.length) out.push(`  false alarms: ${row.falseAlarms.join(", ")}`)
  }
  // eslint-disable-next-line no-console
  console.log(out.join("\n"))
}
