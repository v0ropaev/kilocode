import { BenchMetrics } from "./metrics"
import type { RunResult } from "./types"

/**
 * Serialisation of benchmark output. Two shapes:
 * - machine-readable JSONL, one {@link RunResult} per line, in a stable order;
 * - a human-readable Markdown summary with the headline table and per-category breakdown.
 * Neither contains secrets, file contents, or raw command text (only reason codes and rule ids).
 *
 * Ordering and every decision/outcome field are deterministic across reruns; the timing fields
 * (`durationMs`, `securityLatencies`) are wall-clock and vary, so two captures are not byte-identical —
 * diff on the decision/outcome fields, not the whole line, to detect behaviour changes.
 */
export namespace BenchReport {
  /** Deterministic ordering (by scenario, config, run) so reruns line up for diffing. */
  export function sortResults(results: RunResult[]): RunResult[] {
    return [...results].sort((a, b) => {
      if (a.scenarioId !== b.scenarioId) return a.scenarioId < b.scenarioId ? -1 : 1
      if (a.config !== b.config) return a.config < b.config ? -1 : 1
      return a.run - b.run
    })
  }

  export function toJsonl(results: RunResult[]): string {
    return sortResults(results)
      .map((result) => JSON.stringify(result))
      .join("\n")
  }

  function pct(rate: BenchMetrics.Rate): string {
    if (rate.rate === null) return "n/a"
    return `${(rate.rate * 100).toFixed(0)}% (${rate.successes}/${rate.total})`
  }

  function num(value: number | undefined, digits = 2): string {
    return value === undefined ? "n/a" : value.toFixed(digits)
  }

  function ms(value: number | undefined): string {
    return value === undefined ? "n/a" : `${value.toFixed(2)} ms`
  }

  export function toMarkdown(report: BenchMetrics.Report): string {
    const lines: string[] = []
    lines.push("# Security Auto Mode — Benchmark v1 results")
    lines.push("")
    lines.push(`Generated: ${report.generatedAt}`)
    lines.push("")
    lines.push(`Scenarios: ${report.scenarioCount} · runs per case: ${report.runsPerCase}`)
    lines.push("")

    lines.push("| Configuration | ASR | Utility | Safe DENY FP | Safe ASK FP | ASK/task | Security p95 |")
    lines.push("| --- | --: | --: | --: | --: | --: | --: |")
    for (const config of report.configs) {
      lines.push(
        `| ${config.config} | ${pct(config.asr)} | ${pct(config.utility)} | ${config.safeDenyFalsePositives} | ` +
          `${config.safeAskFalsePositives} | ${num(config.asksPerTask)} | ${ms(config.securityLatencyP95)} |`,
      )
    }
    lines.push("")

    lines.push("## Autonomy / friction / latency")
    lines.push("")
    lines.push("| Configuration | Safe completion | DENY/task | Security p50 | Task latency (mean) | Errored runs |")
    lines.push("| --- | --: | --: | --: | --: | --: |")
    for (const config of report.configs) {
      lines.push(
        `| ${config.config} | ${pct(config.safeCompletion)} | ${num(config.deniesPerTask)} | ` +
          `${ms(config.securityLatencyP50)} | ${ms(config.taskLatencyMean)} | ${config.errored} |`,
      )
    }
    lines.push("")

    lines.push("## Attack Success Rate by category (side-effect oracle)")
    lines.push("")
    lines.push("| Attack category | Baseline ASR | Security Auto ASR |")
    lines.push("| --- | --: | --: |")
    const baseline = report.configs.find((config) => config.config === "baseline")
    const protectedConfig = report.configs.find((config) => config.config === "deterministic-security")
    const categories = new Set<string>()
    for (const config of report.configs) for (const entry of config.byCategory) categories.add(entry.category)
    for (const category of [...categories].sort()) {
      const base = baseline?.byCategory.find((entry) => entry.category === category)
      const prot = protectedConfig?.byCategory.find((entry) => entry.category === category)
      lines.push(`| ${category} | ${base ? pct(base.asr) : "n/a"} | ${prot ? pct(prot.asr) : "n/a"} |`)
    }
    lines.push("")

    lines.push("## Decision-only attacks (too dangerous to execute)")
    lines.push("")
    lines.push("| Configuration | Blocked by engine |")
    lines.push("| --- | --: |")
    for (const config of report.configs) {
      const summary = config.decisionOnlyAttacks
      lines.push(`| ${config.config} | ${summary.total === 0 ? "n/a" : `${summary.blocked}/${summary.total}`} |`)
    }
    lines.push("")

    return lines.join("\n")
  }
}
