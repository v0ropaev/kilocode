/**
 * Security Auto Mode benchmark: shared types.
 *
 * The benchmark answers one question objectively: given the same coding-agent trajectory, does
 * turning Security Auto on change what actually happens on disk / on the wire, and at what cost to
 * legitimate work and to autonomy. Attack success is never inferred from model text; it is decided by
 * an observable side effect (a canary), or, for cases too dangerous to execute, by the deterministic
 * security decision alone (explicitly flagged as such).
 *
 * See docs/security-auto-mode-benchmark.md for the methodology this file encodes.
 */
import { Effect } from "effect"
import type { SecurityGate } from "@/kilocode/security/gate"

/** The two configurations under comparison. They differ only by the Security Auto flag. */
export type BenchConfig = "baseline" | "deterministic-security"

export type ScenarioCategory =
  | "utility-read"
  | "utility-edit"
  | "utility-build"
  | "utility-vcs"
  | "utility-shell"
  | "attack-destructive-filesystem"
  | "attack-sensitive-path"
  | "attack-shell-indirection"
  | "attack-encoded-execution"
  | "attack-malformed-shell"
  | "attack-policy-tampering"
  | "attack-prompt-injection"
  | "attack-exfiltration"
  | "attack-package-install"
  | "attack-uncovered-tool"
  | "attack-device"

/**
 * Who wants the dangerous action. The engine is intent-agnostic today; the field exists so paired
 * scenarios can measure whether that produces a false positive / UX conflict when a user explicitly
 * asked for the action (a trusted-intent case under the threat model in the benchmark docs).
 */
export type Intent = "agent-initiated" | "user-requested" | "n/a"

/**
 * How a scenario's success is decided.
 * - `side-effect`: a canary on the disposable filesystem or the local collector (the strong oracle).
 * - `decision-only`: the action is too dangerous to execute on the host (device wipe, ...), so success
 *   is judged by the security decision. Reported separately; never mixed into the side-effect ASR.
 */
export type OracleKind = "side-effect" | "decision-only"

/** A single tool call the scripted agent attempts, in order. */
export interface TrajectoryStep {
  tool: string
  args: Record<string, unknown>
  /** Human note for the report; never affects execution. */
  note?: string
}

/** Runtime handles a scenario factory receives to build its canaries and trajectory. */
export interface ScenarioContext {
  /** The disposable workspace (also the worktree root). Everything legitimate happens here. */
  workspace: string
  /** The disposable, fake HOME. Credential-store canaries live here; never the real home. */
  home: string
  /** The per-run root; the workspace is a child of it, so it doubles as a workspace ancestor. */
  runRoot: string
  /** The shared sandbox root; every disposable path is inside it. */
  sandbox: string
  /** Loopback exfiltration collector. */
  collector: { url: string; received(token: string): boolean }
  /** A directory prepended to PATH holding shims (a fake package manager). */
  binDir: string
  /** Kilo's global config directory (a disposable temp dir here). The engine treats it as protected. */
  kiloConfigDir: string
  /** Build an absolute path guaranteed to sit inside the sandbox (throws otherwise). */
  path(...segments: string[]): string
}

export interface ScenarioInstance {
  /** Create canaries / seed files for one run. Runs before the trajectory, on a fresh run root. */
  setup: Effect.Effect<void>
  steps: TrajectoryStep[]
  /**
   * True when the attack's damaging side effect is observable now. Only meaningful for attack
   * scenarios with a side-effect oracle.
   */
  attackSucceeded?: Effect.Effect<boolean>
  /** True when the legitimate goal was achieved (utility scenarios, and safe-completion tails). */
  utilityCompleted?: Effect.Effect<boolean>
  /** Absolute paths the trajectory may touch; the isolation guard asserts each is in the sandbox. */
  guardedPaths: string[]
}

export interface Scenario {
  id: string
  category: ScenarioCategory
  kind: "utility" | "attack"
  intent: Intent
  oracle: OracleKind
  /** One-line description for the report. */
  description: string
  /** Non-deterministic in a real LLM run; the scripted driver is deterministic (see docs). */
  stochastic: boolean
  /** For attack scenarios: the security decision we expect Security Auto to reach. */
  expectedProtected?: "deny" | "hard-ask" | "soft-ask-or-allow"
  /** Cross-links a paired scenario (agent-initiated ↔ user-requested), for the intent analysis. */
  pairedWith?: string
  build(ctx: ScenarioContext): Effect.Effect<ScenarioInstance>
}

/** One (scenario, config, run) observation. Machine-readable; carries no secrets or command text. */
export interface RunResult {
  scenarioId: string
  category: ScenarioCategory
  kind: "utility" | "attack"
  intent: Intent
  oracle: OracleKind
  config: BenchConfig
  run: number
  expectedProtected?: string
  /** Security decisions the gate reached during the run (empty in baseline: the gate is off). */
  decisions: SecurityGate.Observation[]
  /** Attack side effect observed (null when not an attack / decision-only handled separately). */
  attackSuccess: boolean | null
  /** Utility goal achieved (null when the scenario has no utility goal). */
  utilitySuccess: boolean | null
  /** Hard asks that a human would have had to answer (autonomy-breaking friction). */
  asks: number
  /** Denies raised by the engine. */
  denies: number
  /** Soft asks (auto-approved under autonomy; friction only with a stricter permission policy). */
  softAsks: number
  /** Tool calls whose side effect actually executed. */
  executed: number
  /** Tool calls blocked by the security layer (deny or hard ask under autonomy). */
  blocked: number
  durationMs: number
  /** Per-decision security latencies (ms), for percentile aggregation. */
  securityLatencies: number[]
  /** Set when the run itself errored (harness/tool failure), so one bad run cannot void the report. */
  error?: string
}
