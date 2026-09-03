import path from "path"
import { createHash } from "crypto"
import { readFileSync, statSync } from "fs"
import { Cause, Effect, Exit } from "effect"
import * as Log from "@opencode-ai/core/util/log"
import { Global } from "@opencode-ai/core/global"
import type { PermissionV1 } from "@opencode-ai/core/v1/permission"
import type { Config } from "@/config/config"
import * as Permission from "@/permission"
import type * as Tool from "@/tool/tool"
import { ConfigProtection } from "@/kilocode/permission/config-paths"
import type { PermissionProvenance } from "@/kilocode/permission/provenance"
import { Decision } from "./decision"
import { SecurityDeniedError } from "./error"
import { SecurityEngine } from "./engine"
import { SecurityFlag } from "./flag"
import { SecurityKeys } from "./keys"
import { PathRisk } from "./path"
import { ShellNormalizer } from "./shell"
import { PackageMetadata } from "./package/metadata"
import { PackageOperation } from "./package/operation"
import { PackageRiskEvaluator } from "./package/evaluator"
import type {
  FileEffect,
  NormalizedAction,
  NormalizedPath,
  SecurityContext,
  SecurityDecision,
  SecurityEvidence,
} from "./types"

/**
 * Integration of the security engine with Kilo's permission and execution pipeline.
 *
 * - `evaluate` turns a permission request into a normalised action and asks the engine.
 * - `apply` folds the decision into the request that reaches `Permission.ask`: DENY never reaches
 *   it, a hard ASK forces an interactive prompt, ALLOW only lifts the default ask, a soft ASK leaves
 *   the existing rules in charge.
 * - `execute` wraps tool execution: tools without their own permission ask get an envelope ask, and
 *   a security denial becomes a structured non-fatal result.
 *
 * With the feature flag off every function is a pass-through and behaviour is unchanged.
 */
export namespace SecurityGate {
  const log = Log.create({ service: "security" })

  export interface Options {
    enabled: boolean
    sandboxed: boolean
    workspace: { directory: string; worktree: string }
    /**
     * Security Auto layers. Absent means "engine only" so callers that build options by hand keep the
     * v1 behaviour; {@link options} fills it from the global config (both on by default).
     */
    layers?: SecurityFlag.Layers
  }

  export type Request = Omit<PermissionV1.Request, "id" | "tool" | "sessionID"> & {
    sessionID?: string
    /** Tool call the ask belongs to; lets the session-state layer link an ask to its execution. */
    tool?: { messageID: string; callID: string }
  }

  export interface Summary {
    decision: SecurityDecision["action"]
    hard: boolean
    reasonCode: SecurityDecision["reasonCode"]
    message: string
    rules: string[]
  }

  /** Tools that never have side effects and need no envelope ask. */
  const READONLY = new Set([
    "question",
    "suggest",
    "plan_enter",
    "plan_exit",
    "invalid",
    "agent_manager_models",
    "chart",
    "todoread",
    "list",
    "codesearch",
    "diagnostics",
  ])

  /** Built-in tools that call `ctx.ask` before their side effect; the ask-level gate covers them. */
  const ASKING = new Set([
    "bash",
    "edit",
    "write",
    "apply_patch",
    "read",
    "glob",
    "grep",
    "task",
    "skill",
    "webfetch",
    "websearch",
    "repo_clone",
    "repo_overview",
    "lsp",
    "todowrite",
    "execute",
    "kilo_local_recall",
    "kilo_memory_recall",
    "kilo_memory_save",
    "background_process",
    "interactive_terminal",
    "agent_manager",
    "board_read",
    "board_post",
    "browser_open",
    "generate_image",
    "notebook_read",
    "notebook_edit",
    "notebook_execute",
    "send_file",
    "semantic_search",
    "list_mcp_resources",
    "list_mcp_resource_templates",
    "read_mcp_resource",
  ])

  export const options = Effect.fn("SecurityGate.options")(function* (input: {
    config: Pick<Config.Interface, "getGlobal">
    sandboxed: boolean
    workspace: { directory: string; worktree: string }
  }) {
    const enabled = yield* SecurityFlag.enabled(input.config)
    const layers = enabled ? yield* SecurityFlag.layers(input.config) : { packages: false, egress: false }
    const result: Options = { enabled, sandboxed: input.sandboxed, workspace: input.workspace, layers }
    return result
  })

  export function summary(decision: SecurityDecision): Summary {
    return {
      decision: decision.action,
      hard: decision.hard,
      reasonCode: decision.reasonCode,
      message: decision.message,
      rules: [...new Set(decision.evidence.map((item) => item.rule))],
    }
  }

  /**
   * Instrumentation seam for the benchmark / evaluation harness only. It observes decisions that the
   * gate has *already made*; it can neither change a decision nor be reached on the normal code path
   * (no observer is registered unless the harness installs one). Kept here rather than in the harness
   * so the measured security-decision latency is exactly the engine's, with no wrapper overhead.
   */
  export interface Observation {
    sessionID: string
    permission: string
    decision: SecurityDecision["action"]
    hard: boolean
    reasonCode: SecurityDecision["reasonCode"]
    rules: string[]
    /** Wall-clock cost of normalisation + engine evaluation, in milliseconds. */
    durationMs: number
    fromEnvelope: boolean
  }

  let observer: ((observation: Observation) => void) | undefined

  /** Register a decision observer; returns a disposer that restores the previous one. */
  export function observe(fn: (observation: Observation) => void): () => void {
    const previous = observer
    observer = fn
    return () => {
      if (observer === fn) observer = previous
    }
  }

  function report(observation: Observation) {
    const current = observer
    if (!current) return
    try {
      current(observation)
    } catch {
      // An instrumentation failure must never affect a security decision or the tool run.
    }
  }

  function text(value: unknown) {
    return typeof value === "string" && value.length > 0 ? value : undefined
  }

  function fingerprint(value: string) {
    return createHash("sha256").update(value).digest("hex").slice(0, 16)
  }

  function collect(request: Request, ctx: SecurityContext, env: PathRisk.Env): NormalizedPath[] {
    const meta = request.metadata ?? {}
    const found = new Set<string>()
    const add = (value: unknown, base: string) => {
      if (typeof value !== "string" || value.length === 0) return
      const clean = value.replace(/[\\/]\*$/, "")
      found.add(path.isAbsolute(clean) ? clean : path.resolve(base, clean))
    }
    const filepath = text(meta.filepath)
    if (filepath) {
      for (const part of filepath.includes(", ") ? filepath.split(", ") : [filepath]) add(part, ctx.workspace.worktree)
    }
    if (Array.isArray(meta.files)) {
      for (const file of meta.files) {
        if (typeof file !== "object" || file === null) continue
        add((file as Record<string, unknown>).filePath, ctx.workspace.worktree)
        add((file as Record<string, unknown>).movePath, ctx.workspace.worktree)
      }
    }
    // parentDir / directories only widen the permission pattern; the target is the file itself.
    if (found.size === 0) add(meta.parentDir, ctx.workspace.worktree)
    if (found.size === 0 && Array.isArray(meta.directories))
      for (const dir of meta.directories) add(dir, ctx.workspace.worktree)
    if (found.size === 0) for (const pattern of request.patterns) add(pattern, ctx.workspace.worktree)
    return [...found].map((value) => PathRisk.classify(value, ctx.cwd, env))
  }

  const normalize = Effect.fn("SecurityGate.normalize")(function* (
    request: Request,
    ctx: SecurityContext,
    env: PathRisk.Env,
  ) {
    const meta = request.metadata ?? {}
    const command = text(meta.command)
    if (request.permission === "sandbox_escalation") {
      return {
        kind: "permission",
        permission: request.permission,
        patterns: [...request.patterns],
      } satisfies NormalizedAction
    }
    if (command !== undefined && (request.permission === "bash" || request.permission === "external_directory")) {
      const normalized = yield* ShellNormalizer.normalize({
        command,
        cwd: text(meta.cwd) ?? ctx.cwd,
        shell: text(meta.shell) ?? "/bin/bash",
        env,
      })
      return { kind: "shell", permission: request.permission, command: normalized } satisfies NormalizedAction
    }
    const mcp = request.patterns.every((pattern) => pattern.startsWith("mcp:"))
    if (
      (request.permission === "edit" || request.permission === "read" || request.permission === "external_directory") &&
      !mcp
    ) {
      // A file tool's external_directory ask only says "the path is outside the workspace"; the
      // tool-specific edit/read ask that follows carries the real effect, so evaluate the boundary
      // crossing as a read and let the next ask apply the write rules.
      const effect: FileEffect = request.permission === "edit" ? "write" : "read"
      // The read tool lists the parent directory as a second pattern for rule matching; only the
      // first pattern is the file being read.
      const paths =
        request.permission === "read"
          ? collect({ ...request, patterns: request.patterns.slice(0, 1) }, ctx, env)
          : collect(request, ctx, env)
      return { kind: "file", permission: request.permission, effect, paths } satisfies NormalizedAction
    }
    return {
      kind: "permission",
      permission: request.permission,
      patterns: [...request.patterns],
    } satisfies NormalizedAction
  })

  const PROJECT_FILE_LIMIT = 256 * 1024

  /** Bounded, synchronous read of a project file (package.json, .npmrc) for the package preflight. */
  function projectFile(file: string): string | undefined {
    try {
      const stat = statSync(file)
      if (!stat.isFile() || stat.size > PROJECT_FILE_LIMIT) return undefined
      return readFileSync(file, "utf8")
    } catch {
      return undefined
    }
  }

  /**
   * Package provenance preflight. Runs only for shell actions that contain a recognised package
   * install / exec, after the deterministic rules, and only when they did not already deny.
   * Returns evidence for the engine's monotonic reducer; never fails (evaluator errors are uncertainty).
   */
  const packageEvidence = Effect.fn("SecurityGate.packageEvidence")(function* (
    action: NormalizedAction,
    base: SecurityDecision,
    ctx: SecurityContext,
  ) {
    if (action.kind !== "shell" || base.action === "deny") return [] as SecurityEvidence[]
    const operations = PackageOperation.collect(action.command)
    if (operations.length === 0) return [] as SecurityEvidence[]
    const result = yield* PackageRiskEvaluator.evaluate({
      operations,
      provider: PackageMetadata.provider(),
      readFile: projectFile,
      cwd: ctx.cwd,
    })
    return result.evidence
  })

  /** Evaluate a permission request. Never fails: any internal error is a hard ASK. */
  export const evaluate = Effect.fn("SecurityGate.evaluate")(function* (input: {
    request: Request
    options: Options
    sessionID: string
    agent: string
  }) {
    const ctx: SecurityContext = {
      sessionID: input.sessionID,
      agent: input.agent,
      workspace: input.options.workspace,
      cwd: input.options.workspace.directory,
      home: Global.Path.home,
      sandbox: { enabled: input.options.sandboxed },
    }
    const layers = input.options.layers ?? { packages: false, egress: false }
    const started = performance.now()
    const exit = yield* Effect.exit(
      Effect.gen(function* () {
        const env = PathRisk.env({ workspace: input.options.workspace, home: ctx.home })
        const action = yield* normalize(input.request, ctx, env)
        const base = SecurityEngine.evaluate(action, ctx)
        if (!layers.packages) return base
        const packages = yield* packageEvidence(action, base, ctx)
        return SecurityEngine.extend(base, packages)
      }),
    )
    const durationMs = performance.now() - started
    const decision = Exit.isSuccess(exit) ? exit.value : Decision.failure(Cause.squash(exit.cause))
    report({
      sessionID: input.sessionID,
      permission: input.request.permission,
      decision: decision.action,
      hard: decision.hard,
      reasonCode: decision.reasonCode,
      rules: [...new Set(decision.evidence.map((item) => item.rule))],
      durationMs,
      fromEnvelope: input.request.metadata?.[SecurityKeys.ENVELOPE] === true,
    })
    const command = text(input.request.metadata?.command)
    log.info("decision", {
      permission: input.request.permission,
      decision: decision.action,
      hard: decision.hard,
      reason: decision.reasonCode,
      rules: [...new Set(decision.evidence.map((item) => item.rule))].join(","),
      sandbox: input.options.sandboxed,
      ...(command ? { fingerprint: fingerprint(command) } : {}),
    })
    return decision
  })

  function liftable(rule: Permission.Rule) {
    const source = (rule as PermissionProvenance.SourcedRule).source
    return rule.action === "ask" && (source === undefined || source === "agent")
  }

  /**
   * Fold a decision into the request. The caller must have handled DENY already (it never reaches
   * `Permission.ask`). A hard ASK forces an interactive prompt that no saved or configured allow rule
   * can satisfy; ALLOW lifts only the default ask (built-in or unmatched) and leaves explicit user,
   * project and session rules untouched; a soft ASK changes nothing.
   */
  export function apply<T extends Request>(input: {
    request: T
    ruleset: Permission.Ruleset
    decision: SecurityDecision
  }): { request: T; ruleset: Permission.Ruleset } {
    const decision = input.decision
    const meta = { ...input.request.metadata, [SecurityKeys.META]: summary(decision) }
    if (decision.action === "ask" && decision.hard) {
      return {
        request: {
          ...input.request,
          metadata: { ...meta, [SecurityKeys.ASK]: true, [ConfigProtection.DISABLE_ALWAYS_KEY]: true },
        },
        ruleset: input.ruleset,
      }
    }
    if (decision.action !== "allow") return { request: { ...input.request, metadata: meta }, ruleset: input.ruleset }
    const lifted: PermissionProvenance.SourcedRule[] = input.request.patterns
      .filter((pattern) => liftable(Permission.evaluate(input.request.permission, pattern, input.ruleset)))
      .map((pattern) => ({ permission: input.request.permission, pattern, action: "allow", source: "security" }))
    return { request: { ...input.request, metadata: meta }, ruleset: [...input.ruleset, ...lifted] }
  }

  /**
   * Execution gate. Tools that are not known to ask for permission themselves get an envelope ask so
   * they are evaluated (unclassified tools stay governed by the existing rules); a security denial
   * raised anywhere inside the tool becomes a structured, non-fatal result.
   */
  export function execute<A extends Tool.ExecuteResult, E, R>(
    input: { ctx: Tool.Context; tool: string; options: Options },
    effect: Effect.Effect<A, E, R>,
  ): Effect.Effect<A | Tool.ExecuteResult, E, R> {
    if (!input.options.enabled) return effect
    const envelope =
      READONLY.has(input.tool) || ASKING.has(input.tool)
        ? Effect.void
        : input.ctx.ask({
            permission: input.tool,
            patterns: ["*"],
            always: ["*"],
            metadata: { [SecurityKeys.ENVELOPE]: true },
          })
    return envelope.pipe(
      Effect.andThen(effect),
      Effect.catchCause((cause) => {
        const err = Cause.squash(cause)
        if (!SecurityDeniedError.isInstance(err)) return Effect.failCause(cause)
        log.info("blocked", { tool: input.tool, reason: err.reasonCode })
        return Effect.succeed(err.result(input.tool))
      }),
    )
  }
}
