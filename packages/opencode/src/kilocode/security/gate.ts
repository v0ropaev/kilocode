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
import { SecuritySessionState } from "./state/store"
import { EgressGuard } from "./state/egress"
import { SecretContent } from "./state/content"
import { ToolAuthority } from "./tool/authority"
import { ToolCapability } from "./tool/capability"
import type {
  FileEffect,
  McpIdentity,
  NormalizedAction,
  NormalizedPath,
  SecurityContext,
  SecurityDecision,
  SecurityEvidence,
  ToolDescriptor,
  ToolInvocation,
  ToolProvenance,
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
     * Evidence layers above the deterministic engine. Absent means "engine only", so callers that
     * build options by hand keep that behaviour; {@link options} fills it from the global config
     * (all on by default).
     */
    layers?: SecurityFlag.Layers
    /** Tool capabilities the user vouches for, from the global config. */
    declarations?: ToolCapability.Declarations
  }

  export type Request = Omit<PermissionV1.Request, "id" | "tool" | "sessionID"> & {
    sessionID?: string
    /** Tool call the ask belongs to; lets the session-state layer link an ask to its execution. */
    tool?: { messageID: string; callID: string }
    /**
     * Identity and arguments of the tool call this ask belongs to. Deliberately
     * *not* part of `metadata`: the arguments stay in process and never reach the permission record,
     * client events, logs or audit. Absent when the mode or the tool layer is off.
     */
    security?: ToolInvocation
  }

  export interface Summary {
    decision: SecurityDecision["action"]
    hard: boolean
    reasonCode: SecurityDecision["reasonCode"]
    message: string
    rules: string[]
  }

  /**
   * Tools that never have side effects, and tools that call `ctx.ask` themselves before their side
   * effect: both need no envelope ask. Derived from the capability table so the classification lives
   * in exactly one place — a tool cannot be added to the table and forgotten here, or listed here
   * without a classification.
   */
  const READONLY = ToolCapability.READONLY
  const ASKING = ToolCapability.ASKING

  export const options = Effect.fn("SecurityGate.options")(function* (input: {
    config: Pick<Config.Interface, "getGlobal">
    sandboxed: boolean
    workspace: { directory: string; worktree: string }
  }) {
    const enabled = yield* SecurityFlag.enabled(input.config)
    const layers: SecurityFlag.Layers = enabled
      ? yield* SecurityFlag.layers(input.config)
      : { packages: false, egress: false, tools: false, content: false, code: false }
    const declarations = enabled && layers.tools ? yield* SecurityFlag.declarations(input.config) : []
    const result: Options = { enabled, sandboxed: input.sandboxed, workspace: input.workspace, layers, declarations }
    return result
  })

  /**
   * Build the security descriptor for a tool call. Called at each execution site, where the tool's
   * structural provenance is known; returns nothing when the mode or the tool layer is off, so a
   * disabled feature adds no field to any request.
   */
  export function describe(input: {
    tool: string
    provenance: ToolProvenance
    args: unknown
    options: Options
    mcp?: McpIdentity
    hints?: ToolDescriptor["hints"]
  }): ToolInvocation | undefined {
    if (!input.options.enabled || input.options.layers?.tools !== true) return undefined
    const args = typeof input.args === "object" && input.args !== null ? (input.args as Record<string, unknown>) : {}
    try {
      const descriptor = ToolCapability.resolve({
        tool: input.tool,
        provenance: input.provenance,
        declarations: input.options.declarations,
        ...(input.mcp ? { mcp: input.mcp } : {}),
        ...(input.hints ? { hints: input.hints } : {}),
      })
      return { descriptor, args }
    } catch {
      // Failing to classify is uncertainty, never permission: fall back to the most conservative
      // descriptor rather than dropping the layer (which would leave the call unclassified).
      return {
        descriptor: {
          tool: input.tool,
          provenance: "unknown",
          capabilities: [],
          source: "unknown",
          asks: false,
        },
        args,
      }
    }
  }

  /**
   * Provenance label for a tool *result* (§tool-result provenance). Audit only:
   * it records that the content in this result came from outside Kilo. No content is inspected,
   * rewritten or filtered, and nothing reads this label as policy today.
   */
  export function resultProvenance(descriptor: ToolDescriptor | undefined): string | undefined {
    if (!descriptor) return undefined
    switch (descriptor.provenance) {
      case "builtin":
        return undefined
      case "mcp-remote":
        return "remote-untrusted"
      case "mcp-local":
        return "mcp-untrusted"
      case "trusted-config":
        return "config-untrusted"
      case "plugin":
        return "plugin-untrusted"
      default:
        return "workspace-untrusted"
    }
  }

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
    const layers = input.options.layers ?? { packages: false, egress: false, tools: false, content: false, code: false }
    const callID = input.request.tool?.callID
    const started = performance.now()
    const exit = yield* Effect.exit(
      Effect.gen(function* () {
        const env = PathRisk.env({ workspace: input.options.workspace, home: ctx.home })
        const action = yield* normalize(input.request, ctx, env)
        let decision = SecurityEngine.evaluate(action, ctx)
        if (layers.packages) {
          const packages = yield* packageEvidence(action, decision, ctx)
          decision = SecurityEngine.extend(decision, packages)
        }
        if (layers.egress) {
          // Record what this call would read/taint, keyed by the tool call so it is committed only
          // when the call succeeds (see `execute`); fold the egress evidence in monotonically.
          const egress = EgressGuard.assess({
            action,
            sessionID: input.sessionID,
            ...(layers.content ? { readFile: contentSource } : {}),
          })
          if (callID !== undefined) SecuritySessionState.recordPending(input.sessionID, callID, egress.pending)
          decision = SecurityEngine.extend(decision, egress.evidence)
        }
        if (layers.tools && input.request.security) {
          // Delegated authority: what the tool is allowed to do, who wrote it, and what its arguments
          // touch. Folded through the same reducer, so it can only tighten earlier decisions.
          const authority = ToolAuthority.assess({
            invocation: input.request.security,
            ctx,
            env,
            sessionID: input.sessionID,
            ...(layers.content ? { readFile: contentSource } : {}),
          })
          if (callID !== undefined) SecuritySessionState.recordPending(input.sessionID, callID, authority.pending)
          decision = SecurityEngine.extend(decision, authority.evidence)
        }
        return decision
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
   * Bounded, synchronous read used at *decision* time to classify content an action would send.
   * Smaller cap than {@link secretSource}: this runs before an outbound action, not after a
   * completed read.
   */
  function contentSource(file: string): string | undefined {
    try {
      const stat = statSync(file)
      if (!stat.isFile() || stat.size > 1024 * 1024) return undefined
      return readFileSync(file, "utf8")
    } catch {
      return undefined
    }
  }

  /** Read a file's contents to fingerprint its secret values, on a committed sensitive read. */
  function secretSource(file: string): string | undefined {
    try {
      const stat = statSync(file)
      if (!stat.isFile() || stat.size > 8 * 1024 * 1024) return undefined
      return readFileSync(file, "utf8")
    } catch {
      return undefined
    }
  }

  /**
   * Classify the content a completed call actually returned. A session becomes
   * sensitive from *observed* content, never from a filename and never from a refused request, so this
   * runs only on the success path with the output the agent really received.
   *
   * Returns nothing when the content earns no label — including when classification fails, which
   * leaves whatever sensitivity the session already had untouched rather than clearing it.
   */
  function observeContent(input: {
    text: string | undefined
    tool: string
    sessionID: string
    callID: string
  }): SecuritySessionState.Observed | undefined {
    if (!input.text) return undefined
    const candidates = SecuritySessionState.pendingCandidates(input.sessionID, input.callID)
    // Only name the source file when the call read exactly one: with several, a per-file rule (skipping
    // structurally noisy files) could not be attributed correctly.
    const file = candidates.length === 1 ? candidates[0]!.canonical : undefined
    const result = SecretContent.classify(input.text, file ? { file } : {})
    if (result.labels.length === 0) return undefined
    return {
      labels: result.labels,
      values: result.values,
      kinds: [...new Set(result.findings.map((item) => item.kind))],
      source: `tool:${input.tool}`,
    }
  }

  /**
   * Execution gate. Tools that are not known to ask for permission themselves get an envelope ask so
   * they are evaluated (unclassified tools stay governed by the existing rules); a security denial
   * raised anywhere inside the tool becomes a structured, non-fatal result.
   *
   * When the egress layer is on it also commits the session-state observations recorded at ask time:
   * a tool that ran successfully really obtained what it read (so its values enter the session's
   * secret set), while a blocked or failed tool discards them — a credential the agent was refused
   * never becomes "secret context".
   */
  export function execute<A extends Tool.ExecuteResult, E, R>(
    input: { ctx: Tool.Context; tool: string; options: Options; invocation?: ToolInvocation },
    effect: Effect.Effect<A, E, R>,
  ): Effect.Effect<A | Tool.ExecuteResult, E, R> {
    if (!input.options.enabled) return effect
    const callID = input.ctx.callID
    const sessionID = input.ctx.sessionID
    // A tool that Kilo did not ship cannot be trusted to ask for permission on its own, and cannot be
    // trusted to report honestly that it was blocked. Both facts follow from provenance alone.
    const trusted = input.invocation === undefined || input.invocation.descriptor.provenance === "builtin"
    const settle = (committed: boolean, output?: string) =>
      Effect.sync(() => {
        if (!input.options.layers?.egress || callID === undefined) return
        if (!committed) return SecuritySessionState.discard(sessionID, callID)
        const observed = input.options.layers.content
          ? observeContent({ text: output, tool: input.tool, sessionID, callID })
          : undefined
        SecuritySessionState.commit(sessionID, callID, secretSource, observed)
      })
    // Tool-id shadowing: a workspace or plugin tool may call itself `read` or `list`. The envelope is
    // skipped only for a genuine built-in, so borrowing a built-in's name buys nothing.
    const envelope =
      trusted && (READONLY.has(input.tool) || ASKING.has(input.tool))
        ? Effect.void
        : input.ctx.ask({
            permission: input.tool,
            patterns: ["*"],
            always: ["*"],
            metadata: { [SecurityKeys.ENVELOPE]: true },
          })
    return envelope.pipe(
      Effect.andThen(effect),
      Effect.tap((result) => {
        // A built-in tool may convert a denial into a structured blocked result rather than failing; a
        // blocked result means the side effect did not happen, so discard rather than commit. The same
        // marker from a tool Kilo did not ship is just tool-controlled text: honouring it would let a
        // custom tool read a credential and then declare itself blocked to erase the session's record.
        const security = (result.metadata as { security?: { status?: string } } | undefined)?.security
        const claimed = security?.status === "blocked" || result.title === "Blocked by security policy"
        const blocked = claimed && trusted
        return settle(!blocked, blocked ? undefined : result.output)
      }),
      Effect.catchCause((cause) => {
        const err = Cause.squash(cause)
        if (!SecurityDeniedError.isInstance(err)) return settle(false).pipe(Effect.andThen(Effect.failCause(cause)))
        log.info("blocked", { tool: input.tool, reason: err.reasonCode })
        return settle(false).pipe(Effect.as(err.result(input.tool)))
      }),
    )
  }

  /**
   * Execution gate for a delegated (MCP) call. Such a call asks for permission explicitly, so it gets
   * no envelope ask; what it gains here is the rest of the envelope's job: the session-state settle,
   * and turning a security denial into a structured result the agent can read instead of a defect
   * that ends the turn.
   */
  export function delegate<A, E, R>(
    input: {
      ctx: Tool.Context
      tool: string
      options: Options
      /** Text of the delegated result, for content classification. */
      output?: (value: A) => string | undefined
    },
    blocked: (error: SecurityDeniedError) => A,
    effect: Effect.Effect<A, E, R>,
  ): Effect.Effect<A, E, R> {
    if (!input.options.enabled) return effect
    const callID = input.ctx.callID
    const sessionID = input.ctx.sessionID
    const settle = (committed: boolean, output?: string) =>
      Effect.sync(() => {
        if (!input.options.layers?.egress || callID === undefined) return
        if (!committed) return SecuritySessionState.discard(sessionID, callID)
        const observed = input.options.layers.content
          ? observeContent({ text: output, tool: input.tool, sessionID, callID })
          : undefined
        SecuritySessionState.commit(sessionID, callID, secretSource, observed)
      })
    return effect.pipe(
      Effect.tap((value) => settle(true, input.output?.(value))),
      Effect.catchCause((cause) => {
        const err = Cause.squash(cause)
        if (!SecurityDeniedError.isInstance(err)) return settle(false).pipe(Effect.andThen(Effect.failCause(cause)))
        log.info("blocked", { tool: input.tool, reason: err.reasonCode })
        return settle(false).pipe(Effect.as(blocked(err)))
      }),
    )
  }
}
