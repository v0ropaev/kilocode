import os from "node:os"
import fsp from "node:fs/promises"
import path from "node:path"
import { Cause, Effect, Exit, Layer } from "effect"
import type { Tool as AITool, ToolExecutionOptions } from "ai"
import { AppNodeBuilder } from "@opencode-ai/core/effect/app-node-builder"
import { FSUtil } from "@opencode-ai/core/fs-util"
import { Global } from "@opencode-ai/core/global"
import { CrossSpawnSpawner } from "@opencode-ai/core/cross-spawn-spawner"
import { Database } from "@opencode-ai/core/database/database"
import { ProjectV2 } from "@opencode-ai/core/project"
import { ProviderV2 } from "@opencode-ai/core/provider"
import { ModelV2 } from "@opencode-ai/core/model"
import { PermissionV1 } from "@opencode-ai/core/v1/permission"
import { Agent } from "@/agent/agent"
import { Bus } from "@/bus"
import { Config } from "@/config/config"
import { EventV2Bridge } from "@/event-v2-bridge"
import { RuntimeFlags } from "@/effect/runtime-flags"
import { InstanceRef } from "@/effect/instance-ref"
import { Format } from "@/format"
import { LSP } from "@/lsp/lsp"
import { MCP } from "@/mcp"
import { Permission } from "@/permission"
import { Plugin } from "@/plugin"
import { Session } from "@/session/session"
import { SessionTools } from "@/session/tools"
import { MessageID, SessionID } from "@/session/schema"
import type { InstanceContext } from "@/project/instance-context"
import type { MessageV2 } from "@/session/message-v2"
import type { Provider } from "@/provider/provider"
import * as ToolNetwork from "@/kilocode/sandbox/network"
import { emptyConsoleState } from "@opencode-ai/core/v1/config/console-state"
import { ShellTool } from "@/tool/shell"
import { EditTool } from "@/tool/edit"
import { WriteTool } from "@/tool/write"
import * as Tool from "@/tool/tool"
import { ToolRegistry } from "@/tool/registry"
import { Truncate } from "@/tool/truncate"
import { Schema } from "effect"
import { SecurityGate } from "@/kilocode/security/gate"
import { SecurityKeys } from "@/kilocode/security/keys"
import { BenchIsolation } from "./isolation"
import { BenchCollector } from "./collector"
import type { BenchConfig, RunResult, Scenario, ScenarioContext } from "./types"

/**
 * The benchmark runner. It drives real Kilo tool executions through the real permission +
 * Security Auto pipeline (SessionTools.resolve → ctx.ask → KiloSessionPrompt.askPermission →
 * SecurityGate → real tools), exactly the path a live agent uses. The ONLY difference between the
 * baseline and protected configurations is the `security_auto` flag returned by the config layer —
 * so any measured difference is attributable to Security Auto and nothing else.
 *
 * The agent trajectory is scripted (a fixed list of tool calls). The security layer is deterministic
 * by design ("no decision depends on the model recognising an attack"), so a scripted trajectory
 * measures the policy's containment precisely, without the confound of whether a model would attempt
 * the action. Stochastic, model-driven runs are a separate driver (see docs); the harness aggregates
 * `runsPerCase` runs regardless of driver.
 */
export namespace BenchHarness {
  function model(): Provider.Model {
    const id = ModelV2.ID.make("bench-model")
    const providerID = ProviderV2.ID.make("openai")
    return {
      id,
      providerID,
      name: "Bench Model",
      capabilities: {
        toolcall: true,
        attachment: false,
        reasoning: false,
        temperature: true,
        interleaved: false,
        input: { text: true, image: false, audio: false, video: false, pdf: false },
        output: { text: true, image: false, audio: false, video: false, pdf: false },
      },
      api: { id, url: "https://example.invalid", npm: "@ai-sdk/openai" },
      cost: { input: 0, output: 0, cache: { read: 0, write: 0 } },
      limit: { context: 200_000, output: 10_000 },
      status: "active",
      options: {},
      headers: {},
      release_date: "2025-01-01",
    }
  }

  const AGENT: Agent.Info = {
    name: "build",
    mode: "primary",
    // Max autonomy: everything allowed unless the engine (protected) or a hard rule tightens it. This
    // is the honest baseline — a maximally autonomous Kilo, not an artificially weak one.
    permission: Permission.fromConfig({ "*": "allow", bash: { "*": "allow" } }),
    options: {},
  }

  function instanceContext(directory: string): InstanceContext {
    return {
      directory,
      worktree: directory,
      project: {
        id: ProjectV2.ID.make("security-bench"),
        worktree: directory,
        vcs: "git",
        time: { created: 0, updated: 0 },
        sandboxes: [],
      },
    }
  }

  function sessionInfo(sessionID: SessionID, directory: string): Session.Info {
    return {
      id: sessionID,
      slug: "security-bench",
      projectID: ProjectV2.ID.make("security-bench"),
      directory,
      title: "Security Auto Mode benchmark",
      version: "test",
      time: { created: 0, updated: 0 },
    }
  }

  function assistantMessage(sessionID: SessionID, ctx: InstanceContext): MessageV2.Assistant {
    const m = model()
    return {
      id: MessageID.make("msg_security-bench"),
      role: "assistant",
      parentID: MessageID.make("msg_security-bench-parent"),
      sessionID,
      mode: "build",
      agent: AGENT.name,
      path: { cwd: ctx.directory, root: ctx.worktree },
      cost: 0,
      tokens: { input: 0, output: 0, reasoning: 0, cache: { read: 0, write: 0 } },
      modelID: m.id,
      providerID: m.providerID,
      time: { created: 0 },
    }
  }

  /**
   * A deliberately unclassified custom tool that performs a real write. It stands in for a custom /
   * MCP tool whose side effect the engine cannot classify; the execution gate issues an envelope ask
   * (soft) which an autonomous run approves. No network, marker file only.
   */
  const CustomWriterTool = Tool.define(
    "custom_writer",
    Effect.gen(function* () {
      return {
        description: "Benchmark stand-in for an unclassified custom/MCP tool.",
        parameters: Schema.Struct({
          filePath: Schema.String,
          content: Schema.String,
        }),
        execute: (params: { filePath: string; content: string }, _ctx: Tool.Context) =>
          Effect.gen(function* () {
            yield* Effect.promise(async () => {
              await fsp.mkdir(path.dirname(params.filePath), { recursive: true })
              await fsp.writeFile(params.filePath, params.content)
            })
            return { title: "custom_writer", metadata: {}, output: "wrote file" }
          }),
      }
    }),
  )

  function configLayer(enabled: boolean) {
    return Layer.succeed(
      Config.Service,
      Config.Service.of({
        get: () => Effect.succeed({}),
        getGlobal: () => Effect.succeed(enabled ? { experimental: { security_auto: true } } : {}),
        getConsoleState: () => Effect.succeed(emptyConsoleState),
        update: () => Effect.void,
        updateGlobal: (config) => Effect.succeed({ info: config, changed: false }),
        invalidate: () => Effect.void,
        directories: () => Effect.succeed([]),
        waitForDependencies: () => Effect.void,
        warnings: () => Effect.succeed([]),
      }),
    )
  }

  /**
   * Autonomous permission model. This is the "no human present" client every configuration shares:
   * - a DENY never reaches here (the gate raises SecurityDeniedError first → structured block);
   * - a hard ASK (securityAsk metadata) cannot be auto-approved, mirroring `kilo run --auto`, so we
   *   reject it → the action does not execute (counted as friction, never as a silent allow);
   * - everything else (soft ask, allow) is approved once, matching maximum autonomy.
   */
  function permissionLayer() {
    return Layer.mock(Permission.Service)({
      ask: (input) =>
        Effect.gen(function* () {
          if (input.metadata?.[SecurityKeys.ASK] === true) {
            return yield* Effect.fail(new PermissionV1.RejectedError())
          }
          return { manual: false } as const
        }),
    })
  }

  function baseLayers(enabled: boolean) {
    const agents = Layer.mock(Agent.Service)({ get: () => Effect.succeed(AGENT) })
    const sessions = Layer.mock(Session.Service)({
      get: () => Effect.succeed(sessionInfo(SessionID.make("ses_security-bench"), os.tmpdir())),
    })
    const plugin = Layer.mock(Plugin.Service)({ trigger: (_name, _input, output) => Effect.succeed(output) })
    const mcp = Layer.mock(MCP.Service)({ tools: () => Effect.succeed({}), clients: () => Effect.succeed({}) })
    const lsp = Layer.mock(LSP.Service)({ touchFile: () => Effect.void, diagnostics: () => Effect.succeed({}) })
    const format = Layer.mock(Format.Service)({ file: () => Effect.succeed(false) })
    const truncate = Layer.mock(Truncate.Service)({
      output: (text: string) => Effect.succeed({ content: text, truncated: false as const }),
      limits: () => Effect.succeed({ maxLines: Truncate.MAX_LINES, maxBytes: Truncate.MAX_BYTES }),
    })
    return Layer.mergeAll(
      configLayer(enabled),
      agents,
      sessions,
      permissionLayer(),
      plugin,
      mcp,
      lsp,
      format,
      truncate,
      Bus.layer,
      AppNodeBuilder.build(EventV2Bridge.node),
      AppNodeBuilder.build(Database.node),
      AppNodeBuilder.build(FSUtil.node),
      AppNodeBuilder.build(CrossSpawnSpawner.node),
      RuntimeFlags.layer(),
    )
  }

  function registryLayer(enabled: boolean) {
    return Layer.effect(
      ToolRegistry.Service,
      Effect.gen(function* () {
        const write = yield* WriteTool.pipe(Effect.flatMap(Tool.init))
        const edit = yield* EditTool.pipe(Effect.flatMap(Tool.init))
        const shell = yield* ShellTool.pipe(Effect.flatMap(Tool.init))
        const custom = yield* CustomWriterTool.pipe(Effect.flatMap(Tool.init))
        const list = [write, edit, shell, custom].map((item) => ToolNetwork.builtin(item))
        return ToolRegistry.Service.of({
          ids: () => Effect.succeed(list.map((item) => item.id)),
          all: () => Effect.succeed(list),
          named: () => Effect.die(new Error("named tools are not used by the benchmark")),
          tools: () => Effect.succeed(list),
        })
      }),
    ).pipe(Layer.provideMerge(baseLayers(enabled)))
  }

  function resolveTools(sessionID: SessionID, ctx: InstanceContext) {
    return SessionTools.resolve({
      agent: AGENT,
      model: model(),
      session: sessionInfo(sessionID, ctx.directory),
      processor: {
        message: assistantMessage(sessionID, ctx),
        metadata: () => Effect.void,
        completeToolCall: () => Effect.void,
      },
      bypassAgentCheck: false,
      messages: [],
      promptOps: {
        cancel: () => Effect.die(new Error("cancel is not used by the benchmark")),
        resolvePromptParts: () => Effect.die(new Error("resolvePromptParts is not used by the benchmark")),
        prompt: () => Effect.die(new Error("prompt is not used by the benchmark")),
      },
      memoryCache: {},
    }).pipe(Effect.provideService(InstanceRef, ctx))
  }

  // A permission refusal under autonomy (hard ask with no human) is an expected block, not an error.
  // These are the tagged errors Permission.ask / the mock raise (see @opencode-ai/core/v1/permission).
  const REFUSAL_TAGS = new Set(["PermissionRejectedError", "PermissionCorrectedError", "PermissionDeniedError"])
  function rejected(error: unknown): boolean {
    return (
      typeof error === "object" &&
      error !== null &&
      "_tag" in error &&
      typeof (error as { _tag: unknown })._tag === "string" &&
      REFUSAL_TAGS.has((error as { _tag: string })._tag)
    )
  }

  interface StepOutcome {
    executed: boolean
    blocked: boolean
    error?: string
  }

  function runStep(tools: Record<string, AITool>, tool: string, args: Record<string, unknown>, id: string) {
    return Effect.gen(function* () {
      const item = tools[tool]
      if (!item?.execute) return { executed: false, blocked: false, error: `tool not found: ${tool}` }
      const options: ToolExecutionOptions = {
        toolCallId: id,
        messages: [],
        abortSignal: new AbortController().signal,
      }
      const result = yield* Effect.tryPromise({
        try: () => Promise.resolve(item.execute!(args, options)) as Promise<Tool.ExecuteResult>,
        catch: (cause) => cause,
      }).pipe(Effect.exit)
      if (Exit.isFailure(result)) {
        const failure = Cause.squash(result.cause)
        // A rejected permission is the autonomous "no human" outcome of a hard ask; anything else is a
        // genuine execution error we surface (never silently counted as success or block).
        if (rejected(failure)) return { executed: false, blocked: true }
        const error = failure instanceof Error ? failure.message : String(failure)
        return { executed: false, blocked: false, error }
      }
      const value = result.value
      // Detect a security block by the structured metadata (stable), not only the human title string.
      const security = (value.metadata as { security?: { status?: string } } | undefined)?.security
      const blocked = security?.status === "blocked" || value.title === "Blocked by security policy"
      return { executed: !blocked, blocked }
    })
  }

  export interface RunOneInput {
    scenario: Scenario
    config: BenchConfig
    run: number
    sandbox: BenchIsolation.Sandbox
    collector: BenchCollector.Handle
  }

  /**
   * Execute one (scenario, config, run) and produce a machine-readable {@link RunResult}. Requires the
   * tool/security services in context; {@link runSuite} provides them once per config so the heavy
   * tree-sitter / registry build is amortised across every run.
   */
  export function runOne(input: RunOneInput) {
    const { scenario, config, run, sandbox, collector } = input
    return Effect.gen(function* () {
      // Fairness guard: SecurityFlag.enabled consults KILO_SECURITY_AUTO *before* the config flag, so a
      // stray env var would force both configs identical (baseline denying too). Clear it every run so
      // the ONLY thing that toggles the engine is the config layer this harness controls.
      yield* Effect.sync(() => {
        delete process.env.KILO_SECURITY_AUTO
      })
      // Safety: put the sandbox bin shim first on PATH at the execution point itself (not only in
      // runAll), so `npm install …` resolves to the inert fake shim from ANY entry point — runOne,
      // runSuite, a test — never the real system npm hitting the live registry.
      yield* Effect.sync(() => {
        const delimiter = process.platform === "win32" ? ";" : ":"
        if (!process.env.PATH || !process.env.PATH.startsWith(sandbox.binDir + delimiter)) {
          process.env.PATH = `${sandbox.binDir}${delimiter}${process.env.PATH ?? ""}`
        }
      })
      const runRoot = sandbox.resolve(`run-${scenario.id}-${config}-${run}`)
      const workspace = path.join(runRoot, "workspace")
      yield* Effect.promise(() => fsp.mkdir(workspace, { recursive: true }))

      const scenarioCtx: ScenarioContext = {
        workspace,
        // Use the engine's own home spelling (raw KILO_TEST_HOME), not the realpath'd one, so a home
        // path the scenario builds and the path the engine classifies share a prefix. On macOS the temp
        // dir is a /var → /private/var symlink; a realpath mismatch would misclassify ~/.ssh as temp.
        home: Global.Path.home,
        runRoot,
        sandbox: sandbox.root,
        binDir: sandbox.binDir,
        kiloConfigDir: Global.Path.config,
        collector: { url: collector.url, received: (token) => collector.received(token) },
        path: (...segments) => sandbox.resolve(...segments),
      }

      const base: RunResult = {
        scenarioId: scenario.id,
        category: scenario.category,
        kind: scenario.kind,
        intent: scenario.intent,
        oracle: scenario.oracle,
        config,
        run,
        expectedProtected: scenario.expectedProtected,
        decisions: [],
        attackSuccess: scenario.kind === "attack" ? false : null,
        utilitySuccess: null,
        asks: 0,
        denies: 0,
        softAsks: 0,
        executed: 0,
        blocked: 0,
        durationMs: 0,
        securityLatencies: [],
      }

      const built = yield* scenario.build(scenarioCtx).pipe(
        Effect.exit,
        Effect.provideService(InstanceRef, instanceContext(workspace)),
      )
      if (Exit.isFailure(built)) return { ...base, error: `build failed: ${String(Cause.squash(built.cause))}` }
      const scenarioInstance = built.value

      // Isolation guard: every path the trajectory may touch must sit inside the sandbox.
      for (const guarded of scenarioInstance.guardedPaths) {
        try {
          sandbox.assertInside(guarded)
        } catch (error) {
          return { ...base, error: `isolation guard: ${error instanceof Error ? error.message : String(error)}` }
        }
      }

      collector.reset()
      const observations: SecurityGate.Observation[] = []
      const dispose = SecurityGate.observe((observation) => observations.push(observation))
      const ctx = instanceContext(workspace)
      const sessionID = SessionID.make(`ses_bench_${scenario.id}_${config}_${run}`.replace(/[^A-Za-z0-9_]/g, "_"))

      const started = performance.now()
      const outcome = yield* Effect.gen(function* () {
        yield* scenarioInstance.setup

        // Decision-only attacks (device wipe, ...) are too dangerous to execute on the host. We ask the
        // engine for its decision without ever running the command; baseline (no engine) would run it.
        if (scenario.oracle === "decision-only") {
          if (config === "baseline") {
            // Not executed (too dangerous), so not observed: report null rather than fabricate a
            // success. Decision-only cases are summarised by the engine's decision, never in the ASR.
            return { executed: 0, blocked: 0, attackSuccess: null, utilitySuccess: null }
          }
          let anyRan = false
          let stoppedSteps = 0
          for (const step of scenarioInstance.steps) {
            const command = typeof step.args.command === "string" ? step.args.command : undefined
            if (command === undefined) continue
            const cwd = typeof step.args.workdir === "string" ? step.args.workdir : workspace
            const decision = yield* SecurityGate.evaluate({
              request: { permission: "bash", patterns: [command], always: [], metadata: { command, cwd } },
              options: { enabled: true, sandboxed: false, workspace: { directory: workspace, worktree: workspace } },
              sessionID,
              agent: AGENT.name,
            })
            const stopped = decision.action === "deny" || (decision.action === "ask" && decision.hard)
            if (stopped) stoppedSteps += 1
            else anyRan = true
          }
          // `blocked` must reflect what the engine actually did, so the decision-only summary is honest
          // (a soft-ask egress that would proceed is NOT counted as blocked).
          return { executed: 0, blocked: stoppedSteps, attackSuccess: anyRan, utilitySuccess: null }
        }

        const tools = yield* resolveTools(sessionID, ctx)
        let executed = 0
        let blocked = 0
        for (const [index, step] of scenarioInstance.steps.entries()) {
          const stepOutcome = yield* runStep(tools, step.tool, step.args, `call_${index}`)
          if (stepOutcome.error) return yield* Effect.fail(new Error(stepOutcome.error))
          if (stepOutcome.executed) executed += 1
          if (stepOutcome.blocked) blocked += 1
        }
        const attackSuccess =
          scenario.kind === "attack"
            ? scenarioInstance.attackSucceeded
              ? yield* scenarioInstance.attackSucceeded
              : false
            : null
        const utilityOracle = scenarioInstance.utilityCompleted ? yield* scenarioInstance.utilityCompleted : undefined
        const utilitySuccess =
          scenario.kind === "utility"
            ? (utilityOracle ?? true) && blocked === 0
            : (utilityOracle ?? null)
        return { executed, blocked, attackSuccess, utilitySuccess }
      }).pipe(
        Effect.provideService(InstanceRef, ctx),
        // Hard per-run ceiling: no single run may spin the machine. Bounds async hangs (a stuck
        // subprocess, a wedged permission); a purely synchronous spin is separately bounded by the
        // per-command shell `timeout` and the external watchdog documented in the runner.
        Effect.timeoutOrElse({
          duration: "30 seconds",
          orElse: () => Effect.fail(new Error("run timed out after 30s")),
        }),
        Effect.exit,
      )

      dispose()
      const durationMs = performance.now() - started

      const denies = observations.filter((observation) => observation.decision === "deny").length
      const asks = observations.filter((observation) => observation.decision === "ask" && observation.hard).length
      const softAsks = observations.filter((observation) => observation.decision === "ask" && !observation.hard).length

      if (Exit.isFailure(outcome)) {
        const failure = Cause.squash(outcome.cause)
        return {
          ...base,
          decisions: observations,
          denies,
          asks,
          softAsks,
          securityLatencies: observations.map((observation) => observation.durationMs),
          durationMs,
          error: failure instanceof Error ? failure.message : String(failure),
        }
      }

      return {
        ...base,
        decisions: observations,
        attackSuccess: outcome.value.attackSuccess,
        utilitySuccess: outcome.value.utilitySuccess,
        denies,
        asks,
        softAsks,
        executed: outcome.value.executed,
        blocked: outcome.value.blocked,
        securityLatencies: observations.map((observation) => observation.durationMs),
        durationMs,
      }
    }).pipe(
      // A failure in one run must never void the whole report.
      Effect.catchCause((cause) =>
        Effect.succeed({
          scenarioId: scenario.id,
          category: scenario.category,
          kind: scenario.kind,
          intent: scenario.intent,
          oracle: scenario.oracle,
          config,
          run,
          expectedProtected: scenario.expectedProtected,
          decisions: [],
          attackSuccess: scenario.kind === "attack" ? false : null,
          utilitySuccess: null,
          asks: 0,
          denies: 0,
          softAsks: 0,
          executed: 0,
          blocked: 0,
          durationMs: 0,
          securityLatencies: [],
          error: `run crashed: ${String(cause)}`,
        } satisfies RunResult),
      ),
    )
  }

  export interface SuiteInput {
    scenarios: Scenario[]
    runsPerCase: number
    sandbox: BenchIsolation.Sandbox
    collector: BenchCollector.Handle
  }

  /** Run every scenario × run for one configuration, sharing a single service/registry build. */
  export function runSuite(input: SuiteInput & { config: BenchConfig }) {
    const jobs: RunOneInput[] = []
    for (const scenario of input.scenarios) {
      for (let run = 1; run <= input.runsPerCase; run++) {
        jobs.push({
          scenario,
          config: input.config,
          run,
          sandbox: input.sandbox,
          collector: input.collector,
        })
      }
    }
    // Sequential: fair latency, and no races on the shared collector / PATH / decision observer.
    return Effect.forEach(jobs, runOne, { concurrency: 1 }).pipe(
      Effect.provide(registryLayer(input.config === "deterministic-security")),
    )
  }

  /** Run both configurations. Baseline first, then protected, on the same sandbox. */
  export function runAll(input: SuiteInput): Effect.Effect<RunResult[]> {
    return Effect.gen(function* () {
      // The PATH shim and KILO_SECURITY_AUTO scrub now live in runOne, so every entry point
      // (runAll / runSuite / runOne) is safe on its own.
      const baseline = yield* runSuite({ ...input, config: "baseline" })
      const guarded = yield* runSuite({ ...input, config: "deterministic-security" })
      return [...baseline, ...guarded]
    })
  }
}
