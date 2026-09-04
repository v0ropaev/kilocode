import { Effect } from "effect"
import { Config } from "@/config/config"
import { ToolCapability } from "./tool/capability"

/**
 * Security Auto Mode is off by default. It is enabled from user-owned state only: the global Kilo
 * config (`experimental.security_auto: true`) or the `KILO_SECURITY_AUTO` environment variable.
 * Project config is deliberately ignored so a repository cannot turn the mode on or off, and the
 * global config directory is itself protected from agent writes by the engine's hard rules.
 *
 * The layers (package provenance preflight, stateful secret-egress protection, delegated-authority
 * classification of MCP / custom tools) follow the same rule: on by default whenever the mode is on,
 * switchable off individually from the global config (`experimental.security_auto_packages`,
 * `experimental.security_auto_egress`, `experimental.security_auto_tools`) or the environment
 * (`KILO_SECURITY_AUTO_PACKAGES`, `KILO_SECURITY_AUTO_EGRESS`, `KILO_SECURITY_AUTO_TOOLS`). They are
 * never read from a project.
 */
export namespace SecurityFlag {
  export interface Layers {
    /** Pre-install package provenance / lifecycle preflight. */
    packages: boolean
    /** Stateful sensitive-read → outbound-egress protection. */
    egress: boolean
    /** Delegated-authority classification of MCP / custom / unclassified tools. */
    tools: boolean
    /** Secret classification of content the agent actually obtained. */
    content: boolean
    /** Trust boundary for executable project code, evaluated before import. */
    code: boolean
    /** Permissioned host process for approved project extensions. */
    runtime: boolean
  }

  function truthy(value: string | undefined) {
    return value === "1" || value === "true"
  }

  function falsy(value: string | undefined) {
    return value === "0" || value === "false"
  }

  export const enabled = Effect.fn("SecurityFlag.enabled")(function* (config: Pick<Config.Interface, "getGlobal">) {
    if (truthy(process.env["KILO_SECURITY_AUTO"])) return true
    if (falsy(process.env["KILO_SECURITY_AUTO"])) return false
    const global = yield* config.getGlobal().pipe(Effect.catch(() => Effect.succeed(undefined)))
    return global?.experimental?.security_auto === true
  })

  function layer(env: string | undefined, configured: boolean | undefined) {
    if (truthy(env)) return true
    if (falsy(env)) return false
    return configured !== false
  }

  /** Which layers are active. Meaningful only when {@link enabled} is true. */
  export const layers = Effect.fn("SecurityFlag.layers")(function* (config: Pick<Config.Interface, "getGlobal">) {
    const global = yield* config.getGlobal().pipe(Effect.catch(() => Effect.succeed(undefined)))
    const result: Layers = {
      packages: layer(process.env["KILO_SECURITY_AUTO_PACKAGES"], global?.experimental?.security_auto_packages),
      egress: layer(process.env["KILO_SECURITY_AUTO_EGRESS"], global?.experimental?.security_auto_egress),
      tools: layer(process.env["KILO_SECURITY_AUTO_TOOLS"], global?.experimental?.security_auto_tools),
      content: layer(process.env["KILO_SECURITY_AUTO_CONTENT"], global?.experimental?.security_auto_content),
      code: layer(process.env["KILO_SECURITY_AUTO_CODE"], global?.experimental?.security_auto_code),
      runtime: layer(
        process.env["KILO_SECURITY_AUTO_EXTENSION_RUNTIME"],
        global?.experimental?.security_auto_extension_runtime,
      ),
    }
    return result
  })

  /**
   * Is the executable-code trust boundary active? Resolved on its own because the loaders that need
   * it run during instance initialisation, long before any session or gate options exist.
   */
  export const codeEnabled = Effect.fn("SecurityFlag.codeEnabled")(function* (
    config: Pick<Config.Interface, "getGlobal">,
  ) {
    if (!(yield* enabled(config))) return false
    const global = yield* config.getGlobal().pipe(Effect.catch(() => Effect.succeed(undefined)))
    return layer(process.env["KILO_SECURITY_AUTO_CODE"], global?.experimental?.security_auto_code)
  })

  /**
   * Is the permissioned extension runtime active? Resolved on its own for the same reason
   * {@link codeEnabled} is: the loaders run long before any session or gate options exist.
   */
  export const runtimeEnabled = Effect.fn("SecurityFlag.runtimeEnabled")(function* (
    config: Pick<Config.Interface, "getGlobal">,
  ) {
    if (!(yield* enabled(config))) return false
    const global = yield* config.getGlobal().pipe(Effect.catch(() => Effect.succeed(undefined)))
    return layer(
      process.env["KILO_SECURITY_AUTO_EXTENSION_RUNTIME"],
      global?.experimental?.security_auto_extension_runtime,
    )
  })

  /**
   * Capability declarations for tools the user vouches for (`experimental.security_auto_tool_capabilities`).
   * Global config only, for the same reason the mode itself is: a repository must not be able to
   * declare capabilities for the tools it also ships.
   */
  export const declarations = Effect.fn("SecurityFlag.declarations")(function* (
    config: Pick<Config.Interface, "getGlobal">,
  ) {
    const global = yield* config.getGlobal().pipe(Effect.catch(() => Effect.succeed(undefined)))
    return ToolCapability.declarations(global?.experimental?.security_auto_tool_capabilities)
  })
}
