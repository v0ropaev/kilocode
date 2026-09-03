import { Effect } from "effect"
import { Config } from "@/config/config"

/**
 * Security Auto Mode is off by default. It is enabled from user-owned state only: the global Kilo
 * config (`experimental.security_auto: true`) or the `KILO_SECURITY_AUTO` environment variable.
 * Project config is deliberately ignored so a repository cannot turn the mode on or off, and the
 * global config directory is itself protected from agent writes by the engine's hard rules.
 *
 * The v2 layers (package provenance preflight, stateful secret-egress protection) follow the same
 * rule: on by default whenever the mode is on, switchable off individually from the global config
 * (`experimental.security_auto_packages`, `experimental.security_auto_egress`) or the environment
 * (`KILO_SECURITY_AUTO_PACKAGES`, `KILO_SECURITY_AUTO_EGRESS`). They are never read from a project.
 */
export namespace SecurityFlag {
  export interface Layers {
    /** Pre-install package provenance / lifecycle preflight. */
    packages: boolean
    /** Stateful sensitive-read → outbound-egress protection. */
    egress: boolean
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

  /** Which v2 layers are active. Meaningful only when {@link enabled} is true. */
  export const layers = Effect.fn("SecurityFlag.layers")(function* (config: Pick<Config.Interface, "getGlobal">) {
    const global = yield* config.getGlobal().pipe(Effect.catch(() => Effect.succeed(undefined)))
    const result: Layers = {
      packages: layer(process.env["KILO_SECURITY_AUTO_PACKAGES"], global?.experimental?.security_auto_packages),
      egress: layer(process.env["KILO_SECURITY_AUTO_EGRESS"], global?.experimental?.security_auto_egress),
    }
    return result
  })
}
