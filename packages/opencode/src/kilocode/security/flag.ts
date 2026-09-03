import { Effect } from "effect"
import { Config } from "@/config/config"

/**
 * Security Auto Mode is off by default. It is enabled from user-owned state only: the global Kilo
 * config (`experimental.security_auto: true`) or the `KILO_SECURITY_AUTO` environment variable.
 * Project config is deliberately ignored so a repository cannot turn the mode on or off, and the
 * global config directory is itself protected from agent writes by the engine's hard rules.
 */
export namespace SecurityFlag {
  function truthy(value: string | undefined) {
    return value === "1" || value === "true"
  }

  export const enabled = Effect.fn("SecurityFlag.enabled")(function* (config: Pick<Config.Interface, "getGlobal">) {
    if (truthy(process.env["KILO_SECURITY_AUTO"])) return true
    if (process.env["KILO_SECURITY_AUTO"] === "0" || process.env["KILO_SECURITY_AUTO"] === "false") return false
    const global = yield* config.getGlobal().pipe(Effect.catch(() => Effect.succeed(undefined)))
    return global?.experimental?.security_auto === true
  })
}
