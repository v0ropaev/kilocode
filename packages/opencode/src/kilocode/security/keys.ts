/**
 * Permission request metadata keys used by Security Auto Mode. Kept dependency-free so the shared
 * permission service can reference them without importing the engine.
 */
export namespace SecurityKeys {
  /** Set on a request when the engine requires an interactive human reply (hard ASK). */
  export const ASK = "securityAsk" as const
  /** Decision summary attached to requests and tool metadata (never contains secrets). */
  export const META = "security" as const
  /** Set on envelope asks issued by the execution gate for tools without their own permission ask. */
  export const ENVELOPE = "securityEnvelope" as const
}
