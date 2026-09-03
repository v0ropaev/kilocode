import { Decision } from "./decision"
import { SecurityRules } from "./rules"
import type { NormalizedAction, SecurityContext, SecurityDecision } from "./types"

/**
 * The central security engine: pure, deterministic, side-effect free.
 *
 * It receives an already normalised action plus the session context, applies the immutable hard
 * rules and the default policy, and reduces the evidence monotonically (DENY > ASK > ALLOW).
 * Any internal failure is a hard ASK, never a silent ALLOW.
 */
export namespace SecurityEngine {
  export function evaluate(action: NormalizedAction, ctx: SecurityContext): SecurityDecision {
    try {
      const list = SecurityRules.evaluate(action, ctx)
      return Decision.reduce(list, {
        rule: "engine.default",
        source: "default",
        action: "ask",
        reasonCode: "UNCLASSIFIED_ACTION",
        message: "The action could not be classified.",
      })
    } catch (err) {
      return Decision.failure(err)
    }
  }
}
