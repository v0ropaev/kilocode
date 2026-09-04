/**
 * LLM classifier — provider abstraction.
 *
 * The two LLM layers (Context Checker, Action Classifier) never talk to a model
 * directly; they talk to a `ClassifierProvider`. This keeps the layers testable
 * offline and lets a real remote/local model drop in behind the same interface.
 *
 * Two implementations:
 *  - `HeuristicProvider`: dependency-free, deterministic stand-in used for the
 *    offline benchmark (no network, no API key). It is a *lower bound* on what a
 *    real model does: it only fires on fairly explicit signals, so its detection
 *    rate under-states a real LLM (which reads "exfiltrate the SSH key" trivially).
 *  - `ModelProvider`: calls a small fast model. Stubbed here (throws without a
 *    key) so the interface and wiring exist; the real call is a follow-up.
 */

export interface ContextVerdict {
  /** The untrusted content looks like it is trying to instruct the agent. */
  suspicious: boolean
  categories: Array<"exfil-instruction" | "destructive-instruction" | "policy-tamper" | "injection-preamble">
  confidence: number
}

export interface IntentVerdict {
  /** The action is within what the user actually asked for. */
  matchesIntent: boolean
  confidence: number
}

export interface ContextInput {
  source: "readme" | "skill" | "docstring" | "web" | "mcp" | "config" | "tool-result"
  content: string
}

export interface ActionInput {
  /** Trusted intent: the user's own request. */
  userRequest: string
  /** Normalized action, human-readable (executable + effect + target). No raw tool output. */
  action: string
  sessionFacts: { readSecret: boolean; sawSuspiciousContent: boolean }
}

export interface ClassifierProvider {
  readonly name: string
  checkContext(input: ContextInput): Promise<ContextVerdict>
  classifyAction(input: ActionInput): Promise<IntentVerdict>
}

/** Deterministic, offline stand-in for a model. Conservative by design. */
export class HeuristicProvider implements ClassifierProvider {
  readonly name = "heuristic-offline"

  async checkContext(input: ContextInput): Promise<ContextVerdict> {
    const text = input.content
    const categories: ContextVerdict["categories"] = []

    // Imperative addressed to the agent ("AGENT:", "ignore previous instructions", "you must").
    const preamble = /\b(agent|assistant|ai)\s*[:,-]|ignore (the )?(previous|above|prior) (instructions|prompt)|you must|do the following/i
    if (preamble.test(text)) categories.push("injection-preamble")

    // Exfiltration: a verb that sends data + a sensitive target nearby.
    const sendVerb = /\b(post|send|upload|exfiltrat\w*|curl|wget|fetch|transmit|leak|share)\b/i
    const secretTarget = /(\.env|\.ssh|\.aws|id_rsa|id_ed25519|credential|token|secret|api[_-]?key|password|\.npmrc|kube|docker\s*config)/i
    if (sendVerb.test(text) && secretTarget.test(text)) categories.push("exfil-instruction")
    // "read X and (post|send) it" pattern even if target is generic.
    if (/\bread\b[^.]{0,60}\b(and|then)\b[^.]{0,40}\b(post|send|upload|curl|wget|http)/i.test(text))
      categories.push("exfil-instruction")

    // Destructive instruction.
    if (/\b(rm\s+-rf|delete (all|the)|drop table|force[- ]?push|reset --hard|mkfs|dd if=)/i.test(text))
      categories.push("destructive-instruction")

    // Policy / config tampering.
    if (/\b(disable|turn off|bypass) (the )?(security|permission|sandbox|guard|policy)|--dangerously/i.test(text))
      categories.push("policy-tamper")

    const uniq = [...new Set(categories)]
    const suspicious = uniq.length > 0
    // Confidence scales with how many independent signals fired.
    const confidence = Math.min(1, 0.55 + 0.15 * uniq.length)
    return { suspicious, categories: uniq, confidence }
  }

  async classifyAction(input: ActionInput): Promise<IntentVerdict> {
    const req = input.userRequest.toLowerCase()
    const action = input.action.toLowerCase()

    // Extract the salient target/effect words from the action.
    const dangerous = /(delete|remove|rm |force|reset --hard|drop |exfil|curl|post|upload|\.ssh|\.aws|\.env|credential|secret|token)/
    const isDangerous = dangerous.test(action)

    if (!isDangerous) return { matchesIntent: true, confidence: 0.9 }

    // Dangerous action: does the user's request explicitly authorize this target/effect?
    // Pull the concrete nouns from the action and check the request mentions them.
    const targets = ["ssh", "id_rsa", "aws", ".env", "credential", "secret", "token", "database", "branch", "remote", "force", "delete", "remove", "push"]
    const named = targets.filter((t) => action.includes(t))
    const authorized = named.some((t) => req.includes(t))

    // Session context tightens the judgement: a secret was read + this action sends data out.
    const exfilShaped = input.sessionFacts.readSecret && /(curl|post|upload|send|http|wget)/.test(action)

    if (exfilShaped && !authorized) return { matchesIntent: false, confidence: 0.85 }
    if (isDangerous && !authorized) return { matchesIntent: false, confidence: 0.7 }
    return { matchesIntent: true, confidence: 0.75 }
  }
}

/** Placeholder for a real small/fast model. Same interface; wired but not runnable without a key. */
export class ModelProvider implements ClassifierProvider {
  readonly name = "remote-model"
  constructor(private readonly opts: { model: string; apiKeyEnv?: string } = { model: "claude-haiku-4-5-20251001" }) {}
  private key(): string {
    const k = this.opts.apiKeyEnv ? process.env[this.opts.apiKeyEnv] : process.env.ANTHROPIC_API_KEY
    if (!k) throw new Error("ModelProvider: no API key in env; use HeuristicProvider offline")
    return k
  }
  async checkContext(_input: ContextInput): Promise<ContextVerdict> {
    this.key()
    throw new Error("ModelProvider.checkContext: real model call not implemented in this prototype")
  }
  async classifyAction(_input: ActionInput): Promise<IntentVerdict> {
    this.key()
    throw new Error("ModelProvider.classifyAction: real model call not implemented in this prototype")
  }
}
