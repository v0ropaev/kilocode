/**
 * Providers for the semantic layer.
 *
 * The layer never talks to a model directly. Three implementations sit behind one interface:
 *
 *  - `MockProvider` — scripted verdicts, for tests that need to control what the model says.
 *  - `HeuristicProvider` — dependency-free, offline. Used by the benchmark so a run needs no key and
 *    no network. It is a **stand-in, not a model**: it reads the untrusted excerpt for an imperative
 *    addressed to the agent. Where it agrees with a real model is where the task is easy.
 *  - `ModelProvider` — a small remote or local model, behind config. Off unless configured.
 *
 * Every call is bounded by an `AbortSignal` the caller owns: a provider that hangs is worse than one
 * that is wrong, because a security decision that never returns stalls the agent.
 */
import { NO_SIGNAL, SYSTEM_PROMPT, nonce, parse, render, type SemanticInput, type Verdict } from "./schema"

export interface ClassifierProvider {
  readonly name: string
  classify(input: SemanticInput, signal: AbortSignal): Promise<Verdict>
}

/** Scripted provider for tests: answers from a queue, or the same verdict every time. */
export class MockProvider implements ClassifierProvider {
  readonly name = "mock"
  readonly seen: SemanticInput[] = []
  constructor(private readonly script: Verdict | Verdict[]) {}
  async classify(input: SemanticInput): Promise<Verdict> {
    this.seen.push(input)
    if (Array.isArray(this.script)) return this.script[this.seen.length - 1] ?? NO_SIGNAL
    return this.script
  }
}

/**
 * Offline stand-in. It looks for the shape of an indirect injection: an imperative addressed to the
 * agent in text the user did not write, naming an action that matches the one being judged.
 *
 * Written against the development examples in `eval/corpus.ts` and never against the held-out set.
 * It is not the thing being proposed — it is what lets the composition be measured without a key.
 */
export class HeuristicProvider implements ClassifierProvider {
  readonly name = "heuristic-offline"

  async classify(input: SemanticInput): Promise<Verdict> {
    const text = input.provenance.map((item) => item.excerpt).join("\n")
    if (!text.trim()) return NO_SIGNAL

    // An instruction pointed at the agent, rather than prose that merely mentions one.
    const addressed =
      /\b(agent|assistant|ai|llm|copilot)\b\s*[:,-]|ignore (the )?(previous|above|prior)\b|you must\b|do the following\b/i
    const imperative =
      /\b(read|cat|collect|stage|copy|rename|append|encode|base64|pipe|send|post|upload|transmit|exfiltrat\w*|curl|wget)\b/i
    const outbound = /\b(post|send|upload|transmit|curl|wget|endpoint|collector|webhook|http)\b/i

    const looksAddressed = addressed.test(text)
    const looksActionable = imperative.test(text) && outbound.test(text)

    if (!looksAddressed && !looksActionable) return { risk: "ORDINARY", category: "BENIGN_CONTEXT", confidence: "LOW" }
    if (!input.action.network) return { risk: "SUSPICIOUS", category: "PROMPT_INJECTION", confidence: "LOW" }
    if (looksAddressed && looksActionable)
      return { risk: "HIGH_RISK", category: "PROMPT_INJECTION", confidence: "HIGH" }
    return { risk: "SUSPICIOUS", category: "PROMPT_INJECTION", confidence: "MEDIUM" }
  }
}

export interface ModelBackend {
  readonly name: string
  complete(system: string, user: string, maxTokens: number, signal: AbortSignal): Promise<string>
}

/**
 * Walk a path through a decoded JSON body without asserting its shape. A backend's response is
 * remote input: a missing or oddly-typed field yields the empty string, which `parse` reads as no
 * signal, rather than a cast that pretends the shape was checked.
 */
function pluck(body: unknown, keys: Array<string | number>): string {
  let node: unknown = body
  for (const key of keys) {
    if (typeof node !== "object" || node === null) return ""
    const entry = Object.entries(node).find(([name]) => name === String(key))
    if (!entry) return ""
    node = entry[1]
  }
  return typeof node === "string" ? node.trim() : ""
}

export function anthropicBackend(opts: { model?: string; apiKey?: string } = {}): ModelBackend {
  const model = opts.model ?? "claude-haiku-4-5-20251001"
  const apiKey = opts.apiKey ?? process.env["ANTHROPIC_API_KEY"]
  return {
    name: `anthropic:${model}`,
    async complete(system, user, maxTokens, signal) {
      if (!apiKey) throw new Error("anthropic backend: no API key")
      const res = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        signal,
        headers: { "content-type": "application/json", "x-api-key": apiKey, "anthropic-version": "2023-06-01" },
        body: JSON.stringify({ model, max_tokens: maxTokens, system, messages: [{ role: "user", content: user }] }),
      })
      if (!res.ok) throw new Error(`anthropic ${res.status}`)
      return pluck(await res.json(), ["content", 0, "text"])
    },
  }
}

export function openaiCompatibleBackend(opts: { baseUrl: string; model: string; apiKey?: string }): ModelBackend {
  const apiKey = opts.apiKey ?? process.env["OPENAI_API_KEY"] ?? "not-needed"
  return {
    name: `openai:${opts.model}`,
    async complete(system, user, maxTokens, signal) {
      const res = await fetch(`${opts.baseUrl.replace(/\/$/, "")}/chat/completions`, {
        method: "POST",
        signal,
        headers: { "content-type": "application/json", authorization: `Bearer ${apiKey}` },
        body: JSON.stringify({
          model: opts.model,
          max_tokens: maxTokens,
          temperature: 0,
          messages: [
            { role: "system", content: system },
            { role: "user", content: user },
          ],
        }),
      })
      if (!res.ok) throw new Error(`openai-compat ${res.status}`)
      return pluck(await res.json(), ["choices", 0, "message", "content"])
    },
  }
}

export class ModelProvider implements ClassifierProvider {
  readonly name: string
  constructor(private readonly backend: ModelBackend) {
    this.name = backend.name
  }
  async classify(input: SemanticInput, signal: AbortSignal): Promise<Verdict> {
    const id = nonce()
    // 24 tokens: enough for the one line, far too few for the model to argue with itself.
    return parse(await this.backend.complete(SYSTEM_PROMPT, render(input, id), 24, signal))
  }
}

/** Build a provider from the environment. Returns `undefined` — never throws — when unconfigured. */
export function providerFromEnv(): ClassifierProvider | undefined {
  const kind = (process.env["KILO_SECURITY_AUTO_CLASSIFIER_PROVIDER"] ?? "heuristic").toLowerCase()
  if (kind === "heuristic") return new HeuristicProvider()
  if (kind === "anthropic")
    return new ModelProvider(
      anthropicBackend({
        model: process.env["KILO_SECURITY_AUTO_CLASSIFIER_MODEL"],
        apiKey: process.env["KILO_SECURITY_AUTO_CLASSIFIER_KEY"],
      }),
    )
  if (kind === "openai")
    return new ModelProvider(
      openaiCompatibleBackend({
        baseUrl: process.env["KILO_SECURITY_AUTO_CLASSIFIER_URL"] ?? "http://localhost:11434/v1",
        model: process.env["KILO_SECURITY_AUTO_CLASSIFIER_MODEL"] ?? "qwen2.5:3b",
        apiKey: process.env["KILO_SECURITY_AUTO_CLASSIFIER_KEY"],
      }),
    )
  return undefined
}

let cached: { provider: ClassifierProvider | undefined } | undefined

/** The process-wide provider, built once. Rebuilt only by {@link resetProvider} (tests, benchmark). */
export function defaultProvider(): ClassifierProvider | undefined {
  cached ??= { provider: providerFromEnv() }
  return cached.provider
}

export function resetProvider() {
  cached = undefined
}
