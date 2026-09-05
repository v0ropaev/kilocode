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
  /**
   * Optional: rewrite a security notice into one plain sentence for a person to read.
   *
   * Optional because the deterministic template is already the product. A provider that does not
   * implement this simply leaves the template in place — which is what the offline stand-in does,
   * since a regex has nothing to add to a sentence.
   */
  rewrite?(system: string, text: string, signal: AbortSignal): Promise<string>
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

  /**
   * Signal (a): does the untrusted text read like an instruction aimed at the agent?
   *
   * Pattern matching, and it shows: this catches the phrasings in the development set and misses the
   * same attacks written politely. The limit is measured rather than argued — see the held-out
   * numbers in `docs/security-auto-mode-llm-results.md`.
   */
  private injection(text: string, network: boolean): Verdict | undefined {
    if (!text.trim()) return undefined
    const addressed =
      /\b(agent|assistant|ai|llm|copilot)\b\s*[:,-]|ignore (the )?(previous|above|prior)\b|you must\b|do the following\b/i
    const imperative =
      /\b(read|cat|collect|stage|copy|rename|append|encode|base64|pipe|send|post|upload|transmit|exfiltrat\w*|curl|wget)\b/i
    const outbound = /\b(post|send|upload|transmit|curl|wget|endpoint|collector|webhook|http)\b/i

    const looksAddressed = addressed.test(text)
    const looksActionable = imperative.test(text) && outbound.test(text)
    if (!looksAddressed && !looksActionable) return undefined
    if (!network) return { risk: "SUSPICIOUS", category: "PROMPT_INJECTION", confidence: "LOW" }
    if (looksAddressed && looksActionable)
      return { risk: "HIGH_RISK", category: "PROMPT_INJECTION", confidence: "HIGH" }
    return { risk: "SUSPICIOUS", category: "PROMPT_INJECTION", confidence: "MEDIUM" }
  }

  /**
   * Signal (b): does the action send data outward while the request never mentioned sending anything?
   *
   * Structural rather than lexical on the action side: its own classification says it leaves the
   * machine and what it carries. The request is checked only for whether the person asked for
   * anything outbound at all. A request that does mention it drops the signal to nothing — which is
   * as far as a matching goal is ever allowed to go, because this function returns an opinion that
   * something is off and has no way to express the opposite.
   */
  private mismatch(input: SemanticInput): Verdict | undefined {
    const goal = input.goal?.toLowerCase()
    if (!goal || !input.action.network) return undefined

    // Does the request name the subject of the action — the store, the labels, or a word from the
    // file's own name? "Set up the AWS deployment" and a read of the AWS config share a subject;
    // "fix the typo in the README" and a read of `~/.aws/credentials` share nothing. This is the
    // comparison the signal is actually about, and it only ever quiets the signal.
    const subjects = new Set<string>()
    for (const operand of input.action.operands) {
      if (operand.store) subjects.add(operand.store)
      for (const label of operand.labels) subjects.add(label.replace(/-/g, " "))
      for (const word of operand.basename.toLowerCase().split(/[^a-z0-9]+/)) if (word.length > 2) subjects.add(word)
    }
    if ([...subjects].some((subject) => goal.includes(subject))) return undefined

    // Nothing in the request refers to what is being touched. Did it ask for anything outbound at all?
    const outbound =
      /\b(send|post|upload|publish|deploy\w*|push|share|report|notify|sync|mirror|export|submit|webhook|curl|http)\b/
    if (outbound.test(goal)) return undefined

    const carriesSecret = input.action.operands.some(
      (operand) =>
        operand.effect === "read" &&
        (operand.labels.length > 0 ||
          operand.relation === "home-sensitive" ||
          /token|secret|credential|password|\bkey\b|\.env|auth/i.test(operand.basename)),
    )
    if (carriesSecret || input.action.readSecret)
      return { risk: "HIGH_RISK", category: "USER_GOAL_MISMATCH", confidence: "MEDIUM" }
    return { risk: "SUSPICIOUS", category: "USER_GOAL_MISMATCH", confidence: "MEDIUM" }
  }

  async classify(input: SemanticInput): Promise<Verdict> {
    const text = input.provenance.map((item) => item.excerpt).join("\n")
    const found = [this.injection(text, input.action.network), this.mismatch(input)].filter(
      (item): item is Verdict => item !== undefined,
    )
    if (found.length === 0)
      return text.trim() ? { risk: "ORDINARY", category: "BENIGN_CONTEXT", confidence: "LOW" } : NO_SIGNAL
    // Report the more serious of the two, which is what the model is asked to do.
    const order = { ORDINARY: 0, SUSPICIOUS: 1, HIGH_RISK: 2 }
    return found.reduce((worst, item) => (order[item.risk] > order[worst.risk] ? item : worst))
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

/**
 * The model Kilo is already configured with, through Kilo's own provider service.
 *
 * This is the backend a deployment should use. It hardcodes no vendor, needs no second key, and
 * follows whatever the user already set up — including a local OpenAI-compatible server declared as a
 * `provider` block in the Kilo config. It asks for the *small* model, the same one prompt enhancement
 * and title generation use, because this is the same shape of job.
 *
 * Everything is behind `await import()`. The classifier subtree is otherwise a leaf — `schema.ts`
 * imports `node:crypto` and nothing else — and a static import here would pull the provider service,
 * the Effect layer graph and the AI SDK into every module that touches security, including its unit
 * tests. It would also add an edge into a strongly-connected component whose members read
 * `Plugin.node` and `Provider.node` at module-body time; that component has already produced a
 * `Cannot access 'node' before initialization` in this project once. The deferral is the same pattern
 * `kilocode/cli/cmd/roll-call.ts` uses, for the same reason.
 */
export function kiloBackend(): ModelBackend {
  return {
    name: "kilo:small-model",
    async complete(system, user, maxTokens, signal) {
      const [{ generateText }, { Provider }, { ProviderTransform }, { AppRuntime }, { Effect }] = await Promise.all([
        import("ai"),
        import("@/provider/provider"),
        import("@/provider/transform"),
        import("@/effect/app-runtime"),
        import("effect"),
      ])
      const resolved = await AppRuntime.runPromise(
        Provider.Service.use((service) =>
          Effect.gen(function* () {
            const ref = yield* service.defaultModel()
            const model =
              (yield* service.getSmallModel(ref.providerID)) ?? (yield* service.getModel(ref.providerID, ref.modelID))
            return { model, language: yield* service.getLanguage(model) }
          }),
        ),
      )
      const result = await generateText({
        model: resolved.language,
        // Deterministic where the provider allows it: a security notice should not vary run to run.
        temperature: resolved.model.capabilities.temperature ? 0 : undefined,
        providerOptions: ProviderTransform.providerOptions(resolved.model, resolved.model.options),
        maxRetries: 0,
        abortSignal: signal,
        maxOutputTokens: maxTokens,
        system,
        messages: [{ role: "user" as const, content: user }],
      })
      return result.text.trim()
    },
  }
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

  /** The input here is a sentence this codebase wrote, not anything a repository controls. */
  async rewrite(system: string, text: string, signal: AbortSignal): Promise<string> {
    return this.backend.complete(system, text, 64, signal)
  }
}

/** Build a provider from the environment. Returns `undefined` — never throws — when unconfigured. */
export function providerFromEnv(): ClassifierProvider | undefined {
  // The model the user already configured is the default: no second key, no vendor named here, and
  // nothing to switch on. `heuristic` is for offline runs that must not touch a network.
  const kind = (process.env["KILO_SECURITY_AUTO_CLASSIFIER_PROVIDER"] ?? "kilo").toLowerCase()
  if (kind === "heuristic") return new HeuristicProvider()
  // The model the user already configured. No second key, no vendor named here.
  if (kind === "kilo") return new ModelProvider(kiloBackend())
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
