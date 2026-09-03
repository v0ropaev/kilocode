import { createHash, randomBytes } from "crypto"
import type { NormalizedPath, PathRelation } from "../types"
import { SecretValues } from "./values"

/**
 * Per-session security state for the stateful secret → egress layer.
 *
 * What is tracked, and only this:
 * - sensitive resources the agent *obtained* (a read that executed), by path fingerprint and label —
 *   a name that was merely mentioned in a denied or rejected request is never recorded;
 * - files that received sensitive contents through a controlled built-in flow (copy, move, redirect,
 *   pipeline, a write whose content carries a tracked value), so a later upload of that file is
 *   recognised;
 * - salted digests of value-like tokens read from those resources — never the values;
 * - a short ring of security events (kinds and rule ids only).
 *
 * Observations are recorded as *pending* against the tool call that asked, and committed only when
 * that call completes successfully (the content was really obtained), or discarded when it was
 * refused. State is keyed by the root session so a sub-agent's read is visible to its parent, and is
 * never shared between unrelated sessions. Nothing here is persisted or logged.
 */
export namespace SecuritySessionState {
  export type Label = "credential" | "private-key" | "secret" | "token" | "production-config"

  export type TaintVia = "copy" | "move" | "redirect" | "pipeline" | "write-content"

  export interface Read {
    fingerprint: string
    labels: Label[]
    relation: PathRelation
    at: number
  }

  export interface Taint {
    labels: Label[]
    via: TaintVia
    at: number
  }

  export interface Event {
    at: number
    kind: "sensitive-read" | "taint" | "untaint" | "egress-denied" | "egress-asked" | "discard" | "reset"
    labels?: Label[]
    rule?: string
    via?: TaintVia
  }

  export interface Pending {
    reads: { canonical: string; labels: Label[]; relation: PathRelation }[]
    taints: { canonical: string; labels: Label[]; via: TaintVia }[]
    untaints: string[]
  }

  interface State {
    root: string
    salt: string
    createdAt: number
    updatedAt: number
    reads: Read[]
    tainted: Map<string, Taint>
    values: Set<string>
    events: Event[]
    pending: Map<string, Pending & { at: number }>
  }

  export interface Snapshot {
    root: string
    reads: number
    tainted: number
    values: number
    labels: Label[]
    pending: number
    events: Event[]
  }

  const MAX_SESSIONS = 512
  const TTL_MS = 12 * 60 * 60_000
  const MAX_EVENTS = 64
  const MAX_READS = 256
  const MAX_TAINTED = 2048
  const MAX_VALUES = 20_000
  const MAX_PENDING = 64

  const states = new Map<string, State>()
  let resolver: (sessionID: string) => string = (sessionID) => sessionID

  /** Install the session → root-session resolver (registered by the Kilo session registry). */
  export function useRootResolver(fn: (sessionID: string) => string) {
    resolver = fn
  }

  export function rootOf(sessionID: string): string {
    try {
      return resolver(sessionID) || sessionID
    } catch {
      return sessionID
    }
  }

  export function fingerprint(canonical: string) {
    return createHash("sha256").update(canonical).digest("hex").slice(0, 16)
  }

  function sweep(now: number) {
    for (const [key, state] of states) {
      if (now - state.updatedAt > TTL_MS) states.delete(key)
    }
    while (states.size > MAX_SESSIONS) {
      const oldest = states.keys().next().value
      if (oldest === undefined) break
      states.delete(oldest)
    }
  }

  function touch(state: State, now: number) {
    state.updatedAt = now
    // Re-insert so Map iteration order doubles as LRU order.
    states.delete(state.root)
    states.set(state.root, state)
  }

  function event(state: State, item: Event) {
    state.events.push(item)
    if (state.events.length > MAX_EVENTS) state.events.splice(0, state.events.length - MAX_EVENTS)
  }

  export function get(sessionID: string): State | undefined {
    return states.get(rootOf(sessionID))
  }

  function open(sessionID: string, now = Date.now()): State {
    const root = rootOf(sessionID)
    sweep(now)
    const existing = states.get(root)
    if (existing) {
      touch(existing, now)
      return existing
    }
    const state: State = {
      root,
      salt: randomBytes(16).toString("hex"),
      createdAt: now,
      updatedAt: now,
      reads: [],
      tainted: new Map(),
      values: new Set(),
      events: [],
      pending: new Map(),
    }
    states.set(root, state)
    return state
  }

  /** Drop everything known about a session (its root). Used at session end and by tests. */
  export function reset(sessionID: string) {
    states.delete(rootOf(sessionID))
  }

  export function resetAll() {
    states.clear()
  }

  /** Labels that make a path a sensitive resource for this layer (reuses the path classification). */
  export function labelsFor(target: NormalizedPath): Label[] {
    const out = new Set<Label>()
    if (target.labels.includes("private-key")) out.add("private-key")
    if (target.labels.includes("credential")) out.add("credential")
    if (target.labels.includes("secret")) out.add("secret")
    if (target.labels.includes("kilo-state") || target.labels.includes("kilo-config")) out.add("token")
    const base = target.canonical.split(/[\\/]/).at(-1) ?? ""
    if (out.has("secret") && /\.(production|prod)(\.|$)/i.test(base)) out.add("production-config")
    return [...out]
  }

  /** True once the session obtained the contents of at least one sensitive resource. */
  export function hasSecretContext(sessionID: string): boolean {
    const state = get(sessionID)
    return state !== undefined && state.reads.length > 0
  }

  export function labelsOf(sessionID: string): Label[] {
    const state = get(sessionID)
    if (!state) return []
    return [...new Set(state.reads.flatMap((read) => read.labels))]
  }

  export function taintOf(sessionID: string, canonical: string): Taint | undefined {
    return get(sessionID)?.tainted.get(canonical)
  }

  /** Does any candidate token equal a value read from a sensitive resource in this session? */
  export function matches(sessionID: string, candidates: string[]): boolean {
    const state = get(sessionID)
    if (!state || state.values.size === 0) return false
    for (const candidate of candidates) {
      if (state.values.has(SecretValues.digest(state.salt, candidate))) return true
    }
    return false
  }

  /** Remember what a tool call *would* obtain or taint; applied by {@link commit}, dropped by {@link discard}. */
  export function recordPending(sessionID: string, callID: string, pending: Pending) {
    if (pending.reads.length === 0 && pending.taints.length === 0 && pending.untaints.length === 0) return
    const state = open(sessionID)
    const existing = state.pending.get(callID)
    if (existing) {
      existing.reads.push(...pending.reads)
      existing.taints.push(...pending.taints)
      existing.untaints.push(...pending.untaints)
      return
    }
    if (state.pending.size >= MAX_PENDING) {
      const oldest = state.pending.keys().next().value
      if (oldest !== undefined) state.pending.delete(oldest)
    }
    state.pending.set(callID, { ...pending, at: Date.now() })
  }

  /** Apply a pending observation directly (used when no tool call links the ask to an execution). */
  export function apply(sessionID: string, pending: Pending, readFile?: (canonical: string) => string | undefined) {
    const state = open(sessionID)
    const now = Date.now()
    let reads = 0
    let taints = 0
    const seen = new Set<string>()
    for (const read of pending.reads) {
      if (seen.has(read.canonical)) continue
      seen.add(read.canonical)
      const key = fingerprint(read.canonical)
      if (!state.reads.some((item) => item.fingerprint === key)) {
        state.reads.push({ fingerprint: key, labels: read.labels, relation: read.relation, at: now })
        if (state.reads.length > MAX_READS) state.reads.splice(0, state.reads.length - MAX_READS)
        event(state, { at: now, kind: "sensitive-read", labels: read.labels })
        reads += 1
      }
      const text = readFile?.(read.canonical)
      if (text !== undefined) {
        for (const value of SecretValues.extract(text)) {
          if (state.values.size >= MAX_VALUES) break
          state.values.add(SecretValues.digest(state.salt, value))
        }
      }
    }
    for (const taint of pending.taints) {
      const previous = state.tainted.get(taint.canonical)
      const labels = [...new Set([...(previous?.labels ?? []), ...taint.labels])]
      state.tainted.set(taint.canonical, { labels, via: taint.via, at: now })
      if (state.tainted.size > MAX_TAINTED) {
        const oldest = state.tainted.keys().next().value
        if (oldest !== undefined) state.tainted.delete(oldest)
      }
      event(state, { at: now, kind: "taint", labels, via: taint.via })
      taints += 1
    }
    for (const canonical of pending.untaints) {
      if (state.tainted.delete(canonical)) event(state, { at: now, kind: "untaint" })
    }
    touch(state, now)
    return { reads, taints }
  }

  /** The tool call completed: what it asked to read/taint really happened. */
  export function commit(sessionID: string, callID: string, readFile?: (canonical: string) => string | undefined) {
    const state = get(sessionID)
    const pending = state?.pending.get(callID)
    if (!state || !pending) return { reads: 0, taints: 0 }
    state.pending.delete(callID)
    return apply(sessionID, pending, readFile)
  }

  /** The tool call was refused or failed: nothing it asked for happened. */
  export function discard(sessionID: string, callID: string) {
    const state = get(sessionID)
    if (!state) return
    if (state.pending.delete(callID)) event(state, { at: Date.now(), kind: "discard" })
  }

  export function note(sessionID: string, item: Event) {
    const state = get(sessionID)
    if (!state) return
    event(state, item)
  }

  /** Counts and event kinds only — safe to log or assert on. */
  export function snapshot(sessionID: string): Snapshot | undefined {
    const state = get(sessionID)
    if (!state) return undefined
    return {
      root: state.root,
      reads: state.reads.length,
      tainted: state.tainted.size,
      values: state.values.size,
      labels: labelsOf(sessionID),
      pending: state.pending.size,
      events: [...state.events],
    }
  }

  /** Test hook: expire sessions as if `ms` had elapsed. */
  export function age(ms: number) {
    for (const state of states.values()) state.updatedAt -= ms
    sweep(Date.now())
  }

  export function size() {
    return states.size
  }
}
