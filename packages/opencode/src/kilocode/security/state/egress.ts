import { evidence as makeEvidence } from "../decision"
import { PathRisk } from "../path"
import { SecurityRules } from "../rules"
import { ShellNormalizer } from "../shell"
import type { NormalizedAction, NormalizedCommand, NormalizedProcess, SecurityEvidence } from "../types"
import { SecuritySessionState } from "./store"
import { SecretValues } from "./values"

/**
 * Stateful sensitive-read → outbound-egress guard.
 *
 * The layer produces two things from an already-normalised action:
 * - `pending`: the sensitive resources this action would obtain and the files it would taint, recorded
 *   against the tool call and committed only when the call actually succeeds (so a name in a denied or
 *   refused request never becomes "secret context");
 * - `evidence`: for outbound actions, whether the session's secret context makes them exfiltration.
 *
 * It is deliberately not a taint engine. Propagation is limited to controlled built-in flows visible
 * in one command (a copy/move/redirect from a sensitive or already-tainted source, or a literal
 * secret value on the command line). Opaque subprocesses are out of reach by design; the sandbox's
 * restricted egress remains the stronger control for those.
 *
 * Decision shape (monotonic, folded into the engine so it can only tighten):
 * - no secret context, ordinary destination → no evidence (the deterministic network policy stands);
 * - sensitive read + local computation → state only, no evidence;
 * - a command that both reads a secret and performs an outbound action, an outbound action that reads
 *   a tainted/sensitive file, or a literal secret value on an outbound command line → DENY;
 * - an outbound action while the session holds secret context, with no deterministic data link → hard ASK.
 * Intent is not inferred: an agent-initiated and a user-requested exfiltration are treated the same.
 */
export namespace EgressGuard {
  type Label = SecuritySessionState.Label

  export interface Assessment {
    evidence: SecurityEvidence[]
    pending: SecuritySessionState.Pending
  }

  const EMPTY: SecuritySessionState.Pending = { reads: [], taints: [], untaints: [] }

  function sensitive(labels: Label[], relation: string): boolean {
    return labels.length > 0 || relation === "home-sensitive" || relation === "kilo-security"
  }

  /** Outbound-capable process: a network command to any destination (loopback included), or `git push`. */
  function outbound(process: NormalizedProcess): boolean {
    if (process.git) return process.git.subcommand === "push"
    if (process.pkg || process.family === "container") return false
    return process.network === true && process.metadata !== true
  }

  /** Tokens on an outbound command line that could carry a secret value. */
  function carriedTokens(process: NormalizedProcess): string[] {
    const out = new Set<string>()
    for (const arg of process.argv) for (const token of SecretValues.tokens(arg)) out.add(token)
    return [...out]
  }

  interface ReadInfo {
    canonical: string
    labels: Label[]
    relation: string
  }

  /** Sensitive read operands of a process (effect read/exec on a credential/secret/private-key path). */
  function sensitiveReads(process: NormalizedProcess): ReadInfo[] {
    const out: ReadInfo[] = []
    for (const operand of process.operands) {
      if (operand.effect !== "read" && operand.effect !== "exec") continue
      const labels = SecuritySessionState.labelsFor(operand.path)
      if (sensitive(labels, operand.path.relation)) {
        out.push({ canonical: operand.path.canonical, labels, relation: operand.path.relation })
      }
    }
    return out
  }

  function assessShell(command: NormalizedCommand, sessionID: string): Assessment {
    const processes = ShellNormalizer.flatten(command)
    const reads: SecuritySessionState.Pending["reads"] = []
    const taints: SecuritySessionState.Pending["taints"] = []
    const evidence: SecurityEvidence[] = []

    // 1. Sensitive reads anywhere in the command.
    let structuralLabels: Label[] = []
    for (const process of processes) {
      for (const read of sensitiveReads(process)) {
        reads.push({ canonical: read.canonical, labels: read.labels, relation: read.relation as never })
        structuralLabels = [...new Set([...structuralLabels, ...read.labels])]
      }
    }
    const structuralSecret = reads.length > 0

    // 2. Controlled propagation: a writer/redirect whose source is a sensitive or session-tainted file,
    //    or whose command line carries a literal secret value, taints its destination.
    for (const process of processes) {
      const readOperands = process.operands.filter((operand) => operand.effect === "read" || operand.effect === "exec")
      const writeOperands = process.operands.filter(
        (operand) => operand.effect === "write" || operand.effect === "delete",
      )
      const sourceLabels = new Set<Label>()
      for (const operand of readOperands) {
        for (const label of SecuritySessionState.labelsFor(operand.path)) sourceLabels.add(label)
        const taint = SecuritySessionState.taintOf(sessionID, operand.path.canonical)
        if (taint) for (const label of taint.labels) sourceLabels.add(label)
      }
      if (SecuritySessionState.matches(sessionID, carriedTokens(process))) sourceLabels.add("secret")
      if (sourceLabels.size > 0) {
        for (const operand of writeOperands) {
          if (operand.path.relation === "unknown") continue
          taints.push({ canonical: operand.path.canonical, labels: [...sourceLabels], via: "copy" })
        }
      }
    }
    // Redirect targets receiving a sensitive/tainted read (`cat secret > dest`, `secret | tee dest`).
    for (const redirect of command.redirects) {
      if (redirect.effect !== "write" || !redirect.path || redirect.path.relation === "unknown") continue
      if (redirect.command === undefined) continue
      const owner = command.commands[redirect.command]
      if (!owner) continue
      const labels = new Set<Label>()
      for (const operand of owner.operands) {
        if (operand.effect !== "read" && operand.effect !== "exec") continue
        for (const label of SecuritySessionState.labelsFor(operand.path)) labels.add(label)
        const taint = SecuritySessionState.taintOf(sessionID, operand.path.canonical)
        if (taint) for (const label of taint.labels) labels.add(label)
      }
      if (SecuritySessionState.matches(sessionID, carriedTokens(owner))) labels.add("secret")
      if (labels.size > 0) taints.push({ canonical: redirect.path.canonical, labels: [...labels], via: "redirect" })
    }

    // 3. Outbound actions: is any of them carrying secret material?
    const sessionSecret = SecuritySessionState.hasSecretContext(sessionID)
    for (const process of processes) {
      if (!outbound(process)) continue
      const destinationLabel = process.git
        ? "git push"
        : SecurityRules.local(process.argv)
          ? "a local endpoint"
          : "the network"
      // Deterministic data link → the strongest reason: refuse.
      const readsTainted = process.operands.some((operand) => {
        if (operand.effect !== "read" && operand.effect !== "exec") return false
        if (sensitive(SecuritySessionState.labelsFor(operand.path), operand.path.relation)) return true
        return SecuritySessionState.taintOf(sessionID, operand.path.canonical) !== undefined
      })
      const valueOnLine = SecuritySessionState.matches(sessionID, carriedTokens(process))
      if (structuralSecret || readsTainted || valueOnLine) {
        const reason = structuralSecret
          ? "reads a credential in the same command and sends data out"
          : valueOnLine
            ? "puts a credential value read earlier in this session onto the command line"
            : "uploads a file that received credential material earlier in this session"
        evidence.push(
          makeEvidence({
            rule: valueOnLine
              ? "hard.egress.secret-value"
              : readsTainted && !structuralSecret
                ? "hard.egress.tainted-file"
                : "hard.egress.read-and-send",
            source: "hard",
            action: "deny",
            reasonCode: "SECRET_EXFILTRATION",
            message: `The outbound command ${reason}; it would send it to ${destinationLabel}.`,
            attributes: { destination: destinationLabel },
          }),
        )
        SecuritySessionState.note(sessionID, { at: Date.now(), kind: "egress-denied", rule: "hard.egress" })
        continue
      }
      if (sessionSecret) {
        evidence.push(
          makeEvidence({
            rule: "hard.egress.secret-context",
            source: "hard",
            action: "ask",
            reasonCode: "SECRET_EXFILTRATION",
            message: `Credential material was read earlier in this session; an outbound action to ${destinationLabel} needs confirmation.`,
            attributes: { destination: destinationLabel },
          }),
        )
        SecuritySessionState.note(sessionID, {
          at: Date.now(),
          kind: "egress-asked",
          rule: "hard.egress.secret-context",
        })
      }
    }

    return { evidence, pending: { reads, taints, untaints: [] } }
  }

  function assessFile(action: Extract<NormalizedAction, { kind: "file" }>, _sessionID: string): Assessment {
    if (action.effect !== "read") return { evidence: [], pending: EMPTY }
    const reads: SecuritySessionState.Pending["reads"] = []
    for (const target of action.paths) {
      const labels = SecuritySessionState.labelsFor(target)
      if (sensitive(labels, target.relation)) {
        reads.push({ canonical: target.canonical, labels, relation: target.relation })
      }
    }
    return { evidence: [], pending: { reads, taints: [], untaints: [] } }
  }

  /** Assess one action against the session's secret state. Pure: it reads state, never mutates it. */
  export function assess(input: { action: NormalizedAction; sessionID: string }): Assessment {
    if (input.action.kind === "shell") return assessShell(input.action.command, input.sessionID)
    if (input.action.kind === "file") return assessFile(input.action, input.sessionID)
    return { evidence: [], pending: EMPTY }
  }

  /** Convenience for tests: does a session hold secret context? */
  export function hasSecretContext(sessionID: string) {
    return SecuritySessionState.hasSecretContext(sessionID)
  }

  export function labelsFor(target: Parameters<typeof PathRisk.sensitive>[0]) {
    return SecuritySessionState.labelsFor(target)
  }
}
