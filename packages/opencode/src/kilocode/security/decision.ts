import type { SafeAlternative, SecurityAction, SecurityDecision, SecurityEvidence, SecurityReasonCode } from "./types"

const severity: Record<SecurityAction, number> = { allow: 0, ask: 1, deny: 2 }

/** Monotonic reducer: DENY > ASK > ALLOW. A weaker action never relaxes a stronger one. */
export function stricter(a: SecurityAction, b: SecurityAction): SecurityAction {
  return severity[a] >= severity[b] ? a : b
}

export function rank(action: SecurityAction) {
  return severity[action]
}

const guidance: Record<SecurityReasonCode, string> = {
  SAFE_READ: "",
  SAFE_WORKSPACE_ACTION: "",
  SAFE_COMMAND: "",
  PROTECTED_PATH: "The path is protected configuration. The user must confirm changes to it.",
  DESTRUCTIVE_FILESYSTEM:
    "The operation would recursively delete or overwrite a protected location. Narrow the target to files inside the workspace, or ask the user to perform this step manually.",
  DESTRUCTIVE_DEVICE:
    "Block devices and filesystems are never formatted or overwritten automatically. Ask the user to run this manually if it is really required.",
  DESTRUCTIVE_GIT:
    "This git operation discards history or working changes. Explain the intent and let the user confirm it.",
  PRIVILEGE_ESCALATION:
    "Privilege escalation is not available to the agent. Complete the task without elevated rights, or ask the user to run the privileged step.",
  UNKNOWN_SHELL_SYNTAX:
    "The command could not be fully parsed. Rewrite it as simple, explicit commands without unusual syntax.",
  SHELL_INDIRECTION:
    "The command builds or evaluates shell code dynamically. Run the intended commands directly and explicitly instead.",
  ENCODED_EXECUTION: "Executing encoded or decoded payloads is not permitted. Write the commands in plain text.",
  REMOTE_EXECUTION:
    "Piping downloaded content into a shell is not permitted. Download to a workspace file, inspect it, then run it explicitly.",
  INTERPRETER_INDIRECTION:
    "Inline interpreter code cannot be verified. Put the code in a workspace file and run that file.",
  DYNAMIC_TARGET: "The target of a destructive operation is computed at runtime. Use explicit, literal paths.",
  SENSITIVE_READ: "The path holds credentials or private key material and cannot be read by the agent.",
  SENSITIVE_WRITE:
    "The path holds credentials or security-sensitive configuration and cannot be modified by the agent.",
  SHELL_PERSISTENCE:
    "Shell startup files and scheduled tasks are not modified automatically. Suggest the change to the user instead.",
  SYSTEM_MODIFICATION: "System-level changes are not performed automatically. Ask the user to run this step.",
  EXTERNAL_PATH: "The path is outside the workspace and needs approval.",
  NETWORK_EGRESS: "Outbound network access needs approval.",
  PACKAGE_INSTALL: "Installing new packages needs approval.",
  PACKAGE_PUBLISH: "Publishing packages needs explicit approval.",
  PACKAGE_PROVENANCE:
    "The package's provenance looks suspicious (new, unadopted, look-alike name, missing repository, or an unexpected registry or source). Prefer an established package, or ask the user to confirm this exact dependency.",
  PACKAGE_UNVERIFIED:
    "The package could not be verified against the registry. Check the exact package name with the user before installing.",
  PACKAGE_LIFECYCLE:
    "Installing this package would run its install-time scripts, and the package is not established enough to trust them. Ask the user to review the package, or install with scripts disabled.",
  SECRET_EXFILTRATION:
    "The outbound action would carry credential material that was read earlier in this session. Do not send credentials anywhere; continue the task without transmitting them.",
  POLICY_TAMPERING: "Security policy, permission state and sandbox state cannot be modified by the agent.",
  SANDBOX_ESCALATION: "Leaving the sandbox needs explicit interactive approval.",
  UNCLASSIFIED_ACTION: "The action could not be classified. The configured permission rules decide.",
  SECURITY_ENGINE_ERROR: "The security check could not complete, so the action needs manual approval.",
}

const alternatives: Partial<Record<SecurityReasonCode, string[]>> = {
  DESTRUCTIVE_FILESYSTEM: [
    "Delete only specific files or directories inside the workspace.",
    "Ask the user to remove the protected location manually.",
  ],
  DESTRUCTIVE_DEVICE: ["Ask the user to perform disk operations outside the agent session."],
  PRIVILEGE_ESCALATION: [
    "Run the command without sudo if the task allows it.",
    "Ask the user to run the privileged command manually.",
  ],
  UNKNOWN_SHELL_SYNTAX: ["Split the work into simple commands with literal arguments."],
  SHELL_INDIRECTION: ["Run each intended command directly instead of through bash -c, eval or a piped shell."],
  ENCODED_EXECUTION: ["Write the commands in plain text."],
  REMOTE_EXECUTION: ["Download the script into the workspace, read it, then run it explicitly."],
  INTERPRETER_INDIRECTION: ["Write the code to a workspace file and execute that file."],
  DYNAMIC_TARGET: ["Use literal paths for destructive operations."],
  SENSITIVE_READ: ["Ask the user for the specific value you need instead of reading the credential store."],
  SENSITIVE_WRITE: ["Describe the required change and let the user apply it."],
  SHELL_PERSISTENCE: ["Print the snippet the user should add to their shell profile."],
  SYSTEM_MODIFICATION: ["Explain the required system change and let the user apply it."],
  POLICY_TAMPERING: ["Security settings can only be changed by the user through the Kilo UI or config."],
  PACKAGE_PROVENANCE: [
    "Use an established package that provides the same functionality.",
    "Ask the user to confirm the exact package name, version and registry.",
  ],
  PACKAGE_UNVERIFIED: ["Ask the user for the exact package name; do not guess dependency names."],
  PACKAGE_LIFECYCLE: [
    "Ask the user to review the package before installing it.",
    "Install with install scripts disabled (`--ignore-scripts`) if the package does not need them.",
  ],
  SECRET_EXFILTRATION: [
    "Complete the task without sending the credential; describe what the user should do with it instead.",
    "Send only non-sensitive data, from a file that never received credential contents.",
  ],
}

/** Reduce collected evidence into a decision. The strictest action wins; ties prefer hard evidence. */
export function reduce(evidence: SecurityEvidence[], fallback: SecurityEvidence): SecurityDecision {
  const list = evidence.length > 0 ? evidence : [fallback]
  const action = list.reduce((acc, item) => stricter(acc, item.action), "allow" as SecurityAction)
  const winners = list.filter((item) => item.action === action)
  const lead = winners.find((item) => item.source === "hard") ?? winners[0] ?? fallback
  return {
    action,
    hard: action === "deny" || (action === "ask" && winners.some((item) => item.source === "hard")),
    reasonCode: lead.reasonCode,
    message: lead.message,
    guidance: guidance[lead.reasonCode],
    canRetry: action !== "allow",
    evidence: list,
    alternatives: (alternatives[lead.reasonCode] ?? []).map((description): SafeAlternative => ({ description })),
  }
}

/** Fail safe: a security layer failure is a hard ASK, never a silent ALLOW. */
export function failure(err: unknown): SecurityDecision {
  const name = err instanceof Error ? err.name : "Error"
  return reduce([], {
    rule: "engine.failure",
    source: "hard",
    action: "ask",
    reasonCode: "SECURITY_ENGINE_ERROR",
    message: "The security check could not be completed.",
    attributes: { error: name },
  })
}

export function evidence(input: {
  rule: string
  source: SecurityEvidence["source"]
  action: SecurityAction
  reasonCode: SecurityReasonCode
  message: string
  attributes?: Record<string, string | number | boolean>
}): SecurityEvidence {
  return input
}

export * as Decision from "./decision"
