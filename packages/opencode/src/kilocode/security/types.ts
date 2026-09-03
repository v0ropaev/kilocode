/**
 * Security Auto Mode: shared types.
 *
 * The security layer adjudicates side-effecting tool calls before they run. Its authority is
 * deterministic policy plus the existing sandbox; it never depends on the model recognising an
 * attack. Every decision is one of ALLOW / ASK / DENY with monotonic severity DENY > ASK > ALLOW.
 */

export type SecurityAction = "allow" | "ask" | "deny"

export type SecurityReasonCode =
  | "SAFE_READ"
  | "SAFE_WORKSPACE_ACTION"
  | "SAFE_COMMAND"
  | "PROTECTED_PATH"
  | "DESTRUCTIVE_FILESYSTEM"
  | "DESTRUCTIVE_DEVICE"
  | "DESTRUCTIVE_GIT"
  | "PRIVILEGE_ESCALATION"
  | "UNKNOWN_SHELL_SYNTAX"
  | "SHELL_INDIRECTION"
  | "ENCODED_EXECUTION"
  | "REMOTE_EXECUTION"
  | "INTERPRETER_INDIRECTION"
  | "DYNAMIC_TARGET"
  | "SENSITIVE_READ"
  | "SENSITIVE_WRITE"
  | "SHELL_PERSISTENCE"
  | "SYSTEM_MODIFICATION"
  | "EXTERNAL_PATH"
  | "NETWORK_EGRESS"
  | "PACKAGE_INSTALL"
  | "PACKAGE_PUBLISH"
  /** Package provenance is suspicious (unexpected registry, non-registry source, new / look-alike / unadopted package). */
  | "PACKAGE_PROVENANCE"
  /** The package could not be verified (registry metadata unavailable, package not found, ambiguous spec). */
  | "PACKAGE_UNVERIFIED"
  /** The install would execute install-time lifecycle scripts of an unvetted package. */
  | "PACKAGE_LIFECYCLE"
  /** An outbound action would carry credential material observed earlier in the session. */
  | "SECRET_EXFILTRATION"
  | "POLICY_TAMPERING"
  | "SANDBOX_ESCALATION"
  | "UNCLASSIFIED_ACTION"
  | "SECURITY_ENGINE_ERROR"

/** Where a resolved path lives relative to the trust boundaries of the session. */
export type PathRelation =
  | "workspace"
  | "workspace-root"
  | "workspace-config"
  | "temp"
  | "external"
  | "unknown"
  | "home"
  | "home-root"
  | "home-sensitive"
  | "system"
  | "kilo-security"
  | "root"

export type PathLabel =
  | "private-key"
  | "credential"
  | "secret"
  | "shell-persistence"
  | "git-identity"
  | "git-dir"
  | "kilo-config"
  | "kilo-state"
  | "device"
  | "glob"
  | "workspace-ancestor"

export interface NormalizedPath {
  /** The literal argument before expansion. */
  input: string
  /** Lexical resolution against the effective cwd (`~`, `$HOME` expanded). */
  absolute: string
  /** Realpath of the nearest existing ancestor joined with the remaining segments. */
  canonical: string
  relation: PathRelation
  labels: PathLabel[]
  /** True when the canonical path differs from the lexical one (a symlink was traversed). */
  symlink: boolean
  exists: boolean
}

/** `unknown`: an unrecognised command touches the path; the effect could be anything. */
export type FileEffect = "read" | "write" | "delete" | "chmod" | "exec" | "unknown"

export interface GitAction {
  subcommand: string
  mutating: boolean
  destructive: boolean
  remote: boolean
}

export interface PackageAction {
  manager: string
  operation: "install" | "publish" | "fetch-exec" | "run" | "other"
  packages: string[]
  system: boolean
}

export interface PathOperand {
  path: NormalizedPath
  effect: FileEffect
  /** The command acts on entries inside the directory (find, chmod -R), not on the operand itself. */
  within?: boolean
}

export interface NormalizedProcess {
  /** Static executable name (basename, lower-cased for PowerShell/cmd); undefined when dynamic. */
  executable?: string
  /** Wrapper the executable was unwrapped from (sudo, env, nohup, xargs, ...). */
  wrapper?: string
  argv: string[]
  /** Static cwd in effect for this command; undefined when a prior `cd` made it unknown. */
  cwd?: string
  /** Classification of that cwd: commands acting on the current directory implicitly inherit its risk. */
  cwdRelation?: PathRelation
  /** Static path operands, classified, each with the effect the command has on it. */
  operands: PathOperand[]
  /** Primary filesystem effect of the command family, when known. */
  effect?: FileEffect
  recursive: boolean
  force: boolean
  /** True when at least one operand is dynamic (variables, substitutions, globs without a prefix). */
  dynamic: boolean
  /** Targets come from stdin (xargs) or a pipeline rather than static operands. */
  stdinTargets: boolean
  privileged: boolean
  /** The command feeds a shell / interpreter with a payload that is analysed recursively when static. */
  indirection?: "shell" | "interpreter" | "eval" | "cmd"
  nested?: NormalizedCommand
  encoded: boolean
  network: boolean
  git?: GitAction
  pkg?: PackageAction
  /** Set when the process consumes a pipeline (`... | sh`). */
  piped: boolean
  /** Executables of the producers earlier in the same pipeline (for `curl | sh`, `base64 -d | sh`). */
  producers: string[]
  /** An option that makes an otherwise benign command execute an arbitrary program (`rg --pre`, `man -P`). */
  escape?: string
  /** Command families with hard-coded semantics (device wipe, shutdown, ...). */
  family?: "device" | "system-control" | "persistence" | "process-control" | "container" | "metadata"
  /** Metadata-only command (ls, stat, ps, ping ...) with no content access or side effect. */
  metadata: boolean
  /**
   * Static `NAME=value` assignments that prefix the command (`npm_config_registry=… npm install`).
   * Names are kept verbatim; values are kept only for the package-provenance rules and never logged.
   */
  assignments?: Record<string, string>
}

export interface NormalizedCommand {
  shell: "bash" | "powershell" | "cmd"
  source: string
  commands: NormalizedProcess[]
  fullyParsed: boolean
  unparsed: string[]
  redirects: NormalizedRedirect[]
  hasPipe: boolean
  hasRedirect: boolean
  hasSubshell: boolean
  hasCommandSubstitution: boolean
  hasProcessSubstitution: boolean
  hasDynamicExpansion: boolean
  hasHeredoc: boolean
  hasControlFlow: boolean
  hasFunction: boolean
  hasBackground: boolean
  /** PowerShell expression statements (`[IO.File]::Delete(...)`, `.Invoke(...)`) that are not commands. */
  hasExpression: boolean
  depth: number
}

export interface NormalizedRedirect {
  operator: string
  effect: "read" | "write"
  path?: NormalizedPath
  dynamic: boolean
  append: boolean
  /** Index into `commands` of the process the redirect is attached to (undefined when unattributable). */
  command?: number
}

export type NormalizedAction =
  | { kind: "shell"; permission: string; command: NormalizedCommand }
  | { kind: "file"; permission: string; effect: FileEffect; paths: NormalizedPath[] }
  | { kind: "permission"; permission: string; patterns: string[] }

export interface SecurityContext {
  sessionID: string
  agent: string
  workspace: { directory: string; worktree: string }
  cwd: string
  home: string
  sandbox: { enabled: boolean }
}

export type SecuritySource = "hard" | "default"

export interface SecurityEvidence {
  /** Stable rule identifier, e.g. `hard.fs.recursive-system-delete`. */
  rule: string
  source: SecuritySource
  action: SecurityAction
  reasonCode: SecurityReasonCode
  message: string
  /** Never include secret contents or full commands here. */
  attributes?: Record<string, string | number | boolean>
}

export interface SafeAlternative {
  description: string
}

export interface SecurityDecision {
  action: SecurityAction
  /**
   * A hard decision may not be relaxed by permissive permission rules. DENY is always hard; ASK is
   * hard when it comes from an immutable rule (unparsed shell, indirection, sensitive reads, ...).
   * A soft ASK only means the engine cannot vouch for the action: the existing permission model decides.
   */
  hard: boolean
  reasonCode: SecurityReasonCode
  /** Human readable, shown in permission prompts and tool metadata. */
  message: string
  /** Agent readable, tells the model how to continue safely without exposing policy internals. */
  guidance: string
  canRetry: boolean
  evidence: SecurityEvidence[]
  alternatives: SafeAlternative[]
}

/** Structured result returned to the agent instead of a fatal error when an action is denied. */
export interface BlockedResult {
  status: "blocked"
  decision: "deny"
  reasonCode: SecurityReasonCode
  message: string
  canRetry: boolean
  alternatives: string[]
}
