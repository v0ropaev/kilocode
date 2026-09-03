# Security Auto Mode

Deterministic `ALLOW / ASK / DENY` adjudication for side-effecting tool calls, sitting between Kilo's
permission prompts and unsafe auto-approval. Off by default.

> Agent intent may be compromised; agent authority stays bounded by deterministic policy plus the
> existing sandbox. No decision depends on the model recognising an attack.

Code map verified against commit `f062b0737eb6969644ab3fea7b391b8049401e4a` (2026-09-02).

## Enabling

- Global config (`~/.config/kilo/kilo.json` or `opencode.json`): `{ "experimental": { "security_auto": true } }`
- or the environment variable `KILO_SECURITY_AUTO=1` (`0` / `false` forces it off).

Two additional evaluation layers (v2) are on whenever the mode is on and can be switched off
individually, global config or environment only:

| Layer | Config key | Env | Default |
|---|---|---|---|
| Package provenance preflight | `experimental.security_auto_packages` | `KILO_SECURITY_AUTO_PACKAGES` | on |
| Stateful secret-egress protection | `experimental.security_auto_egress` | `KILO_SECURITY_AUTO_EGRESS` | on |

Project configuration is ignored on purpose: a repository must not be able to switch the mode or its
layers. The global config directory itself is protected by the engine's hard rules, so the agent
cannot switch it either. The existing `--auto` / allow-everything semantics are untouched when the flag
is off.

## Execution flow (as implemented in Kilo today)

```
model tool call
  └─ SessionTools.resolve                     packages/opencode/src/session/tools.ts
       ├─ plugin.trigger("tool.execute.before")
       ├─ SandboxPolicy.executeTool          (unrestricted() when the sandbox is off)
       │    └─ SecurityGate.execute           envelope ask for unclassified tools, blocked-result conversion
       │         └─ item.execute(args, ctx)   the tool
       │              └─ ctx.ask(request)     every side-effecting builtin asks before its effect
       │                   └─ KiloSessionPrompt.askPermission   packages/opencode/src/kilocode/session/prompt.ts
       │                        ├─ buildAskRuleset (agent + session rules, provenance tags)
       │                        ├─ SecurityGate.evaluate  → normalise → SecurityEngine → decision
       │                        ├─ DENY  → fail SecurityDeniedError (Permission.ask never runs)
       │                        ├─ ASK   → hard: metadata.securityAsk forces an interactive prompt
       │                        ├─ ALLOW → lifts only the built-in / unmatched ask via a `source: "security"` rule
       │                        └─ Permission.ask   packages/opencode/src/permission/index.ts (existing deny / veto / prompt logic)
       ├─ plugin.trigger("tool.execute.after")
       └─ SessionProcessor → tool part → next model context
```

The shell tool additionally parses the command with Tree-sitter (`ShellPermission.check`) and asks
`external_directory` / `bash` / `sandbox_escalation`. The security normaliser reuses that parser and
its helpers (`ShellAst`, exported from `tool/shell.ts`) rather than adding a second one.

### Choke point

`ctx.ask` → `KiloSessionPrompt.askPermission` is the single Kilo-owned point that every builtin tool
passes through before its side effect, and it already assembles the ruleset and provenance. The
engine is invoked there. `SessionTools.resolve` adds coverage: tools that are not known to ask
(custom, plugin, `notify_user`, ...) receive an envelope ask so the engine at least sees them, and a
security denial anywhere inside a tool is converted into a structured, non-fatal tool result.

## Decision model

- `SecurityEngine.evaluate(action, context)` is pure and synchronous; the normalisers run before it.
- Evidence is reduced monotonically: `DENY > ASK > ALLOW`; a weaker piece of evidence never relaxes a
  stronger one. Compound shell commands are evaluated as a whole, nested payloads included.
- `hard` decisions (all DENY; ASK from an immutable rule) override every permissive permission rule,
  including saved "always allow" approvals and allow-everything. A soft ASK only means "the engine
  cannot vouch for this": the existing permission rules decide.
- ALLOW never overrides anything: it only replaces the built-in default ask (`source: agent` or the
  unmatched fallback). Explicit user / project / session `ask` rules and every `deny` rule stay in force.
- Any failure inside the security layer is a hard ASK (`SECURITY_ENGINE_ERROR`), never ALLOW.
- A hard ASK request cannot be resolved by allow-everything, by sibling-approval draining, or by a
  non-interactive reply; a human must answer it.

## What the normaliser sees

`ShellNormalizer` (`packages/opencode/src/kilocode/security/shell.ts`):

- every `command` node inside lists, pipelines, subshells, substitutions, loops and functions, with
  every operand (the permission scanner's `parts()` drops `$VAR`, `$(...)` and numeric words; the
  security tokenizer keeps them so a destructive command never looks operand-free);
- shell quoting removed the way the shell does it (`r''m`, `'r'm`, `r\m` are `rm`), static brace
  expansion (`{build,/etc}` classifies every target and keeps the riskiest), `~user` / `~+` /
  `%VAR%` / `@splat` treated as unknown;
- executable + argv after unwrapping `sudo`/`doas`/`su`, `env` (including `env -S` re-splitting),
  `busybox`, `nohup`, `nice`, `timeout`, `xargs`, ...;
- static cwd tracking across `cd`/`pushd`/`popd` per scope (a subshell `cd` stays in the subshell, a
  dynamic `cd` makes later relative targets unknown);
- path operands classified per effect (read / write / delete / chmod / exec), redirect targets, `ln -s`
  links created earlier in the same command line;
- pipelines and their producers (`base64 -d | sh`, `curl | sh`), process substitution, PowerShell
  pipeline binding (`Get-Item ~/.ssh | Remove-Item` has unknown targets);
- recursive analysis of `bash|sh|zsh|... -c`, `pwsh|powershell -Command`, `cmd /c` payloads up to depth 4;
  dynamic payloads stay opaque;
- interpreter indirection (`python -c`, `node -e`, ...), exec-escape options (`rg --pre`, `man -P`,
  `tar --checkpoint-action=exec`, `find -exec`, `sed w`, `awk system()`, `LD_PRELOAD=`), git
  subcommand semantics including read-only subcommands that read file operands (`git show ~/.ssh/id_rsa`),
  package manager operations, devices, system control, scheduled tasks and services, container escapes,
  output options that write files (`sort -o`, `curl -o`, `dd of=`, `patch -d`, `tar -C`);
- parse errors (`UNKNOWN_SHELL_SYNTAX`).

`PathRisk` (`path.ts`) classifies after expansion, resolution against the effective cwd and
canonicalisation through the nearest existing ancestor (both lexical and physical location are
classified, the riskier wins): `workspace`, `workspace-root`, `workspace-config`, `temp`, `home`,
`home-root`, `home-sensitive` (credential stores, private keys, shell startup files, git identity),
`kilo-security` (global config, `~/.kilo`, sandbox state, runtime state), `system`, `root`,
`external`, `unknown`; plus labels such as `private-key`, `credential`, `secret`, `device`, `git-dir`,
`workspace-ancestor`.

## Hard rules (immutable)

| Rule | Decision |
|---|---|
| recursive / plain destruction of `/`, system roots, home root, ancestors of the workspace | DENY |
| writes, deletes, chmod on credential stores, private keys, shell startup files, Kilo config / state | DENY |
| reads of private keys and credential files (`~/.ssh/id_*`, `~/.aws/credentials`, `~/.netrc`, ...) | DENY |
| `sudo`, `doas`, `su`, `pkexec` | DENY |
| block devices, `mkfs*`, `dd of=/dev/*`, `diskutil erase*`, `> /dev/sd*` | DENY |
| `shutdown`, `reboot`, `crontab -r`, `kill -9 -1`, persistence commands (`crontab`, `launchctl load`, `at`) | DENY |
| decoded payload into a shell / interpreter, `pwsh -EncodedCommand` | DENY |
| network content piped or substituted into a shell / interpreter | DENY |
| calls to the local Kilo server permission / sandbox routes (any loopback spelling, unix sockets) | DENY |
| unparsed shell text, opaque `bash -c` payloads, `eval`, piped shells, exec-escape options, dynamic executables | hard ASK |
| destructive commands with dynamic or stdin targets, dynamic redirect targets | hard ASK |
| credential metadata reads (`~/.ssh/config`), `.env` / key-like files in the workspace | hard ASK |
| project configuration at any depth, case-insensitive (`kilo.json`, `opencode.json(c)`, `.kilo/**`, `.kilocode/**`, `.claude/**`, `AGENTS.md`, `CLAUDE.md`), `.git` directory, whole-workspace deletes | hard ASK |
| commands that act on their working directory while it is outside the workspace (`npm install`, `make`, `tar x`) | soft ASK, hard ASK inside sensitive directories |
| destructive git (`push --force`, `reset --hard`, `checkout -- .`, `clean -f`, `branch -D`, global config) | hard ASK |
| system package managers, publishing, system services, privileged containers | hard ASK |

Default policy: ordinary reads, workspace writes and deletes, temp-dir actions, git read-only and
non-destructive mutations, project scripts (`npm test`, `make`, `python script.py`) are ALLOW.
Package installs, fetch-and-execute (`npx`), outbound network tools, interpreter inline code, writes
outside the workspace, unrecognised git subcommands and unclassified tools are soft ASK.

## Security Auto layers

Two evaluation layers run after the v1 rules and hand structured evidence to the same monotonic
reducer, so they can only *tighten* a decision — a deterministic v1 DENY / hard ASK is never weakened,
and their own failures fail safe (a hard ASK, never ALLOW). Each is independently switchable (see
[Enabling](#enabling)).

### Package provenance preflight (`security_auto_packages`)

A recognised package operation is evaluated against registry metadata *before* the package manager
runs, so an unvetted package's install-time scripts never execute first.
`packages/opencode/src/kilocode/security/package/`.

- **What is recognised** (read from the already-normalised command, wrappers and nested `bash -c`
  included — not a second parser): npm/pnpm/yarn/bun installs, `npm ci` / `clean-install` (manifest
  installs that run every dependency's scripts, so treated as installs, not project scripts), and
  `npx` / `npm exec` / `pnpm dlx` / `bunx` fetch-and-execute. Explicit vs manifest install, scoped
  names, versions/ranges/tags, alias / git / url / file sources, `--registry` and
  `npm_config_registry` overrides, and `--ignore-scripts` are distinguished.
- **Signals** (an explainable set, never one opaque score): deterministic — package age, release age,
  declared install scripts, repository presence, non-registry source, registry override (command line
  or project `.npmrc`); heuristic — adoption (weekly downloads), name similarity to a well-known
  package (edit distance / separator / affix / homoglyph / scope, each naming the look-alike);
  uncertainty — registry metadata unavailable, package not found, ambiguous spec, unresolved range.
- **Decision**: uncertainty never resolves to ALLOW (`metadata lookup failure ≠ trusted`); an unvetted
  package whose code would run now (install scripts enabled, or `npx`) is a DENY; other suspicious
  provenance is a hard ASK; an established, adopted package keeps the base soft ASK. Manifest installs
  assess the direct dependencies. Registry metadata comes through a mockable provider (deterministic
  fixtures for tests / the benchmark; an optional live npm adapter with a timeout, size cap and cache).
- Honest guarantee: *suspicious provenance is evaluated before local execution*. It does not detect
  arbitrary zero-days, and does not make later execution of imported malicious code safe. Ecosystems
  other than npm/pnpm/yarn/bun keep the base soft ask.

### Stateful sensitive-read → egress protection (`security_auto_egress`)

A lightweight per-session state closes the class where individual steps look allowable but the
sequence is exfiltration (`read secret → copy → outbound`). `packages/opencode/src/kilocode/security/state/`.

- **State** (per root session, so a sub-agent read is visible to its parent; never shared between
  unrelated sessions; swept by TTL): sensitive resources whose contents were actually obtained (a read
  that *executed* — a name in a denied request never counts), files tainted through a controlled
  built-in flow (copy / move / redirect / a write carrying a tracked value), and salted digests of the
  value-like tokens in those resources. It never stores raw secret values, and nothing is persisted or
  logged. Observations are recorded against the tool call and committed only when it succeeds.
- **Propagation** is limited to controlled flows visible in one command; it is *not* a taint engine.
  Opaque subprocesses are out of reach by design — the OS sandbox's restricted egress remains the
  stronger control there.
- **Decision**: an ordinary outbound call with no secret context keeps the base network policy; a command
  that both reads a credential and sends data out, an outbound action that reads a tainted/sensitive
  file, or a literal secret value on an outbound command line is a DENY; an outbound action while the
  session holds secret context, with no deterministic data link, is a hard ASK. Loopback destinations
  are treated as egress (no 127.0.0.1 exception). Intent is not inferred: an agent-initiated and a
  user-requested exfiltration are treated the same, because the engine cannot prove trusted provenance.
- Honest guarantee: *a known sensitive read influences later outbound decisions in the same session.*
  It does not track dataflow inside arbitrary programs, encoded/transformed values, or secrets the user
  typed directly.

## Structured safe continuation

A DENY inside a tool becomes a completed tool result titled "Blocked by security policy" whose
output carries a stable reason code, a human/agent readable reason, `canRetry` and safe
alternatives (no thresholds or rule internals). The turn continues; Kilo's doom-loop guard still
catches repeated identical attempts.

## Invariants enforced by code and tests

- covered side-effecting actions are evaluated before execution (`test/kilocode/security/session-tools.test.ts`);
- DENY never reaches `Permission.ask` and the executor is never invoked;
- `DENY + ALLOW = DENY`, `ASK + ALLOW = ASK` (`decision.test.ts`);
- a security failure is a hard ASK, never ALLOW;
- explicit user / project / session ASK rules are never lifted; deny rules always win (`gate.test.ts`);
- `bash -c`, wrappers, decoders, `curl | sh` do not bypass the rules; `../`, symlinks, `cd` are
  canonicalised; unknown syntax never auto-allows (`shell.test.ts`, `path.test.ts`);
- Kilo config / sandbox state writes are denied (`POLICY_TAMPERING`);
- flag off leaves requests, rulesets and executor behaviour unchanged;
- logs and metadata carry reason codes, rule ids and a command fingerprint, never command text or contents;
- a recognised package install/exec is evaluated before the package manager runs; a metadata
  lookup failure is a hard ASK, never ALLOW; layer evidence cannot weaken a deterministic DENY/hard ASK
  (`test/kilocode/security/package.test.ts`);
- a committed sensitive read updates session state and influences later outbound decisions; a
  refused read does not; session state is isolated between sessions and holds no raw secret values; a
  protected egress block happens before the outbound side effect (`test/kilocode/security/egress.test.ts`).

## Adversarial review

Six independent review lenses (nested shells, paths, tampering, coverage, failure-open, PowerShell)
probed the engine with several hundred commands through the real normaliser. Confirmed bypasses that
were fixed before this slice was finished: `env -S 'rm -rf /'`, quote-split command names (`r''m`),
brace expansion (`rm -rf {build,/etc}`), `cp -r`/`mv -i` option parsing swallowing the source,
`~user` and `%VAR%` forms, PowerShell pipeline binding and splatting, `patch -d`, `sort -o`,
`git show <secret>`, `systemd-run`, loopback obfuscation (`127.1`, decimal / hex IPs, `nip.io`,
unix sockets), nested and case-variant project config paths, the workspace-equals-home case, and
scheduled task / service cmdlets, unknown commands with `-o`-style outputs (`shuf`, `ed`,
`Import-Csv`), `sl` / `Copy-Item -Destination` / `Rename-Item` / `--%` / `$env:` / provider-qualified
paths in PowerShell, .NET expression statements, wildcards inside directory segments (`~/.ss[h]/`),
`find -exec cat` over the home tree, `sort -o`, `git apply --unsafe-paths`, `tar -P`, raw sockets to
localhost and additional autorun files (`~/.vimrc`, `~/.gdbinit`, fish `functions/`).

The package and egress layers were reviewed the same way. Package review probed wrappers, `bash -c` and doubly-nested
payloads, `;`/`&&`/subshell chaining, `npx`/`npm exec`/`pnpm dlx`/`bunx`, scoped and quoted names, pins
and dist-tags, `--registry`/`npm_config_registry`/`.npmrc` overrides, git/url/tarball/file specs and
bare-manifest installs — every recognised install of the days-old postinstall fixture is denied and
every provenance variant at least asks. Egress review probed secret→temp→network, a two-hop copy,
literal and base64 values, many benign steps between read and send, session reset, an untainted upload
under secret context (a hard ASK, not a false DENY), and confirmed no raw value appears in a decision
or the state snapshot. Confirmed residuals kept honest: opaque subprocess flow (`python upload.py
secret`, unknown outbound tools) and encoded values are not statically contained, and pip/cargo/go are
outside the npm-family package scope.

## Known limitations (not guaranteed by this slice)

- Sandbox off is materially weaker: allowed workspace scripts (`npm run x`, `make`, `python script.py`)
  run with full host authority; the engine only decides whether an action may be attempted.
- Interpreter inline code (`python -c`, `node -e`) is a soft ASK, not analysed.
- Network policy without secret context is unchanged: `webfetch`, `websearch`, an ordinary `curl` are
  soft ASK / existing rules. MCP tools and custom tools remain unclassified (existing rules decide) —
  an intentional residual class for the next milestone; `notify_user`, `background_process`
  restart/stop and `generate_image` upload perform effects without a classifiable ask (pre-existing
  Kilo gaps).
- (egress) The egress layer sees only controlled built-in flows: an **opaque subprocess** that
  reads a secret and sends it itself (`python upload.py secret`, an unknown outbound tool) is not
  contained by static state — the OS sandbox is the control there; **encoded/transformed** values are
  not value-matched (a same-session sensitive read still raises the context hard ASK); secrets the user
  types directly are not labelled. The package layer covers **npm/pnpm/yarn/bun** only; pip / cargo /
  go / system package managers keep their base handling. A **malicious but popular/established** package,
  and malicious code that runs at import/build time rather than install time, are out of scope.
- User agent-level config `ask` rules are tagged `agent` by Kilo and therefore liftable like built-in defaults.
- `kilo run --auto` and TUI auto mode cannot answer a security hard ASK (it needs an interactive reply);
  the request stays pending, matching Kilo's existing skill-shell behaviour.
- PowerShell / cmd fidelity is lower than bash: expressions without a command node are a hard ASK;
  .NET static calls, registry Run keys and `cmd` builtins are only partially modelled.
- Executing scripts located under system roots (`sh /etc/x.sh`) is treated like running any installed
  program; `git apply` / `git checkout` can materialise `.kilo/**` from repository content (Kilo's own
  trust decision for project-provided tools).
- Reads of non-secret home files (`~/.gitconfig`, `~/.bashrc`) are allowed; recursive content reads
  over a tree outside the workspace (`grep -r x ~`, `find ~ -exec cat`) are a hard ASK.
- Data-driven writers (`patch`, `tar x`, `unzip`, `git apply`) are judged by their target directory and
  escape flags (`tar -P`, `git apply --unsafe-paths`), not by the archive or diff contents; the tools'
  own traversal protections are relied upon for the rest.
- Unrecognised commands are judged by their escaping operands only; an unknown tool writing to a
  workspace-relative path it names differently is not detected.
- Prompt-file attachments and the subtask command path call `askPermission` without the gate (user-initiated).
- The `experimental.security_auto`, `security_auto_packages` and `security_auto_egress` keys must be
  mirrored in the cloud config schema (`apps/web/src/app/config.json/extras.ts`).
