---
"@kilocode/cli": minor
---

Add Security Auto Mode (`experimental.security_auto`, off by default): a deterministic security engine that adjudicates shell and file tool calls as ALLOW / ASK / DENY before the permission prompt, blocks destructive, credential-exposing and policy-tampering actions with a structured result the agent can recover from, and forces an interactive prompt for opaque or unparsed shell commands.
