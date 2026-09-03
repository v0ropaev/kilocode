import { afterAll, beforeAll, describe, expect, test } from "bun:test"
import fs from "fs/promises"
import os from "os"
import path from "path"
import { Global } from "@opencode-ai/core/global"
import { SandboxStore } from "../../../src/kilocode/sandbox/store"
import { PathRisk } from "../../../src/kilocode/security/path"

const root = await fs.mkdtemp(path.join(os.tmpdir(), "kilo-security-path-"))
const real = await fs.realpath(root)
const home = path.join(real, "home")
const ws = path.join(home, "code", "app")
// The fixture home lives under the OS temp dir, so use an explicit temp root list to keep the
// classification of "temp" vs "external" meaningful.
const env = PathRisk.env({
  workspace: { directory: ws, worktree: ws },
  home,
  temp: ["/tmp", "/private/tmp", "/var/tmp"],
  // macOS keeps the temp dir under /private/var, so keep the system list to roots the fixture never touches.
  system: [
    "/etc",
    "/usr",
    "/bin",
    "/sbin",
    "/System",
    "/Library",
    "/dev",
    "/boot",
    "/proc",
    "/sys",
    "/home",
    "/Users",
    "/opt",
  ],
})

beforeAll(async () => {
  await fs.mkdir(path.join(home, ".ssh"), { recursive: true })
  await fs.mkdir(path.join(ws, "src"), { recursive: true })
  await fs.mkdir(path.join(real, "elsewhere"), { recursive: true })
  await fs.writeFile(path.join(home, ".ssh", "id_rsa"), "")
  await fs.symlink(path.join(home, ".ssh"), path.join(ws, "keys"))
  await fs.symlink(path.join(ws, "src"), path.join(real, "elsewhere", "srclink"))
})

afterAll(async () => {
  await fs.rm(root, { recursive: true, force: true })
})

const at = (input: string, cwd: string | undefined = ws) => PathRisk.classify(input, cwd, env)

describe("PathRisk classification", () => {
  test("workspace paths, root and config", () => {
    expect(at("src/index.ts").relation).toBe("workspace")
    expect(at("./build").relation).toBe("workspace")
    expect(at(".").relation).toBe("workspace-root")
    expect(at(ws).relation).toBe("workspace-root")
    expect(at("kilo.json").relation).toBe("workspace-config")
    expect(at("opencode.jsonc").relation).toBe("workspace-config")
    expect(at("AGENTS.md").relation).toBe("workspace-config")
    expect(at(".kilo/tool/x.ts").relation).toBe("workspace-config")
    expect(at(".kilocode/agents/x.md").relation).toBe("workspace-config")
    expect(at("packages/a/.kilo/x").relation).toBe("workspace-config")
    expect(at(".kilo/plans/x.md").relation).toBe("workspace")
    expect(at(".git/config").labels).toContain("git-dir")
    expect(at(".env").labels).toContain("secret")
    expect(at(".env.local").labels).toContain("secret")
    expect(at(".env.example").labels).not.toContain("secret")
    expect(at("certs/dev.pem").labels).toContain("private-key")
  })

  test("home, sensitive locations and labels", () => {
    expect(at("~").relation).toBe("home-root")
    expect(at(home).relation).toBe("home-root")
    expect(at("$HOME").relation).toBe("home-root")
    expect(at("~/Documents/notes.md").relation).toBe("home")
    expect(at("~/.ssh").relation).toBe("home-sensitive")
    expect(at("~/.ssh/id_rsa").labels).toEqual(expect.arrayContaining(["credential", "private-key"]))
    expect(at("~/.ssh/config").labels).toEqual(["credential"])
    expect(at("~/.ssh/id_ed25519.pub").labels).toEqual(["credential"])
    expect(at("~/.aws/credentials").labels).toContain("private-key")
    expect(at("~/.aws/config").labels).toEqual(["credential"])
    expect(at("~/.kube/config").labels).toContain("private-key")
    expect(at("~/.netrc").labels).toContain("private-key")
    expect(at("~/.bashrc").labels).toEqual(["shell-persistence"])
    expect(at("~/.zshrc").relation).toBe("home-sensitive")
    expect(at("~/.config/fish/config.fish").labels).toEqual(["shell-persistence"])
    expect(at("~/Library/LaunchAgents/x.plist").labels).toEqual(["shell-persistence"])
    expect(at("~/.gitconfig").labels).toEqual(["git-identity"])
    expect(at("~/.git-credentials").labels).toContain("private-key")
    expect(PathRisk.secret(at("~/.ssh/id_rsa"))).toBe(true)
    expect(PathRisk.secret(at("~/.ssh/config"))).toBe(false)
  })

  test("system, temp, device and external", () => {
    expect(at("/").relation).toBe("root")
    expect(at("/etc/passwd").relation).toBe("system")
    expect(at("/usr/local/bin/x").relation).toBe("system")
    expect(at("/System/Library").relation).toBe("system")
    expect(at("/dev/sda").labels).toContain("device")
    expect(at("/dev/null").labels).not.toContain("device")
    expect(at("/etc/cron.d/job").labels).toContain("shell-persistence")
    expect(at("/tmp/scratch/x").relation).toBe("temp")
    expect(at("/tmp").relation).toBe("external")
    expect(at(path.join(real, "elsewhere", "x")).relation).toBe("external")
    expect(at(path.dirname(ws)).labels).toContain("workspace-ancestor")
    expect(at(home).labels).toContain("workspace-ancestor")
  })

  test("Kilo configuration and state are protected", () => {
    expect(at(path.join(Global.Path.config, "kilo.json")).relation).toBe("kilo-security")
    expect(at(path.join(Global.Path.config, "kilo.json")).labels).toContain("kilo-config")
    expect(at(path.join(Global.Path.state, "x")).relation).toBe("kilo-security")
    expect(at(path.join(SandboxStore.root, "abc")).relation).toBe("kilo-security")
    expect(at(path.join(Global.Path.data, "auth.json")).labels).toContain("kilo-state")
    expect(at("~/.kilo/skills/x/SKILL.md").relation).toBe("kilo-security")
    expect(at("~/.config/kilo/kilo.json").relation).toBe("kilo-security")
    expect(at(path.join(Global.Path.data, "plans", "x.md")).relation).not.toBe("kilo-security")
  })

  test("traversal, symlinks and canonicalisation", () => {
    expect(at("../../.ssh/id_rsa").relation).toBe("home-sensitive")
    expect(at("src/../../../.ssh").relation).toBe("home-sensitive")
    expect(at("../app/src/x.ts").relation).toBe("workspace")
    const linked = at("keys/id_rsa")
    expect(linked.relation).toBe("home-sensitive")
    expect(linked.symlink).toBe(true)
    expect(linked.canonical).toBe(path.join(home, ".ssh", "id_rsa"))
    const inward = at(path.join(real, "elsewhere", "srclink", "x.ts"))
    expect(inward.relation).toBe("external")
    expect(at("../../.ssh/missing/deeper").relation).toBe("home-sensitive")
    expect(at("../../.ssh/missing/deeper").exists).toBe(false)
  })

  test("unknown cwd and dynamic input stay unknown", () => {
    expect(PathRisk.classify("build", undefined, env).relation).toBe("unknown")
    expect(at("$DIR/build").relation).toBe("unknown")
    expect(at("`pwd`/x").relation).toBe("unknown")
    expect(PathRisk.classify("/etc", undefined, env).relation).toBe("system")
  })
})
