// Guards on the semantic evaluation. Two kinds: the split has to stay a split, and the layer has to
// stay safe on text it has never seen. Recall is reported by the eval, not asserted as a floor — a
// test that demands a recall number is a test that invites tuning the provider until it passes.
import { describe, expect, test } from "bun:test"
import { HeuristicProvider } from "../provider"
import { DEVELOPMENT, HELD_OUT } from "./corpus"
import { score } from "./run"

describe("the evaluation split is a split", () => {
  test("no held-out excerpt appears in the development set", () => {
    const dev = new Set(DEVELOPMENT.flatMap((item) => item.input.provenance.map((entry) => entry.excerpt)))
    for (const item of HELD_OUT) for (const entry of item.input.provenance) expect(dev.has(entry.excerpt)).toBe(false)
  })

  test("ids are unique across both sets", () => {
    const ids = [...DEVELOPMENT, ...HELD_OUT].map((item) => item.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  test("both sets carry positives and hard negatives", () => {
    for (const set of [DEVELOPMENT, HELD_OUT]) {
      expect(set.some((item) => item.expect === "escalate")).toBe(true)
      expect(set.filter((item) => item.expect === "quiet").length).toBeGreaterThan(2)
    }
  })

  test("the held-out set covers every carrier the brief names", () => {
    const groups: string[] = HELD_OUT.map((item) => item.group)
    for (const required of [
      "readme",
      "skill",
      "dependency",
      "web",
      "mcp",
      "source-comment",
      "ci-config",
      "notebook",
      "laundering",
      "goal-mismatch",
      "benign-carrier",
      "benign-network",
      "benign-secret-task",
      "benign-coding",
    ])
      expect(groups).toContain(required)
  })
})

describe("the shipped operating point stays quiet on work it has never seen", () => {
  test("no benign held-out case is escalated under the default policy", async () => {
    const scored = await score(new HeuristicProvider(), HELD_OUT, "conservative")
    expect(scored.falseEscalation).toBe(0)
  })

  test("every escalation lands on a case that should escalate more often than not", async () => {
    for (const set of [DEVELOPMENT, HELD_OUT])
      for (const mode of ["conservative", "balanced"] as const) {
        const scored = await score(new HeuristicProvider(), set, mode)
        expect(scored.precision).toBeGreaterThan(0.5)
      }
  })

  test("a hard escalation only ever comes from a HIGH_RISK verdict", async () => {
    for (const set of [DEVELOPMENT, HELD_OUT])
      for (const mode of ["conservative", "balanced"] as const) {
        const scored = await score(new HeuristicProvider(), set, mode)
        // The `balanced` point adds soft asks only: nothing it admits may reach a hard ask.
        for (const item of scored.outcomes.filter((entry) => entry.hard))
          expect(["PROMPT_INJECTION", "USER_GOAL_MISMATCH", "DATA_EXFILTRATION", "DELEGATED_AUTHORITY"]).toContain(
            item.category,
          )
      }
  })
})
