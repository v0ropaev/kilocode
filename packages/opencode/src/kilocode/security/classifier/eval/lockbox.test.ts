/**
 * The seal.
 *
 * A pre-registration nobody checks is a sentence in a document. This turns it into a test: if the
 * prompt is reworded or the policy's severity table moves after the configuration was sealed, the
 * fingerprint changes and this fails — before a number claimed from the sealed configuration can be
 * reported. That is the only mechanical difference between "we froze the setup" and "we say we did".
 *
 * The construction checks are the same ones `semantic.test.ts` applies to the existing corpus. They
 * run against an empty set today and cost nothing; they are here so that the day cases arrive, the
 * set is checked before it is scored rather than after.
 */
import { describe, expect, test } from "bun:test"
import { CONTRACT, PREREGISTRATION, SEMANTIC_LOCKBOX, fingerprint } from "./lockbox"
import { INJECTION_GROUPS, type SemanticCase } from "./semantic"

describe("the sealed configuration", () => {
  test("the prompt and the severity table are exactly what was registered", () => {
    // If this fails, the seal is broken and any number claimed from it is claimed from a
    // configuration that no longer exists. The fix is to take the seal again on a later date and say
    // so — not to paste in the new digest.
    expect(fingerprint()).toBe(PREREGISTRATION.fingerprint)
  })

  test("the contract names all three kinds of pair, because a set missing one measures less", () => {
    for (const kind of ["INDIRECT INJECTION", "GOAL / ACTION MISMATCH", "GOAL / CONTENT"])
      expect(CONTRACT).toContain(kind)
  })
})

describe("the set, whenever it arrives", () => {
  const pairs = () => {
    const out = new Map<string, SemanticCase[]>()
    for (const item of SEMANTIC_LOCKBOX) out.set(item.pair, [...(out.get(item.pair) ?? []), item])
    return out
  }

  const metadata = (item: SemanticCase) =>
    JSON.stringify({
      action: item.input.action,
      goal: item.input.goal ?? null,
      provenance: item.input.provenance.map((entry) => ({ source: entry.source, name: entry.name })),
    })

  test("is either empty or large enough for a rate to mean anything", () => {
    if (SEMANTIC_LOCKBOX.length === 0) return
    expect(pairs().size).toBeGreaterThanOrEqual(20)
  })

  test("is built as pairs: one attack and one benign case each", () => {
    const broken = [...pairs()]
      .filter(
        ([, group]) =>
          group.length !== 2 ||
          group.filter((item) => item.expect === "escalate").length !== 1 ||
          group.filter((item) => item.expect === "quiet").length !== 1,
      )
      .map(([name]) => name)
    expect(broken).toEqual([])
  })

  test("cannot be solved without reading: the injection halves are metadata-identical", () => {
    const broken = [...pairs()]
      .filter(([, group]) => INJECTION_GROUPS.includes(group[0]!.group))
      .filter(([, group]) => metadata(group[0]!) !== metadata(group[1]!))
      .map(([name]) => name)
    expect(broken).toEqual([])
  })

  test("does not reuse ids from the sets it replaces", () => {
    expect(new Set(SEMANTIC_LOCKBOX.map((item) => item.id)).size).toBe(SEMANTIC_LOCKBOX.length)
    expect(SEMANTIC_LOCKBOX.filter((item) => !item.id.startsWith("lock-")).map((item) => item.id)).toEqual([])
  })
})
