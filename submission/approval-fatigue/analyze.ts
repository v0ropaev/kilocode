#!/usr/bin/env bun
/**
 * Разбор результатов стенда approval-fatigue.
 *
 *   bun run analyze.ts results/*.json      // файлы сессий
 *   bun run analyze.ts results/            // каталог: все .json и .csv внутри
 *   bun run analyze.ts results/p-01.csv    // CSV той же формы
 *
 * Скрипт печатает Markdown-таблицы, пригодные для слайда. Без входных файлов он печатает
 * сообщение об отсутствии данных и завершается кодом 0 — никаких примеров, оформленных как
 * результаты, здесь нет и быть не должно.
 */

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs"
import { extname, join, resolve } from "node:path"

type Kind = "safe" | "dangerous" | "ambiguous" | "benign_looking_dangerous" | "context_dependent"
type Decision = "allow" | "block"
type EngineDecision = "ALLOW" | "ASK" | "DENY"

interface Case {
  id: string
  kind: Kind
  category: string
  tool: string
  proposal: string
  context: string
  expected: Decision
  security_auto: EngineDecision
  /** Only meaningful when security_auto is "ASK": false means a soft ASK the autonomy client
   *  auto-approves, so it costs the human nothing. Absent is treated as hard. */
  security_auto_hard?: boolean
  rationale: string
  layer: string
}

interface Response {
  participantId: string
  caseId: string
  decision: Decision
  expected: Decision
  correct: boolean
  responseTimeMs: number
  sequencePosition: number
  timestamp: string
}

const KIND_ORDER: Kind[] = ["safe", "dangerous", "ambiguous", "benign_looking_dangerous", "context_dependent"]

// ── Загрузка набора кейсов ───────────────────────────────────────────────────────────────────

function loadCases(): Case[] {
  const file = join(import.meta.dir, "cases.json")
  const parsed = JSON.parse(readFileSync(file, "utf8")) as Case[]
  if (!Array.isArray(parsed) || parsed.length === 0) throw new Error(`cases.json пуст или не является массивом: ${file}`)
  return parsed
}

// ── Сбор входных файлов ──────────────────────────────────────────────────────────────────────

function walk(path: string, out: string[]) {
  const info = statSync(path)
  if (info.isDirectory()) {
    for (const entry of readdirSync(path).sort()) walk(join(path, entry), out)
    return
  }
  const ext = extname(path).toLowerCase()
  if (ext === ".json" || ext === ".csv") out.push(path)
}

function collectFiles(args: string[]): { files: string[]; missing: string[] } {
  const files: string[] = []
  const missing: string[] = []
  for (const arg of args) {
    const path = resolve(arg)
    if (!existsSync(path)) {
      missing.push(arg)
      continue
    }
    walk(path, files)
  }
  return { files: [...new Set(files)], missing }
}

// ── Разбор одного файла ──────────────────────────────────────────────────────────────────────

function splitCsvLine(line: string): string[] {
  const out: string[] = []
  let field = ""
  let quoted = false
  for (let i = 0; i < line.length; i++) {
    const char = line[i]!
    if (quoted) {
      if (char === '"' && line[i + 1] === '"') {
        field += '"'
        i++
      } else if (char === '"') quoted = false
      else field += char
      continue
    }
    if (char === '"') quoted = true
    else if (char === ",") {
      out.push(field)
      field = ""
    } else field += char
  }
  out.push(field)
  return out.map((value) => value.trim())
}

function asResponse(raw: Record<string, unknown>, fallbackParticipant: string): Response | undefined {
  const caseId = String(raw.caseId ?? "")
  const decision = String(raw.decision ?? "")
  const expected = String(raw.expected ?? "")
  if (!caseId) return undefined
  if (decision !== "allow" && decision !== "block") return undefined
  if (expected !== "allow" && expected !== "block") return undefined
  const time = Number(raw.responseTimeMs)
  const position = Number(raw.sequencePosition)
  return {
    participantId: String(raw.participantId ?? fallbackParticipant ?? "unknown"),
    caseId,
    decision,
    expected,
    correct: raw.correct === undefined ? decision === expected : String(raw.correct) === "true" || raw.correct === true,
    responseTimeMs: Number.isFinite(time) ? time : Number.NaN,
    sequencePosition: Number.isFinite(position) ? position : Number.NaN,
    timestamp: String(raw.timestamp ?? ""),
  }
}

function readFile(path: string): { responses: Response[]; skipped: number } {
  const text = readFileSync(path, "utf8")
  const responses: Response[] = []
  let skipped = 0

  if (extname(path).toLowerCase() === ".csv") {
    const lines = text.split(/\r?\n/).filter((line) => line.trim().length > 0)
    if (lines.length < 2) return { responses, skipped }
    const header = splitCsvLine(lines[0]!)
    for (const line of lines.slice(1)) {
      const cells = splitCsvLine(line)
      const raw: Record<string, unknown> = {}
      header.forEach((name, index) => (raw[name] = cells[index]))
      const parsed = asResponse(raw, "")
      if (parsed) responses.push(parsed)
      else skipped++
    }
    return { responses, skipped }
  }

  const data = JSON.parse(text) as unknown
  const list = Array.isArray(data) ? data : ((data as { responses?: unknown[] }).responses ?? [])
  const participant = Array.isArray(data) ? "" : String((data as { participantId?: string }).participantId ?? "")
  for (const item of list as Record<string, unknown>[]) {
    const parsed = asResponse(item, participant)
    if (parsed) responses.push(parsed)
    else skipped++
  }
  return { responses, skipped }
}

// ── Статистика ───────────────────────────────────────────────────────────────────────────────

function rate(numerator: number, denominator: number): string {
  if (denominator === 0) return "n/a"
  return `${Math.round((numerator / denominator) * 100)} % (${numerator}/${denominator})`
}

function median(values: number[]): number | undefined {
  if (values.length === 0) return undefined
  const sorted = [...values].sort((a, b) => a - b)
  const middle = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 1 ? sorted[middle]! : Math.round((sorted[middle - 1]! + sorted[middle]!) / 2)
}

function p90(values: number[]): number | undefined {
  if (values.length === 0) return undefined
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.max(0, Math.ceil(sorted.length * 0.9) - 1)]!
}

function ms(value: number | undefined): string {
  return value === undefined ? "n/a" : `${Math.round(value)} мс`
}

/** `align`: true — колонка числовая и прижимается вправо. По умолчанию правая — всё, кроме первой. */
function table(header: string[], rows: string[][], align?: boolean[]): string {
  const rule = header.map((_, index) => ((align ? align[index] : index > 0) ? "--:" : "---"))
  return [`| ${header.join(" | ")} |`, `| ${rule.join(" | ")} |`, ...rows.map((row) => `| ${row.join(" | ")} |`)].join(
    "\n",
  )
}

// ── Точка входа ──────────────────────────────────────────────────────────────────────────────

function noData(reason: string): never {
  console.log("Ответы участников ещё не собраны.")
  console.log("")
  console.log(reason)
  console.log("")
  console.log("Как запускать:")
  console.log("  bun run analyze.ts results/*.json")
  console.log("  bun run analyze.ts results/")
  console.log("  bun run analyze.ts results/p-01.csv")
  console.log("")
  console.log("Пока входных файлов нет, скрипт не печатает никаких чисел: цифры этого стенда")
  console.log("не должны появляться в материалах до реального сбора ответов.")
  process.exit(0)
}

const args = Bun.argv.slice(2).filter((arg) => !arg.startsWith("-"))
if (args.length === 0) noData("Входные файлы не переданы.")

const { files, missing } = collectFiles(args)
for (const item of missing) console.error(`Пропущено: путь не найден — ${item}`)
if (files.length === 0) noData("Ни одного файла .json или .csv по указанным путям не найдено.")

const cases = loadCases()
const caseById = new Map(cases.map((item) => [item.id, item]))

const all: Response[] = []
let skippedRows = 0
for (const file of files) {
  try {
    const parsed = readFile(file)
    all.push(...parsed.responses)
    skippedRows += parsed.skipped
  } catch (error) {
    console.error(`Пропущено: файл не разобран — ${file} (${String(error)})`)
  }
}

const unknownIds = new Set(all.filter((item) => !caseById.has(item.caseId)).map((item) => item.caseId))
for (const id of unknownIds) console.error(`Пропущено: caseId отсутствует в cases.json — ${id}`)
const responses = all.filter((item) => caseById.has(item.caseId))

if (responses.length === 0) noData("Во входных файлах нет ни одного пригодного ответа.")

const participants = [...new Set(responses.map((item) => item.participantId))]
const totalsByParticipant = new Map<string, number>()
for (const item of responses) {
  const current = totalsByParticipant.get(item.participantId) ?? 0
  if (Number.isFinite(item.sequencePosition)) {
    totalsByParticipant.set(item.participantId, Math.max(current, item.sequencePosition))
  }
}

function sessionLength(participantId: string): number {
  return totalsByParticipant.get(participantId) || cases.length
}

const dangerous = responses.filter((item) => item.expected === "block")
const safe = responses.filter((item) => item.expected === "allow")
const dangerousAllowed = dangerous.filter((item) => item.decision === "allow")
const safeBlocked = safe.filter((item) => item.decision === "block")
const correct = responses.filter((item) => item.decision === item.expected)

const times = responses.map((item) => item.responseTimeMs).filter((value) => Number.isFinite(value))
const firstHalf = responses.filter((item) => item.sequencePosition <= sessionLength(item.participantId) / 2)
const secondHalf = responses.filter((item) => item.sequencePosition > sessionLength(item.participantId) / 2)
const firstTimes = firstHalf.map((item) => item.responseTimeMs).filter((value) => Number.isFinite(value))
const secondTimes = secondHalf.map((item) => item.responseTimeMs).filter((value) => Number.isFinite(value))

function quartileOf(item: Response): number {
  const total = sessionLength(item.participantId)
  if (!Number.isFinite(item.sequencePosition) || total <= 0) return 0
  return Math.min(4, Math.max(1, Math.ceil((item.sequencePosition / total) * 4)))
}

// ── Вывод ────────────────────────────────────────────────────────────────────────────────────

const out: string[] = []
out.push("# Approval fatigue — результаты")
out.push("")
out.push(
  `Участников: **${participants.length}** · решений: **${responses.length}** · ` +
    `кейсов затронуто: **${new Set(responses.map((item) => item.caseId)).size} из ${cases.length}** · ` +
    `файлов прочитано: ${files.length}`,
)
if (skippedRows > 0 || unknownIds.size > 0) {
  out.push("")
  out.push(`Пропущено строк: ${skippedRows}; неизвестных caseId: ${unknownIds.size}.`)
}

out.push("")
out.push("## Основные показатели")
out.push("")
out.push(
  table(
    ["Метрика", "Значение"],
    [
      ["Dangerous allow rate — опасное разрешено", rate(dangerousAllowed.length, dangerous.length)],
      ["Safe block rate — безопасное заблокировано", rate(safeBlocked.length, safe.length)],
      ["Overall decision accuracy", rate(correct.length, responses.length)],
    ],
  ),
)

out.push("")
out.push("## Время решения")
out.push("")
out.push(
  table(
    ["Срез", "median", "p90", "n"],
    [
      ["Вся последовательность", ms(median(times)), ms(p90(times)), String(times.length)],
      ["Первая половина", ms(median(firstTimes)), ms(p90(firstTimes)), String(firstTimes.length)],
      ["Вторая половина", ms(median(secondTimes)), ms(p90(secondTimes)), String(secondTimes.length)],
    ],
  ),
)

out.push("")
out.push("## Ошибки по квартилям последовательности")
out.push("")
out.push("Сигнал усталости: растёт ли доля ошибок ближе к концу.")
out.push("")
const quartileRows: string[][] = []
for (const quartile of [1, 2, 3, 4]) {
  const slice = responses.filter((item) => quartileOf(item) === quartile)
  const errors = slice.filter((item) => item.decision !== item.expected)
  const sliceDangerous = slice.filter((item) => item.expected === "block")
  const sliceAllowed = sliceDangerous.filter((item) => item.decision === "allow")
  const sliceTimes = slice.map((item) => item.responseTimeMs).filter((value) => Number.isFinite(value))
  quartileRows.push([
    `Q${quartile}`,
    rate(errors.length, slice.length),
    rate(sliceAllowed.length, sliceDangerous.length),
    ms(median(sliceTimes)),
  ])
}
out.push(table(["Квартиль", "Ошибок", "Опасное разрешено", "median"], quartileRows))

out.push("")
out.push("## По типу кейса")
out.push("")
const kindRows: string[][] = []
for (const kind of KIND_ORDER) {
  const ids = new Set(cases.filter((item) => item.kind === kind).map((item) => item.id))
  const slice = responses.filter((item) => ids.has(item.caseId))
  if (slice.length === 0) {
    kindRows.push([kind, "0", "n/a", "n/a"])
    continue
  }
  const errors = slice.filter((item) => item.decision !== item.expected)
  const sliceTimes = slice.map((item) => item.responseTimeMs).filter((value) => Number.isFinite(value))
  kindRows.push([kind, String(slice.length), rate(errors.length, slice.length), ms(median(sliceTimes))])
}
out.push(table(["kind", "Решений", "Ошибок", "median"], kindRows, [false, true, true, true]))

out.push("")
out.push("## Security Auto на тех же кейсах")
out.push("")
const touched = [...new Set(responses.map((item) => item.caseId))].map((id) => caseById.get(id)!)
const engineAllow = touched.filter((item) => item.security_auto === "ALLOW")
const engineDeny = touched.filter((item) => item.security_auto === "DENY")
const engineAsk = touched.filter((item) => item.security_auto === "ASK")
// A soft ASK is auto-approved under autonomy and costs the human nothing; only a hard ASK is a
// prompt a person has to answer. Counting the two together would overstate the friction the engine
// leaves behind, and the rest of the package is built on exactly that split.
const engineSoftAsk = engineAsk.filter((item) => item.security_auto_hard === false)
const engineHardAsk = engineAsk.filter((item) => item.security_auto_hard !== false)
const removed = engineAllow.length + engineDeny.length + engineSoftAsk.length
out.push(
  table(
    ["Решение движка", "Кейсов", "Что это значит"],
    [
      ["ALLOW", String(engineAllow.length), "человек не нужен"],
      ["DENY", String(engineDeny.length), "человек не нужен, действие не выполняется"],
      ["soft ASK", String(engineSoftAsk.length), "автономный режим одобряет сам, человек не нужен"],
      ["hard ASK", String(engineHardAsk.length), "движок намеренно оставляет решение человеку"],
    ],
    [false, true, false],
  ),
)
out.push("")
out.push(
  `Снято решений человека: **${removed} из ${touched.length}**; ` +
    `оставлено жёстких ASK: **${engineHardAsk.length}**.`,
)
out.push("")
out.push(
  "Решения движка в этой таблице выведены из hard rules и описаний слоёв " +
    "(`docs/security-auto-mode.md`), а не измерены прогоном бенчмарка на этих 28 кейсах.",
)

out.push("")
out.push("### Кейсы, где верным ответом был block")
out.push("")
const blockIds = touched.filter((item) => item.expected === "block")
const blockRows: string[][] = []
for (const item of blockIds) {
  const slice = responses.filter((entry) => entry.caseId === item.id)
  const allowed = slice.filter((entry) => entry.decision === "allow")
  blockRows.push([item.id, item.kind, item.security_auto, rate(allowed.length, slice.length)])
}
blockRows.sort((a, b) => a[0]!.localeCompare(b[0]!))
out.push(table(["case", "kind", "Security Auto", "Ошибочно разрешили"], blockRows, [false, false, false, true]))

out.push("")
out.push(
  "Сравнение не apples-to-apples: человек здесь решает по одному вызову без истории сессии, " +
    "а движок видит контекст сессии, provenance пакета и содержимое файла. См. README.",
)
out.push("")

console.log(out.join("\n"))
