# Security Auto Mode — LLM-прослойки поверх детерминированного контура

Статус: design / план. Ветка `feature/llm-security-layers`.

## 0. Целевая архитектура (7 компонентов)

```
             ┌───────────────── untrusted input (README, MCP, web, tool results)
             ▼
   [ LLM Context Checker ]  → только ДОБАВЛЯЕТ признаки риска в Session State (не блокирует)
             │
             ▼
   ┌──────────────── действие агента (tool call) ────────────────┐
   │                                                             │
   ▼                                                             │
[ Deterministic Security Engine ]  ← ОСНОВНОЙ КОНТУР             │
   • опасные команды / защищённые пути / package policy          │
   • Capability / CodeTrust (кто вправе выполнять)               │
   • Session State (читал секрет? видел подозрительный контент?) │
   → ALLOW / soft-ASK / hard-ASK / DENY                          │
   │                                                             │
   ├─ DENY / hard-ASK ─────────────────────────────► immutable (LLM не трогает)
   │                                                             │
   └─ soft-ASK (эвристическая неоднозначность)                   │
             ▼                                                   │
   [ LLM Action Classifier ]  → соответствует ли действие тому,  │
             │                   что реально просил пользователь?│
             │   yes → ALLOW (реже дёргаем человека)             │
             │   no  → keep ASK / DENY                           │
             ▼                                                   │
        решение ALLOW/ASK/DENY ──────────────────────────────────┘
             ▼
   [ OS Sandbox / Extension Runtime ]  ← физически ограничивает даже после ALLOW
             ▼
        выполнение
```

## 1. Что уже есть vs что новое

| Компонент | Статус | Где |
|---|---|---|
| Deterministic Security Engine (rules, paths, command AST) | ✅ есть | `security/rules.ts`, `command.ts`, `path.ts`, `engine.ts`, `decision.ts` |
| Package Security (pre-install) | ✅ есть | `security/package/*` |
| Capability / CodeTrust | ✅ есть | `security/tool/*`, `security/code/*` |
| Session State | ✅ есть (частично) | `security/state/*` |
| OS Sandbox / Extension Runtime | ✅ есть | `kilo-sandbox/*`, `security/extension/*` |
| **LLM Action Classifier** | 🔲 НОВОЕ | `security/classifier/action.ts` (план) |
| **LLM Context Checker** | 🔲 НОВОЕ | `security/classifier/context.ts` (план) |

Вывод: детерминированный контур — фундамент, он остаётся источником полномочий. LLM добавляем **двумя тонкими прослойками**, ни одна из которых не может ослабить детерминированное решение.

## 2. Инварианты (нерушимые при добавлении LLM)

1. LLM **никогда** не превращает детерминированный `DENY` → `ALLOW`.
2. LLM **никогда** не понижает `hard-ASK` (явная policy человека) → `ALLOW`.
3. LLM трогает только `soft-ASK` (эвристическая «не уверен») — может понизить до ALLOW или повысить до DENY.
4. Ошибка/таймаут LLM → **fail-closed**: остаёмся на детерминированном решении (обычно ASK). Latency-спайк не ломает поток.
5. Classifier **reasoning-blind**: НЕ получает raw tool-output / текст агента → инъекция до него не доходит.
6. Context Checker **ничего не блокирует** — только пишет признаки риска в Session State.

Это выполняет требование кейса: хотя бы один контроль архитектурно неуязвим к prompt injection — им остаётся детерминированный слой + sandbox.

## 3. «Лёгкий и быстрый» LLM — принципы дизайна

1. **Вызываем редко.** LLM работает только на узкой полосе:
   - Action Classifier — только когда детерминированный вердикт `soft-ASK` (доли процента действий; ALLOW/DENY идут без LLM).
   - Context Checker — только на недоверенном входном контенте (README/MCP/web), не на каждом действии.
2. **Two-stage (приём Anthropic).** Stage 1 — один токен `yes/no` (нужен ли человек / подозрительно ли), настроен осторожно. Stage 2 (короткий CoT) — только если stage 1 флагнул. Большинство кейсов останавливается на stage 1.
3. **Минимальный вход.** Только: исходный запрос пользователя + нормализованное действие (executable, argv, resolved paths, effect) + пара фактов из Session State. Без raw-контента → мало токенов + injection-safe.
4. **Prompt caching.** Фиксированный шаблон-префикс кешируется; добавляем только переменную часть.
5. **Мемоизация в сессии** по fingerprint действия (+ хэш запроса) — повтор того же действия не вызывает LLM снова.
6. **Малая быстрая модель** (Haiku-class), remote. Интерфейс абстрагирован (`ClassifierProvider`), чтобы можно было подменить на локальную small-модель для корпоративного контура.
7. **Бюджет латентности** (напр. 300 мс) → превышение = fail-closed на детерминированное решение.

Ориентир стоимости: stage-1 ≈ 1 выходной токен на малую долю действий → overhead в разы меньше самого агент-рана.

## 4. Интерфейсы (черновик)

```ts
// Общий провайдер — абстракция над моделью (remote small / local)
interface ClassifierProvider {
  // Stage 1: один токен. true = "нужен человек / подозрительно".
  flag(prompt: string, signal: AbortSignal): Promise<boolean>
  // Stage 2: короткое обоснование + вердикт (вызывается только если flag=true).
  judge(prompt: string, signal: AbortSignal): Promise<{ verdict: "allow" | "ask" | "deny"; confidence: number }>
}

// Action Classifier: работает ТОЛЬКО на soft-ASK
interface ActionClassifierInput {
  userRequest: string                 // trusted intent
  action: NormalizedAction            // executable/argv/paths/effect (без raw output)
  sessionFacts: { readSecret: boolean; sawSuspiciousContent: boolean }
}
// Выход: как скорректировать soft-ASK
type ActionVerdict = "downgrade-allow" | "keep-ask" | "escalate-deny"

// Context Checker: сигналы, не блокировка
interface ContextCheckInput {
  source: "readme" | "mcp" | "web" | "tool-result" | "docstring"
  content: string                     // усечённый недоверенный контент
}
interface ContextRiskSignal {
  suspicious: boolean
  categories: Array<"exfil-instruction" | "destructive-instruction" | "policy-tamper" | "other">
}
```

Точки интеграции:
- Action Classifier — в `gate.ts`, после `engine.evaluate()`, только в ветке `decision.action === "ask" && !decision.hard`.
- Context Checker — на пути tool-result (SessionProcessor / место, где входной контент попадает в контекст); результат → `SecuritySessionState` (флаг `sawSuspiciousContent` + категории). Дальше его читают risk-score и Action Classifier.

## 5. Что делаем в первую очередь (приоритеты)

**Phase 0 — быстрые детерминированные фиксы (не LLM, но усиливают основной контур).**
Закрыть найденные бенчмарком дыры правилами: value-based taint (за `cp`/`mv`/encode), анализ аргументов интерпретаторов (`python -c`/`node -e`), egress-каналы (`curl -F`/`--data-urlencode`), `git stash -u`. Дёшево, on-thesis, поднимает базу перед LLM.

**Phase 1 — LLM Action Classifier (ПЕРВЫЙ LLM-слой). ← начинаем с него.**
Почему первым:
- бьёт в главную продуктовую метрику — **Friction ↓ / approval fatigue** (реже дёргаем человека на soft-ASK);
- минимальная поверхность (только soft-ASK), не может снизить безопасность (DENY/hard-ASK неприкосновенны);
- сильный differentiator и понятная демонстрация.
Объём: `ClassifierProvider` (mock + remote), `action.ts`, интеграция в `gate.ts` за флагом, unit-тесты инвариантов (не понижает DENY/hard-ASK; fail-closed).

**Phase 2 — LLM Context Checker (ВТОРОЙ LLM-слой).**
Закрывает пробел «не сканируем вход на инъекции». Только сигналы в Session State → усиливает risk-score и multi-step детекцию (напр. «видел подозрительный README» + последующий egress → жёстче).
Объём: `context.ts`, хук на tool-result, запись сигналов в state, fail-open (сигнал-only не блокирует).

**Phase 3 — Бенчмарк-ablation.**
Добавить ступени `+action-classifier` и `+context-checker` поверх лестницы. Показать:
- Action Classifier: **Friction ↓** при ~равном ASR (и Latency/Cost ↑ — честный trade-off);
- Context Checker: **ASR ↓** на injection/multi-step.
Классификатор в бенче — **mockable** (детерминированный по умолчанию), плюс opt-in прогон с реальной моделью для headline latency/cost.

## 6. Порядок реализации (чек-лист)

- [ ] Phase 0: детерминированные фиксы 4 дыр + прогон (подтвердить ASR ↓)
- [ ] `ClassifierProvider` интерфейс + mock-провайдер
- [ ] `action.ts`: two-stage, reasoning-blind, инварианты
- [ ] интеграция в `gate.ts` (только soft-ASK) за feature-флагом
- [ ] unit-тесты: не понижает DENY/hard-ASK; fail-closed; мемоизация
- [ ] бенч-ступень `+action-classifier` (mock) + метрика Friction
- [ ] `context.ts` + хук tool-result → Session State сигналы
- [ ] бенч-ступень `+context-checker` + метрика ASR на injection
- [ ] (опц.) remote-провайдер + прогон с реальной моделью для latency/cost
