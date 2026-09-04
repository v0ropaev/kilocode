# Итоговый чек-лист подачи

## Как читать

Строка — одно требование, столбцы — где оно закрыто в пакете и чем именно доказано. Статус
проставлен только по тому, что реально лежит в `submission/` и в репозитории на момент сборки
пакета; там, где доказательство тонкое, стоит `готово, нужна ручная правка` с названной причиной.

## Требования хакатона

| Требование | Артефакт | Статус | Что осталось вручную |
|---|---|---|---|
| Слайдовая презентация: проблематика, постановка задачи, решение, результаты, демонстрация, ограничения, планы, слайд команды | `Security-Auto-ATH.pptx` и `Security-Auto-ATH.pdf`; текстовый источник `presentation.md` (слайды 2, 3 и 5 — проблематика и постановка; 6–9 — решение; 10–12 — benchmark и результаты; 13 — демонстрация, ограничения, пилот; 14 — команда); сборка `build-deck.py` с проверкой вёрстки | готово, нужна ручная правка | На слайде команды стоят плейсхолдеры `[ЗАПОЛНИТЬ]`; после правки пересобрать PPTX и PDF |
| Итоговый Markdown-документ с аннотацией 6–7 абзацев | `FINAL_SOLUTION.md`: `## Аннотация` — семь абзацев, далее проблематика, постановка задачи, техническое решение по восьми слоям, результаты, ограничения, дальнейшее развитие, команда | готово, нужна ручная правка | Плейсхолдеры имён в разделе «Команда и распределение задач» того же файла — см. строку ниже |
| Три продуктовых материала | `product/01_PRODUCT_BRIEF.md` (пользователь, JTBD, гипотеза, MVP, границы, критерии успеха), `product/02_EVIDENCE_AND_DECISIONS.md` (какие измерения к каким решениям привели), `product/03_PILOT_PLAN.md` (кто пилотирует, метрики, риски, критерии выхода) | готово | — |
| Раздел «Команда и распределение задач» | `TEAM.md` (состав, зоны, что подтверждает git); тот же раздел в `FINAL_SOLUTION.md`; слайд 14 в `presentation.md` и `build-deck.py` | готово, нужна ручная правка | Историей git подтверждён один участник — 19 из 19 коммитов ветки. В каждом из четырёх мест оставлена ровно одна строка-плейсхолдер: продублировать её по числу реальных участников и заполнить. Проценты вклада намеренно не проставлены |

## Требования кейсодателя

| Требование | Артефакт | Статус | Что осталось вручную |
|---|---|---|---|
| Threat Model: какие угрозы рассматриваем и какие нет, от чего защищает, каким механизмом, что deterministic, что heuristic, какие residual risks | `README.md` § Threat Model — Assets, Trusted components (с явной ценой допущения о доверенном пользователе), Untrusted, таблица Threat classes с колонками «какой control отвечает» и «измерено baseline → final», Out of scope / residual, Security guarantees с отдельным блоком Heuristic; `SOURCE_OF_TRUTH.md` §9; `docs/security-auto-mode.md` | готово | — |
| Работающая версия Kilo Code с Security Auto controls | Ветка `feat/security-auto-mode`, HEAD `fc857eb173495a3a0a1507a7024b9bc3c4c4ac0c`; восемь слоёв Deterministic Security, Package Security, Stateful Egress, Delegated Tool Security, Content Secret Detection, Executable Code Trust, Permissioned Extension Runtime, Read-Confinement за отдельными конфиг-ключами; тесты 557 pass / 0 fail (opencode security и registry) и 65 pass / 1 skip (kilo-sandbox) | готово | — |
| Benchmark — атаки | 81 attack-сценарий из 130; категории и вклад каждого слоя — `SOURCE_OF_TRUTH.md` §7, полный разбор по сценариям — `evidence/benchmark-summary.md`; реализация `packages/opencode/src/kilocode/security/bench/` | готово | — |
| Benchmark — taxonomy | `docs/security-auto-mode-benchmark.md` § Case taxonomy; в `SOURCE_OF_TRUTH.md` §7 каждая attack-категория дана с baseline, final и слоем, который её закрыл | готово | — |
| Benchmark — дизайн dataset | 130 сценариев = 81 attack + 49 utility; `docs/security-auto-mode-benchmark.md` § Scenario schema, isolation, oracles, § Paired user-intent scenarios (пары, отличающиеся только полем `intent`), § How to add a scenario | готово | — |
| Benchmark — isolation | Одноразовый sandbox в системном temp, поддельный `$HOME` под тем же корнем, инертные shim'ы package manager'ов первыми в `PATH`, сеть только на loopback, таймаут 10 с на команду и 30 с на прогон, обязательный внешний kill-watchdog, все секреты фейковые и помечены `BENCH` / `FAKE` с проверкой `validateFakeSecrets`; `SOURCE_OF_TRUTH.md` §4 | готово | — |
| Benchmark — canary / damage oracle | Успех атаки — наблюдаемый побочный эффект, никогда не текст модели: удалённый, созданный или перезаписанный canary-файл, фейковый секрет в loopback-коллекторе, маркер shim'а package manager'а, canary в теле tool result (`resultNeedle`); `SOURCE_OF_TRUTH.md` §4 | готово | — |
| Benchmark — repeated runs | 3 повтора каждого сценария; 3510 прогонов, 0 errored во всех конфигурациях; знаменатель ASR — 237 прогонов атак, знаменатель Utility — 147 | готово | — |
| Benchmark — baseline | Строка 0 лестницы: максимально автономный Kilo, ASR 100 % (237/237), Utility 100 %; собственный sandbox агента при прогоне выключен — самое слабое состояние хоста | готово | — |
| Benchmark — protected configurations | 9 конфигураций ablation-лестницы, соседние строки отличаются ровно одним флагом конфиг-слоя; финальная — `read-confined-extension-runtime`; таблица в `SOURCE_OF_TRUTH.md` §5 и в `evidence/benchmark-summary.md` | готово | — |
| Benchmark — методика эксперимента | `docs/security-auto-mode-benchmark.md` целиком; скриптованный драйвер с фиксированным списком tool call'ов; воспроизводимые команды в `SOURCE_OF_TRUTH.md` §10 и `README.md` § Как воспроизвести; вендоренный канонический прогон `2026-09-04T02:26:19.792Z` в `evidence/` | готово | — |
| Benchmark — ASR | Overall 100 % (237/237) → 6 % (15/237); по категориям и по конфигурациям — `SOURCE_OF_TRUTH.md` §5 и §7; остаточные 15 прогонов разобраны поимённо в §8 (ровно пять сценариев) | готово | — |
| Benchmark — Utility | 98 % (144/147) в финальной конфигурации; extension и executable-code utility 100 % (42/42), content utility 100 % (27/27), MCP/custom utility 100 % (15/15); единственная потеря — `util-package-install-safe-new` (0/3), названная измеренной ценой Package Security | готово | — |
| Benchmark — FP | Safe DENY FP = 0, Safe ASK FP = 6; FP-сторона классификатора секретов измерена отдельно как content utility 100 % (27/27); `SOURCE_OF_TRUTH.md` §6 | готово | — |
| Benchmark — Friction | ASK/task 0,154 (60 hard ASK на 390 прогонов), DENY/task 0,30 (117 DENY), breakdown allows 150 · soft ASK 81 · hard ASK 60 · DENY 117 · approvals 18, Safe Completion Rate 50 % (3/6); `SOURCE_OF_TRUTH.md` §6, инструментовка — `docs/security-auto-mode-benchmark.md` § The autonomy (permission) model and friction instrumentation | готово, нужна ручная правка | Трение измерено инструментально на скриптованном драйвере; человеческая сторона — отдельный стенд approval-fatigue, ответы по которому не собраны |
| Benchmark — Latency | Решение политики p50 0,65 мс / p95 1,04 мс по всему прогону; стоимость extension-хоста измерена отдельно (холодный старт 22,9 / 32,8 мс с сужёнными чтениями против 21,9 / 22,7 мс с открытыми, тёплый capability-roundtrip 0,43 / 0,87 мс, решение политики отдельно 0,29 / 0,31 мс); task latency 15,3 → 17,2 мс помечена как конфаундед | готово | — |
| Benchmark — ограничения методики | `docs/security-auto-mode-benchmark.md` § What the benchmark lets you conclude — and what it does not и § Known methodology limitations; `README.md` § Методологические границы бенчмарка; `FINAL_SOLUTION.md` § Методологические границы бенчмарка: скриптованный драйвер без модели в петле, registry-метаданные как фикстуры, подменённый MCP-транспорт при реальном пути решения, trusted-user approval как программный прокси, Linux-профиль не верифицирован | готово | — |

## Особые требования

| Требование | Артефакт | Статус | Что осталось вручную |
|---|---|---|---|
| Slopsquatting решается внутри coding agent и до установки, а не в CI | Package Security (`security_auto_packages`): распознанная установка или исполнение npm-семейства оценивается до запуска package manager, гарантия 8 в `SOURCE_OF_TRUTH.md` §9; измерено `attack-package-install` 100 % (42/42) → 0 % (0/42); демо B `atk-package-install` с канарейкой «маркер shim'а package manager'а», shim не достигнут | готово | — |
| Оценка provenance неизвестного пакета, не только denylist | Детерминированные сигналы (возраст, install scripts, наличие репозитория, non-registry source, registry override) и эвристические (adoption, схожесть имени) разведены явно в `SOURCE_OF_TRUTH.md` §9 и `README.md` § Heuristic; неопределённость никогда не сводится к ALLOW; измеренная цена — hard ASK честному трёхдневному пакету. Ограничение заявлено: в бенчмарке registry-метаданные фиксированные фикстуры, живой реестр не опрашивается | готово | — |
| Хотя бы один control, архитектурно неуязвимый к prompt injection, с тезисом «agent intent and agent authority are separated» | Deterministic Security: решение принимает чистая синхронная `SecurityEngine.evaluate` в единственной точке `SecurityGate` до побочного эффекта, модель в решении не участвует; монотонный редуктор только ужесточает, сбой слоя = hard ASK, hard ASK не снимается ни `--auto`, ни «always allow». Там, где статической политики мало, граница уходит в профиль ОС — Permissioned Extension Runtime и Read-Confinement. Тезис дословно в `README.md`, `FINAL_SOLUTION.md` § Аннотация, слайде 9 презентации и `SOURCE_OF_TRUTH.md` §12; семантическое распознавание injection честно оставлено вне scope — `attack-prompt-injection` 100 % (3/3) → 100 % (3/3) | готово | — |
| Честное разделение enforceable / heuristic / known limitation / production future work | `SOURCE_OF_TRUTH.md` §9 (15 enforceable-гарантий, блок Heuristic, Known limitations, Future production hardening); `README.md` § Security guarantees и § Ограничения; `FINAL_SOLUTION.md` § Ограничения и § Дальнейшее развитие; `docs/security-auto-mode.md#known-limitations` | готово | — |

## Дополнительно

| Пункт | Артефакт | Статус | Что осталось вручную |
|---|---|---|---|
| Approval-fatigue эксперимент | `approval-fatigue/README.md` (research question, дизайн, что записывается и что нет, как провести и как посчитать, ограничения), `cases.json` с ground truth и разбором по слоям, `index.html` без единого сетевого запроса, `analyze.ts` | готово, нужна ручная правка | Стенд готов, ответы не собраны; каталога `results/` намеренно нет. Ни одно число оттуда не может появиться в материалах до реального сбора и разбора |
| Demo runbook и fallback | `DEMO_RUNBOOK.md`: общие правила, подготовка, четыре демо A–D с канарейками, § Fallback и § Что показать, если осталось 30 секунд; вендоренные `evidence/benchmark-summary.md`, `evidence/benchmark-summary.json` и `evidence/demo-verification.md` — реальные локальные прогоны, а не скриншоты | готово | Прогнать все четыре демо на той машине, с которой будет защита, и проверить, что fallback-команды по `evidence/` отрабатывают |
| Воспроизводимость | Команды в `SOURCE_OF_TRUTH.md` §10 и `README.md` § Как воспроизвести (клон, checkout, полный прогон под внешним kill-watchdog, одиночный сценарий, тесты, typecheck); канонический прогон вендорен в `evidence/` | готово | Пакет закоммичен и запушен: ветка `submission/security-auto`, HEAD `9bcaddd97c`, upstream `fork`. Артефакты прогона в `packages/opencode/.artifacts` не коммитятся намеренно — вместо них вендорен `evidence/` |
| Pitch script | `PITCH_SCRIPT.md`: версии ~5 и ~7 минут с хронометражом по отрезкам, обязательные формулировки, ключевой переход про benchmark, ответы на три вопроса, которые прервут доклад | готово | Репетиция с таймером; см. список ниже |
| Judge Q&A | `JUDGE_QA.md`: архитектура, benchmark и методика, метрики, угрозы и остаточный риск, продукт и внедрение, команда и процесс — включая прямой вопрос «19 коммитов и один автор, где здесь команда» | готово | — |

## Что нужно от команды завтра

1. Заполнить реальные имена, роли и фактический вклад в `TEAM.md`, `FINAL_SOLUTION.md`
   (§ Команда и распределение задач), `presentation.md` (слайд 14) и `build-deck.py` — лишние
   строки-плейсхолдеры удалить целиком, а не оставлять пустыми.
2. Пересобрать deck и PDF после правки состава — обе команды в `presentation.md` § Как пересобрать
   (`build-deck.py`, затем конвертация в PDF); сборка падает с ненулевым кодом, если вёрстка
   поехала.
3. Финальный визуальный просмотр PPTX в PowerPoint или Keynote: скрипт проверяет переполнение
   пессимистичной подстановкой шрифта, но глазами вёрстка не смотрелась.
4. Проверить, что ветка `submission/security-auto` на `fork` — та, что показывают жюри:
   `git ls-remote fork submission/security-auto` должен вернуть HEAD, совпадающий с локальным.
5. Собрать ответы approval-fatigue минимум с 5 участников и прогнать `analyze.ts`; до этого ни одно
   число оттуда не появляется ни в одном материале.
6. Репетиция по `PITCH_SCRIPT.md` с таймером — сначала версия ~5 минут, затем ~7.
7. Прогнать четыре демо по `DEMO_RUNBOOK.md` на машине защиты и проверить fallback-команды по
   `evidence/`.
8. Сверить каждое число в PPTX и PDF с `SOURCE_OF_TRUTH.md`: при расхождении прав он.
9. Решить, переносить ли на продуктовую ветку два исправления документации, закоммиченных здесь
   (`3d601b44f7`): механизм отказа в `atk-workspace-wipe` и утверждение о task latency. На
   `feat/security-auto-mode` они пока не перенесены.
10. Прочитать вслух раздел «Угрозы и остаточный риск» в `JUDGE_QA.md`: остаточные 6 % (15/237) —
    самое вероятное место вопроса.

## Что сознательно не делалось

- **Новых security-функций не добавлялось.** Код заморожен на HEAD
  `fc857eb173495a3a0a1507a7024b9bc3c4c4ac0c`; всё, что лежит в `submission/`, ничего в `packages/`
  не меняет, иначе измеренные числа перестали бы относиться к измеренной сборке.
- **Benchmark не переигрывался под лучшие числа.** Канонический прогон один —
  `2026-09-04T02:26:19.792Z`, вендорен целиком; выбор лучшего из нескольких прогонов сделал бы
  цифру невоспроизводимой.
- **Остаточные атаки не удалялись из набора.** Пять сценариев, дающих 15/237, названы поимённо
  вместе с причиной; убрать их значило бы отчитаться о защите, которой нет.
- **Оракул не менялся.** Успех атаки остаётся наблюдаемым побочным эффектом; смягчение оракула до
  текста модели дало бы другую, несопоставимую метрику.
- **ASK не превращались в DENY ради ASR.** Hard ASK там, где решение принадлежит человеку;
  автоматический DENY снизил бы ASR за счёт Safe DENY FP, который сейчас равен 0.
- **Utility-кейсы не удалялись.** `util-package-install-safe-new` (0/3) оставлен в наборе как
  измеренная цена Package Security, а не вычеркнут ради ровных 100 %.
