# Диаграммы

`architecture.mmd` — каноничный слоёный поток Security Auto: tool call проходит Normalization,
SecurityGate и SecurityEngine, evidence-слои подают свидетельства в тот же монотонный reducer, и
решение ALLOW / ASK / DENY доходит до executor'а. Отдельно показаны две границы, работающие до
появления tool call'а: Executable Code Trust и Permissioned Extension Runtime с Read-Confinement.
Trust boundary между untrusted-стороной и enforcement'ом отмечен явным узлом.

`evaluation-loop.mmd` — измерительный цикл: найти атаку, воспроизвести в одноразовом fixture,
поставить canary, снять baseline, снять protected, измерить ASR, Utility, FP, friction и latency,
зафиксировать новый residual и вернуться к началу.

Рендер: содержимое файла вставляется в fenced-блок с языком `mermaid` и рисуется в GitHub, Obsidian
и большинстве просмотрщиков Markdown; в SVG — `mmdc -i architecture.mmd -o architecture.svg`.

Презентация воспроизводит обе схемы нативными фигурами, а не вставленной картинкой: эти файлы —
источник структуры и подписей, а не готовый экспорт. Числа в схемы не выносятся, их источник —
`submission/SOURCE_OF_TRUTH.md`.
