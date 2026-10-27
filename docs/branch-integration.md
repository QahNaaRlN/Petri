# Интеграция платформенных кандидатов в dev и main

Дата: **2026-10-27, Asia/Yekaterinburg**. Запись объединения истории и инвариантов общей линии.

Владелец разрешил объединить все три кандидатные ветки в `dev`, затем продвинуть
общий результат в `main`. Это разрешение на Git-интеграцию. Оно не является
нативной квалификацией backend, приёмкой всех требований или выпуском Petri 1.0.
Версия CLI остаётся `0.3.0`; `0.4-draft1` обозначает редакцию ТЗ/ТС.

## Закреплённые входы

Это снимки до интеграции, а не обещание неизменности последующих head веток.
Обновление PR-ветки для актуальной базы сохраняет достижимость исходного кандидата.

| Кандидат | Ветка | Исходный commit | Содержание и предел |
| --- | --- | --- | --- |
| Linux | `feat/linux-native-candidate` | [`ddcd8372bce1c1d52d75ad74c315c43f9b146b3b`](https://github.com/QahNaaRlN/Petri/commit/ddcd8372bce1c1d52d75ad74c315c43f9b146b3b) | Подготовленная Linux-реализация и её governance/CI. Суммарные cgroup-бюджеты и hard disk quota не добавлены. |
| Windows | `feat/windows-native-candidate` | [`004ac659a1a17ba7de9c563363487233a384e19c`](https://github.com/QahNaaRlN/Petri/commit/004ac659a1a17ba7de9c563363487233a384e19c) | Собственный offline CPython-кандидат на LPAC/Job Objects. Нативная Windows-квалификация остаётся `UNVERIFIED`. |
| macOS | `feat/macos-native-candidate` | [`f7042dcf4e0122ebab8666b5a0652cb8b2f83889`](https://github.com/QahNaaRlN/Petri/commit/f7042dcf4e0122ebab8666b5a0652cb8b2f83889) | ТЗ/ТС, Apple API assessment, план, критерии, packaging fixtures и read-only preflight. Backend `NOT IMPLEMENTED`; native qualification `UNVERIFIED`. |

В локальном снимке перед этой интеграцией `origin/dev` и `origin/main` указывали на
[`f7a2af7916ac5db10fa4eb9330ed8336c5b933b7`](https://github.com/QahNaaRlN/Petri/commit/f7a2af7916ac5db10fa4eb9330ed8336c5b933b7).
Результаты опубликованных PR и новые удалённые SHA фиксируются ниже после проверки.
Исходный Linux runtime commit `70e0bc69c1a5be0761f073e69b6efae9a751b22d`
и последующие общие контракты сохраняются в истории; кандидаты не являются тремя
независимыми реализациями одного и того же ядра.

## Маршрут и подтверждения

Используется действующий поток **рабочая ветка → dev → main** с merge commits,
без force push и обхода защиты. При конфликтах сохраняется совокупный результат
кандидатов и явно исправляются устаревшие текущие описания. Исторические отчёты,
исходные документы и прежние `FAIL`/`UNVERIFIED` не переписываются.

| Шаг | Направление | Источник фактических результатов |
| --- | --- | --- |
| Linux | `feat/linux-native-candidate` → `dev` | [PR #2](https://github.com/QahNaaRlN/Petri/pull/2), merge `e366bebaf428d5286134d559e1486374911b9374`; пять CI checks исходного head прошли |
| Windows + macOS | `chore/integrate-native-candidates` → `dev` | [PR #3](https://github.com/QahNaaRlN/Petri/pull/3); обе ветки объединены обычными merge commits, не cherry-pick |
| Promotion | `dev` → `main` | Отдельный PR из `dev` этого репозитория; accepted head, merge SHA и результаты checks берутся из GitHub PR/Actions |

В интеграционной рабочей ветке коммиты `23c3346` и `a6936f3` объединяют исходные
Windows/macOS heads поверх Linux merge. До согласования текущей документации и
интеграционных исправлений дерево точно совпало с `f7042dc`; это проверено через
`git diff --exit-code f7042dc`.

При завершении объединения проверяются следующие инварианты на фактических
удалённых refs, а не на устаревших local branches:

- Все три закреплённых кандидатных SHA — предки `origin/dev` и `origin/main`.
- Содержимое `docs/sources/` совпадает с Linux baseline `70e0bc6`; SHA256 всех
  четырёх DOCX и четырёх TXT совпадают с сохранёнными SHA256SUMS.
- Дерево promotion `main` совпадает с принятым деревом `dev`.
- Для каждого PR выполняются пять required checks на его окончательном head;
  native Windows/macOS qualification при этом не подменяется portable CI.

Точные конечные SHA не встраиваются в файл собственного commit: авторитетные
merge receipts и проверки хранятся в GitHub PR/Actions. Документ описывает
состав и проверяемые условия интеграции; наличие файла само по себе не означает
успешный merge или зелёный CI.

## Выявленные интеграционные исправления

Проверки общей ветки обнаружили Windows mismatch обычных и канонических drive paths, выбор default Administrators owner на elevated CI runner и непереносимые macOS TempDir/case-sensitive предположения фикстур. Исправления нормализуют только local-drive spelling, явно назначают TokenUser новым приватным объектам и сохраняют отказ для чужих существующих объектов. Runtime admission обычного Windows 11 пользователя не ослабляется. macOS positive fixtures используют канонический temp root; production no-alias guards сохраняются. Эти исправления проверяются заново на CI окончательного PR head.

## Что интеграция не меняет

- [Статус реализации](status.md), [Windows-квалификация](windows-native-candidate.md)
  и [подготовка macOS](macos-native-candidate.md) сохраняют свои платформенные
  ограничения. Наличие кода в `main` не доказывает изоляцию на настоящей ОС.
- Linux E2E требует пригодного rootless/Landlock runner. Старый успешный прогон
  не становится доказательством нового head без его отдельной проверки.
- Portable tests, cross-build и read-only macOS preflight не заменяют native
  Windows/macOS security qualification. Preflight не запускает sandbox.
- Реальный агент, Meridian adapter, provider/network broker, Vault, ConPTY,
  hard disk quotas, полная Docker/Compose-совместимость и итоговые выпускные
  требования остаются работами из [ТЗ](requirements.md) и платформенных планов.
- Petri возвращает lab/execution/runtime facts. Постановка, роли, надзор,
  handoff, инженерная приёмка и решение об интеграции результата остаются в Meridian.

Политика веток и защиты: [repository-governance.md](repository-governance.md).
Эта запись описывает конкретную разрешённую интеграцию, а не ослабляет её правила.
