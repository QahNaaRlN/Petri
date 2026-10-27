# ТЗ — подготовка и реализация нативного Petri для macOS

Версия документа: **0.1-preparation**, 2026-10-27, Asia/Yekaterinburg.
Ветка: `feat/macos-native-candidate`. Статус: **готов пакет подготовки; backend не реализован и не квалифицирован**.

## 1. Цель и происхождение

Дать человеку и агенту ту же модель лаборатории Petri на ядре macOS:
независимый исходный снимок, нативные инструменты, ограниченное исполнение,
наблюдения, остановка, checkpoint и явное принятие результата. Docker, MXC,
Linux VM, WSL и системный Git не являются основой исполнения. macOS-программы
исполняются на macOS; одинаковый UX не означает одинаковые механизмы ядра.

Подготовленная основа: Linux runtime `70e0bc6`, Windows native `69f6009` и
исправление ссылок на кандидатные ветки `a26220a`. Ветка macOS продолжает
Windows-кандидат ради общих механизмов, а не потому, что Windows Job/LPAC
можно перенести на Darwin. `main`/`dev` этим пакетом не интегрируются.

Общие продуктовые требования сохраняются в [основном ТЗ](requirements.md).
Этот документ уточняет следующий macOS-пакет и его проверяемые ограничения.
Техническое решение — [macOS ТС](macos-technical-specification.md), факты API —
[оценка API](macos-api-assessment.md), порядок работ —
[план реализации](macos-implementation-plan.md), проверки —
[матрица приёмки](macos-acceptance.md).

## 2. Два разных результата

**Подготовка сейчас:** ТЗ/ТС, оценка доступных API, план, контракты изменений,
шаблоны минимальных entitlements, read-only preflight и критерии приёмки.
Не выполняются установка, подпись пользовательским ключом, изменение TCC/SIP,
создание системных пользователей, запуск агента или публикация приложения.

**Реализация следующим пакетом:** сначала ограниченные native feasibility
prototypes на собственных canary-данных, затем backend после приёмки обязательных
свойств. Наличие entitlement, скомпилированного helper или подходящей версии ОС
не закрывает такую приёмку. Неудавшийся обязательный gate означает blocker;
неизолированный запуск не является успешным частичным результатом.

## 3. Первый qualification target

- macOS **26**, Apple silicon **arm64**, стандартная учётная запись без admin.
- Одна явно закреплённая patch/build, локальный APFS; фактическая конфигурация
  выбирается на доступном Mac и записывается до опыта. Номер build не выдумывается.
- Headless **CPython 3.12 с точным patch и digest**, stdlib-only, свой fixture,
  явный executable/argv, сеть `none`.
- Затем две параллельные лабы, чтобы проверить независимость данных и полномочий.
- Версии SDK/Xcode, deployment target, hardware, подписи и весь состав toolchain
  входят в qualification manifest. Это охват кандидата, не API minimum.

Intel/x86_64, другие версии ОС, Node/Rust, GUI, PTY, live provider, Keychain,
SSH/signing broker и полноценная IDE проверяются отдельными пакетами. Их
отсутствие не отменяет обязательную цель трёх нативных ОС всего Petri.

## 4. Обязательные требования кандидата

| ID | Требование |
| --- | --- |
| MAC-N01 | Использовать собственные adapter/controller/guardian Petri и нативные средства macOS. Не включать MXC, VM, Docker или host exec как fallback. |
| MAC-N02 | Проверять точные OS/arch/filesystem/signing prerequisites; неподдержанная конфигурация явно отклоняется до workload. |
| MAC-N03 | Первым исследовать публичный App Sandbox с отдельным подписанным helper. Выбор production-механизма зависит от feasibility gates. |
| MAC-N04 | Не считать custom Seatbelt/SBPL стабильным публичным контрактом. Не переходить к нему или Endpoint Security без нового явного ADR и пересмотра критериев. |
| MAC-L01 | Lab, Execution и Operation имеют разные IDs; повтор start/stop с тем же ключом не создаёт повторный эффект. Конфликтующий запрос отклоняется. |
| MAC-L02 | Ready подтверждается доверенным helper после обязательной защиты и до недоверенного исполнения; Running — после наблюдаемого запуска. |
| MAC-L03 | Stop и timeout охватывают всех потомков, включая fork/exec, double-fork, смену session/group, и подтверждают отсутствие оставшихся эффектов. |
| MAC-L04 | Потеря controller/guardian не превращает отсутствие root PID в доказательство остановки. Unknown блокирует новый запуск, restore, публикацию и discard. |
| MAC-L05 | POSIX exit status и signal сохраняются отдельно. Windows DWORD и Windows Job facts не переинтерпретируются как macOS данные. |
| MAC-I01 | Лаба не читает и не меняет source repo, control metadata, Git metadata, blackbox, checkpoint и данные другой лабы. |
| MAC-I02 | Все доступные writable области, включая собственный app-container, temp, preferences/caches и служебное хранилище, перечислены явно. Изменение HOME не считается access control. |
| MAC-I03 | Одинаковый app/helper identifier не считается автоматически отдельной lab identity. Проверяются одновременные и последовательные лабы, старые handles и повторное использование identity. |
| MAC-I04 | Toolchain доступен на чтение/исполнение без записи из лабы. Динамическое право чтения не приравнивается к праву exec/dlopen. |
| MAC-I05 | Проверять symlink/hardlink, APFS clones, case aliases, Unicode equivalence, extended attributes/resource forks и подмену предков. Неподдержанное представление отклоняется явно. |
| MAC-I06 | Сеть none проверяется по IPv4/IPv6, loopback/LAN, DNS, прямым соединениям и доступным локальным IPC/host-service путям с независимыми положительными контролями. |
| MAC-I07 | Не запрашивать Full Disk Access, отключение SIP/TCC, debugger, широкие app groups, Apple Events или arbitrary path exceptions для исправления отказа теста. |
| MAC-R01 | Ресурсные бюджеты имеют явные единицы, scope и hard/observed статус. Per-process rlimits не называются aggregate limits лабы. |
| MAC-R02 | До допуска недоверенного агента доказать требуемые aggregate memory/process/CPU semantics либо признать профиль Unsupported. Числа Windows не создают механизм Darwin. |
| MAC-R03 | Wall/stop watchdog не зависит от записи журнала или callback workload. Если effect нельзя подтвердить, результат остаётся Unknown. |
| MAC-R04 | Output/event/request/staging bounds ограничивают и workload, и host collector. Soft disk sampling не называется hard quota. |
| MAC-G01 | Источник экспортируется из закреплённого committed HEAD встроенной Git-библиотекой, без host hooks/filters/helpers. Dirty/untracked данные не копируются молча. |
| MAC-G02 | Host Git операции связываются с собственными метаданными Petri; workload `.git`, пути, config и команды не предоставляют host полномочий. |
| MAC-G03 | Checkpoint/restore возможны только при доказанной остановке под одной блокировкой; snapshot не включает память, сессии или credentials и не откатывает audit. |
| MAC-O01 | Управляющие журналы и итоговые артефакты находятся вне writable областей нагрузки. Общий лимит событий сохраняет резерв для stop/terminal. |
| MAC-O02 | Result manifest содержит input/source/tool/runtime/helper/policy identities, фактические ограничения, exit/signal, stop evidence, digests и gaps. Exit 0 не означает инженерную приёмку Meridian. |
| MAC-O03 | Pipe capture не называется PTY, полным kernel audit или доступом к скрытому reasoning модели. Сырые пользовательские данные не собираются без необходимости. |
| MAC-C01 | Linux legacy и Windows `petri.control/v1` / native-v2 сохраняют прежние форматы. Новые macOS contracts не дописываются как совместимые поля к закрытым Windows enum/структурам. |
| MAC-C02 | Общая модель V3 и новый protocol version разрабатываются явно, с rejection старых writers и отдельной migration policy. Миграция не выполняется автоматически. |
| MAC-P01 | Подпись, Hardened Runtime и notarization проверяются раздельно от App Sandbox. Ad-hoc prototype не объявляется Developer ID release. |
| MAC-P02 | Подписывающий ключ, Team ID и entitlement approvals не предполагаются существующими. Release secrets/identities не попадают в Git или workload. |

## 5. Ресурсы и обязательные решения перед реализацией

Для сравнительного fixture можно использовать значения Windows-кандидата:
8 процессов, 512 MiB, 10 секунд CPU, 30 секунд wall, 3 секунды stop,
8 MiB output, 16 MiB journal. Это **предлагаемые входы опыта**, а не уже
действующие macOS гарантии. До backend-приёмки нужно зафиксировать memory
metric, состав учитываемого дерева, user/kernel CPU, момент начала budget,
обработку denial, реакцию guardian и независимое подтверждение прекращения.

Не разрешается улучшать результат сравнением разных метрик: Windows committed
memory, Darwin RSS и physical footprint — разные величины. Отсутствующая hard
disk quota остаётся явным gap; допустимость первого контролируемого fixture не
означает допуск произвольного агента или отсутствие disk DoS.

## 6. Доказательства и готовность

Перед каждым native опытом фиксируются manifest и независимый test oracle.
Нет endpoint/предпосылки/наблюдения — **UNVERIFIED**, а не PASS. Исследования
проводятся на одноразовых собственных файлах, собственных endpoints и процессах,
без настоящих credentials, чужих служб и изменения защиты рабочей машины.

Полный допуск блокируют: исполнение bundled/imported tools; независимость lab
identity; контроль потомков и crash-stop; обязательные resource budgets;
network/IPC none; безопасная файловая коллекция; журнал при faults; подписанный
пакет и platform regression. Точные опыты перечислены в связанных ТС/матрице.

Подготовка завершена, когда материалы и read-only preflight опубликованы в
кандидатной ветке. Следующая конкретная работа — MP-00/feasibility из плана;
реальный runtime остаётся не реализованным до последующих code packages.
