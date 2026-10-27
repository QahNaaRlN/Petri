# ТС — Petri: собственное нативное ядро защищённой лаборатории

Версия: **0.4-draft1**. Дата: **2026-10-26**. Статус: **проект технического решения**.

Документ описывает предлагаемую реализацию требований [ТЗ](requirements.md).
Он задаёт целевое решение; реализация кандидата не означает приёмку всего документа или выпуск. Фактические ограничения отражены в [статусе](status.md).
Принято направление собственного нативного ядра Petri для каждой ОС; детали
первого Windows-профиля и критерии его реализации предъявляются на ревью.

## 1. Решение и граница текущего пакета

Petri владеет моделью лаборатории, жизненным циклом, политиками, Git, артефактами
и реализацией исполнения. Для ОС используются её документированные механизмы
через системные API и Rust bindings. MXC SDK, MXC runtime, Docker Engine,
Docker Desktop и системный Git executable не являются основой исполнения.

Первый следующий backend — **Windows native**. Linux-код снимка
`70e0bc69c1a5be0761f073e69b6efae9a751b22d` сохраняется отдельным backend.
Нативный macOS остаётся целью продукта, но его механизм и профиль будут предметом
отдельной ТС; настоящая редакция не обещает ему готовые гарантии.

Windows-нагрузка исполняется непосредственно под Windows. WSL, Linux VM,
Windows Sandbox и автоматический запуск без защиты не являются запасным путём.
Отсутствующая обязательная возможность означает `Unsupported` до нагрузки.
ОС-библиотеки и Windows SDK bindings допустимы; чужой sandbox SDK не подменяет
собственную реализацию. Повторное использование стандарта OCI для Linux-стеков
не означает зависимости от Docker.

## 2. Модель доверия

Доверены поддерживаемая ОС, обновлённое ядро, Petri controller/guardian,
зарегистрированный native toolchain и пользователь, задающий полномочия.
Недоверен весь процесс нагрузки и его потомки: модель, shell, код проекта,
build hooks, зависимости, результаты инструментов и созданные ими файлы.

Изначально в лабораторию попадает копия закреплённого коммита, а не исходный
checkout. Исполнитель не получает host Git metadata, управление Petri, ключи,
реальную БД Meridian, blackbox на запись или токен доверенного controller.
Доступность данных и право выполнить host-операцию — разные полномочия.

Не заявляются защита от администратора хоста, скомпрометированного ядра,
физического доступа, всех аппаратных side channels или любого отказа ресурсов.
Код проекта может быть вредоносным; ограничения должны действовать на всё его
дерево процессов независимо от того, следует ли он инструкциям агента.

Windows LPAC — граница прав внутри общего ядра Windows. Она не называется
гипервизорной изоляцией. Допустимость этой границы для первого профиля фиксируется
при приёмке с перечислением проверенных атак и непокрытых возможностей.

## 3. Архитектура

```text
CLI / будущий адаптер Meridian
  → Controller: проверка запроса, lab store, Git, решения и evidence
    → доверенный Guardian отдельной операции
      → Windows LPAC token + private Job + native process tree
      → Linux native supervisor + namespaces / LSM / seccomp
```

Controller остаётся единственным владельцем пользовательских решений и Git
promotion. Guardian является доверенным процессом Petri, а не кодом проекта.
Он владеет OS process/job handles конкретного `ExecutionId`, timer, ограниченными
stdio pumps и обязательным журналом исполнения. Он способен остановить нагрузку при отказе controller
или записи журнала без обращения к модели и без работающего журнала.

Petri controller владеет разрешениями только своего runtime-контура. Постановка,
роль, надзор и инженерная приёмка остаются в Meridian. Будущий адаптер передаёт
непрозрачные `caller_context` refs (workspace/work/run/actor и assignment/context
digests), допуск и correlation key. Petri сохраняет их происхождение и возвращает
в manifest, но не изменяет task/handoff/acceptance по исходу процесса.
Для первого offline-кандидата `caller_context` может отсутствовать.

Реализация остаётся в существующем Rust package Petri. Первое разбиение:

| Модуль | Ответственность |
|---|---|
| `main` / `cli` | Проверка CLI-синтаксиса, вывод; не скрытая политика backend |
| `labs` / `store` | Lab identity, locks, metadata, миграция, retention |
| `execution` | Execution/operation identities, lifecycle, manifest и протокол |
| `runtime::linux` | Существующий нативный Linux backend |
| `runtime::windows` | Probe, LPAC/ACL, suspended launch, Job, handles, stop |
| `runtime::macos` | Явный `Unsupported` до отдельного принятого профиля |
| `git` | Экспорт baseline, candidate diff/commit и host promotion |
| `observer` / `journal` | Доверенные события, output policy, bounded storage |
| `policy` / `profiles` | Строгая схема и backend-specific capabilities |
| `stacks` | Linux rootfs; не Windows toolchain под прежним именем |

Граница процесса Linux сохраняется: `fork` и setup не вызываются прямо из
многопоточного desktop/controller процесса. Разделение общей модели и backend
не требует одновременно переписать все существующие модули или создать сервер.

## 4. Первый квалифицируемый Windows-профиль

Идентификатор проекта профиля: `windows-native-python312-lpac/v1`.
Среда: **Windows 11 24H2 x64**, стандартная учётная запись без elevation.
Нагрузка: закреплённый portable **CPython 3.12**, собственный CLI fixture,
создание и остановка его потомков. GUI, ConPTY, Docker, системные службы,
драйверы и настоящее обращение агента к облачной модели в этот профиль не входят.

Точный build/patch ОС, версия Python, digest дистрибутива, исполняемых файлов,
DLL, fixture, Petri binary и политики записываются в candidate manifest перед
проверкой. Эта ТС не выдумывает подходящий patch или ожидаемый hash.
Поддержка не выводится только из строки `24H2`: проверяются нужные API и эффекты.

LPAC является обязательным default этого профиля. Обычный AppContainer может
появиться только как отдельно названный, явно выбранный и квалифицированный
профиль совместимости. Отказ LPAC не вызывает автоматическое понижение защиты.
Неадминистратор не должен получать запрос elevation для обхода этого отказа.

## 5. Probe и описание возможностей

`probe` не запускает недоверенную команду. Он проверяет архитектуру, доступность
API token/process attributes, создание private Job, настройку обязательных
лимитов, безопасный временный storage, handle allowlist и возможность LPAC.
Используется собственный безвредный probe fixture с явным назначением проверки.

Результат содержит backend/version, OS facts, профиль, `Supported`/`Unsupported`,
причины и capabilities. `Supported` относится к конкретному профилю и версии.
Probe не сертифицирует произвольную программу или рабочий проект.
Перед `start` существенные условия проверяются повторно; advisory-кэш не заменяет
проверку host state и digest используемого toolchain.

Для Windows первого среза capabilities включают только фактически реализованные
`native_exec`, `lpac`, `job_tree`, `stdio_pipes`, `network_none`, ограничения
процессов/commit memory/CPU/wallclock и stopped-only файловый checkpoint.
`conpty`, `gui`, `network_allowlist`, `live_provider`, `hard_disk_quota` и native
macOS отсутствуют до собственной реализации и квалификации.

Любое явно запрошенное неподдерживаемое поле приводит к `UnsupportedPolicy`.
Общие поля не принимаются молча только потому, что другой backend их понимает.

## 6. Лаборатория, исполнение, операция и persistent storage

`LabId` обозначает долговечную рабочую область. `ExecutionId` (`exec-*`) — одно
физическое исполнение. `OperationId` — отдельное управляющее действие, например
prepare/start/stop/collect/checkpoint; оно не является идентичностью процесса.
Операция без физического запуска может не иметь `ExecutionId`. Повтор операции
не перезаписывает argv, exit status или evidence прошлого исполнения.
Одновременно изменять одну lab может один действующий
владелец lease; параллельный запуск отклоняется `LabBusy`.

```text
<private-home>/
  metadata/<lab-id>/lab.json
  metadata/<lab-id>/executions/<execution-id>.json
  metadata/<lab-id>/operations/<operation-id>.json
  git/<lab-id>/
  blackbox/<lab-id>/<execution-id>/events.jsonl
  blackbox/<lab-id>/<execution-id>/output/
  journal/<lab-id>/operations.jsonl
  workspace/<lab-id>/
  temp/<lab-id>/
  profile/<lab-id>/
  checkpoints/<lab-id>/<checkpoint-id>/
  toolchains/<toolchain-id>/manifest.json
```

Это логическая схема; абсолютные пути выбираются явно или платформенным data
каталогом. Они не становятся идентичностью lab. Storage находится вне source
checkout. Путь home проверяется до подготовки и не может быть внутри источника,
workspace, toolchain или другого управляемого содержимого.

На Windows приватность обеспечивается проверенными owner/DACL/integrity labels
и объектной идентичностью; проверка строкового префикса пути недостаточна.
На Linux сохраняется требование private host directories/files и безопасного
открытия. Процессы с теми же полномочиями доверенного пользователя вне sandbox
относятся к доверенной стороне модели угроз.

### 6.1. Обязательные записи и состояния

| Запись | Обязательные поля |
|---|---|
| `LabRecord` | `schema_version`, `lab_id`, `metadata_revision`, source identity/commit, exported baseline digest, tagged environment ref, profile ref, execution refs, checkpoint refs, active execution либо null |
| `ExecutionRecord` | `execution_id`, `lab_id`, start `operation_id`, phase, outcome, stop state, cleanup state, exact command ref, requested/effective policy digests, environment digest, backend identity, durable resource binding и artifact refs |
| `OperationRecord` | `operation_id`, request digest, operation kind, target lab/execution/checkpoint, expected revision, intent, observed effect и receipt либо unknown |

Новый execution проходит `Created → Preparing → Ready → Running → Finalizing → Terminal`.
`Ready` означает установленную защиту до resume, `Running` — наблюдённый resume.
До resume отказ даёт `SetupFailed`; после resume нельзя задним числом назвать
эффект отсутствующим. При потере сведений состояние и outcome явно unknown.

Outcome отделён от phase: `Exited`, `SetupFailed`, `TimedOut`, `Cancelled`,
`BudgetExceeded`, `Interrupted`, `Unknown`. Для `Exited` обязателен точный код:
Windows сохраняет все 32 бита `DWORD`, Linux отдельно различает exit и signal.
Код ноль не меняет предметную приёмку Meridian. Stop state:
`NotRequested`, `Requested`, `Confirmed`, `Unconfirmed`; cleanup state:
`Pending`, `Complete`, `Failed`. `Terminal` с `Unknown` не освобождает workspace
для записи. Только подтверждённая остановка и действующий lock позволяют
checkpoint/restore/discard или новый start.

Legacy-сведения, которых не было в v0.3, остаются null с `legacy_incomplete=true`.
Старый общий cast не разрезается на выдуманные executions. Read-only adapter
показывает прежние status/command/exit отдельно от новых подтверждённых состояний.

## 7. Windows identity, ACL и integrity

Для каждой lab создаётся отдельная AppContainer identity с устойчивым SID,
пригодным для LPAC. В первом кандидате она никогда не разделяется с другой lab.
Token не включает сетевые capabilities или разрешения произвольных broker IPC.
LPAC задаётся через проверяемые process security attributes, а не только именем
профиля. Фактические token properties регистрируются guardian до `resume`.

Workspace, temp и private profile получают минимальные RW/execute права только
требуемого per-lab SID. Для записи процессом Low IL задаётся подходящая mandatory
integrity label. Эффективность DACL и integrity проверяется на реальных файлах.
Controller/git/blackbox/config и БД не наследуют широкие grants для
`ALL APPLICATION PACKAGES` / `ALL RESTRICTED APPLICATION PACKAGES`.

Читаемые и исполняемые OS runtime paths и CPython paths перечисляются в
toolchain manifest. CPython импортируется в Petri-owned copied toolchain;
его ACL, workspace/temp/profile ACL меняются только в принадлежащих Petri данных.
OS runtime доступен лишь через допустимые существующие OS/token grants.
Нельзя менять ACL Windows/system/global user/source объектов ради запуска.
Если необходимый системный доступ нельзя получить в допустимом LPAC-профиле,
результат — `Unsupported`, а не правка системных разрешений.

Controller не разрешает workload менять ACL доверенных ресурсов и принимает
решение promotion вне workload token. Наличие файла в workspace не означает,
что его можно использовать как executable toolchain или доверенную настройку.

## 8. Подготовка файлов и безопасные пути

Windows first-profile поддерживает явно ограниченное подмножество обычных
локальных NTFS файлов/каталогов. Source может быть read-only входом; подготовка
копирует committed baseline в новый workspace без изменения исходника.

На входе и при collect/checkpoint отклоняются reparse points, junctions,
неподдерживаемые symlinks, hardlinks, UNC, device paths, alternate data streams,
неоднозначные имена и case-colliding entries. Исходные данные сохраняются;
отказ не означает удаления или нормализации оригинала. Поддержку новых типов
можно добавить отдельным проверяемым контрактом.

Пути открываются с no-follow/reparse-aware семантикой; доверенные parents
закрепляются handles. Проверяются volume/file identity и тип объекта,
а не только результат `canonicalize` перед последующим открытием по строке.
Гонки замены и переименования учитываются там, где workload имеет запись.
Если API не обеспечивает нужную гарантию, операция отказывает.

Не делается общий вывод о безопасности всех путей по разовому обходу дерева.
Коллектор проверяет каждый открываемый объект; лимиты количества/размера файлов,
глубины и общего объёма применяются до и во время чтения.

## 9. Контракт команды и окружения

Основной вариант — `Exec { executable, argv, cwd, env }` с абсолютным executable
из зарегистрированного toolchain. Windows command line строится по определённым
правилам выбранного executable и проверяется fixture с пробелами/кавычками.
Нельзя объявить любой Windows argv универсально эквивалентным POSIX argv.

`Shell { shell_id, script }` — отдельный явный режим с закреплённым shell,
известной quoting semantics и собственными критериями. Строка пользователя
не вставляется в произвольный `cmd /c` или PowerShell как скрытый переход.

Окружение строится заново. `SYSTEMROOT` и другие действительно необходимые
Windows variables передаются явно; PATH содержит только разрешённые tool dirs.
TEMP/TMP, USERPROFILE/LOCALAPPDATA и рабочий HOME указывают на private lab paths.
Не наследуются host SSH/Git credentials, proxy secrets, пользовательский PATH,
agent/MCP settings, startup hooks или локальные tool configs.

Для CPython fixture используется документированный isolated CLI mode;
исходная форма — `python.exe -I -S <absolute-fixture-script> <args...>`.
Fixture использует только закреплённую стандартную библиотеку; изменение этой
формы создаёт отдельную revision профиля и повтор проверок окружения.
Они уменьшают влияние Python configuration, но не являются заменой LPAC.
Зависимости готовятся отдельно; произвольная установка с egress не разрешена.

Windows toolchain manifest содержит `format_version`, logical toolchain ID,
OS/architecture, точные tool versions, source/provenance refs, SHA-256 пакета,
перечень executable/DLL/config файлов с digest/size, entrypoints, разрешённые
read/execute paths и требуемые системные зависимости. License/notices входят
в поставляемый набор. Пользователь выбирает доверенный импорт; SHA-256 сам по
себе не подтверждает издателя. Импорт сначала проходит bounded staging и
проверки типов/aliases, затем публикуется private immutable-копия. Before-start
проверяется её identity/digest, а native workload не получает права изменять
инструменты или указатель manifest. Обнаруженная подмена даёт `ArtifactInvalid`.

## 10. Suspended launch и обязательный Job

| Механизм | Нативная API surface первого профиля |
|---|---|
| Identity | `CreateAppContainerProfile`; для принадлежащего Petri существующего профиля — `DeriveAppContainerSidFromAppContainerName` |
| LPAC | `UpdateProcThreadAttribute`: `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` и `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` с `PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT` |
| Handles | `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, явные inheritable stdio handles без control/job handles |
| Process | `CreateProcessW` с явным `lpApplicationName`, отдельной command line и flags `CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | EXTENDED_STARTUPINFO_PRESENT` |
| Job | `CreateJobObjectW`, `SetInformationJobObject`, `AssignProcessToJobObject`, `QueryInformationJobObject`, `TerminateJobObject` |
| Resume | `ResumeThread` только после обязательных Job/limits/security checks |

Привязка API реализуется Windows SDK Rust bindings с проверкой кодов ошибок.
LPAC flags и token properties проверяются на квалифицируемом host; отсутствующий
API либо недейственный обязательный attribute не подменяется совместимым режимом.

Guardian создаёт private named Job с ограниченной DACL. Имя содержит
неугадываемый execution identity; имя/PID сами по себе не являются credential.
Он сохраняет handles и сведения об объектной идентичности до запуска нагрузки.

Последовательность обязательна:

1. Проверить request/profile/toolchain/base digests и существующую lease.
2. Подготовить private paths, pipes, event budget и `launch_intent`.
3. Создать Job и установить обязательные ограничения/kill-on-close.
4. Создать process с LPAC security attributes и `CREATE_SUSPENDED`.
5. Передать только разрешённые stdio handles через явную handle allowlist.
6. Назначить suspended process в Job, проверить назначение и ограничения.
7. Сохранить execution binding, связь start operation и событие `launch_ready`.
8. Ещё раз проверить stop request/lease/journal, затем `ResumeThread`.
9. Сохранить `resumed`; если запись не удалась — остановить Job независимо от лога.

Guardian передаёт controller `READY` с execution ID, policy/toolchain digests,
подтверждённой Job membership и установленными лимитами. Это готовность setup,
не состояние `Running`. Controller публикует `Running` только после подтверждённого
resume той же execution. До resume недоверенная fixture не выполняет действий.
Разрыв подтверждения после resume даёт unknown и запускает независимую остановку.

При любой ошибке до `resume` suspended process завершается, handles закрываются,
lease сохраняет диагностируемый execution/operation outcome. Нагрузка не получает время исполнения.
Не используется breakaway; невозможность безопасно вложить Job в текущей host
среде даёт явный отказ. Нельзя запускать сперва, а назначать Job позднее.

## 11. Ресурсы и остановка

Обязательны Job active-process limit и Job committed-memory hard limit.
Job memory означает ограничение учитываемой ОС committed memory, не обещание
точного RSS или предотвращения всех видов resource exhaustion.
Обязательный CPU-time budget первого профиля — совокупное **user-mode CPU time**
Job через `PerJobUserTimeLimit` / `JOB_OBJECT_LIMIT_JOB_TIME` с проверенной
терминацией при исчерпании. Это не точный бюджет суммы kernel+user CPU time.
Job CPU hard-cap rate — отдельная опциональная политика доли CPU с объявленными
единицами; она не подменяет CPU-time budget. Поддержка и ожидаемый exit outcome
проверяются до `resume`; неподдержанный обязательный режим отклоняется.

Wall-clock deadline принадлежит guardian и действует на всё дерево независимо
от активности stdout. Нулевой/неограниченный timeout разрешается только если
это прямо допускает профиль. Лимиты output и событий имеют самостоятельный
бюджет; остановка при лимите не требует успешного дополнительного логирования.

Hard disk quota в первом Windows-профиле **не заявляется**. Можно включить
периодический учёт и sample-and-stop с явно указанным интервалом/остаточной
неопределённостью. Это не hard limit: нагрузка может записать больше между
замерами. Запрос обязательной жёсткой дисковой квоты возвращает `Unsupported`.

`stop` фиксирует запрос, вызывает принудительное завершение Job и ждёт
подтверждения `ActiveProcesses=0` по ещё действительному Job handle.
Завершение root process не доказывает остановку потомков. Timeout ожидания
даёт `StopUnconfirmed`; повторное исполнение и destructive cleanup запрещены.
Успешный `stop` не откатывает уже выполненные операции и не принимает результат.
При штатном stop, wallclock timeout и проверяемом parent/guardian crash приёмка
требует наблюдаемого нуля. Сохранившийся потомок — FAIL. `OutcomeUnknown`
является ожидаемым только в отдельно внедрённом отказе наблюдения и не позволяет
назвать обычную неработающую остановку успешной.

Guardian владеет handle Job с `KILL_ON_JOB_CLOSE`; workload этот handle не
наследует. Controller хранит lease/control связь. Разрыв родительского канала
инициирует остановку; гибель guardian закрывает его handles. После полного crash
одного факта закрытия handle недостаточно для отчёта `ActiveProcesses=0`.

`KILL_ON_JOB_CLOSE` действует при закрытии **последнего** handle Job. В normal
режиме guardian — единственный долговременный владелец такого handle; controller
не оставляет скрытую дублированную ссылку. При временном trusted inspect lifetime
дубликата явно учитывается, а его владелец обязан остановить Job при потере
guardian. Crash-test не удерживает Job открытым самим oracle: наблюдение
известных fixture descendants использует их process handles/creation identity.
При неизвестной принадлежности нельзя завершать произвольные host процессы.

CPU/wall/output deadlines и отказ журнала имеют явный stop-путь. Job RAM/PID
limits прежде всего запрещают выход за предел средствами ядра: отказ allocation
или создания процесса сам по себе не равен автоматической остановке всего Job.
Guardian обрабатывает limit/violation notifications и проверяемые счётчики,
инициирует stop при наблюдённом нарушении. Негарантированное уведомление не служит
единственным доказательством enforcement. Приёмка отдельно проверяет kernel
limit, доступность наблюдения и reaction; отсутствие наблюдения обозначается
пробелом, а не обещанием мгновенного stop при любом отказе API нагрузки.

### 11.1. Исходные проектные бюджеты first-profile

Это предлагаемые значения дизайна, а не результаты измерения:

| Бюджет | Значение и область |
|---|---|
| Active processes | 8 workload процессов вместе с потомками; controller/guardian вне Job |
| Job committed memory | 512 MiB совокупно |
| Job user-mode CPU time | 10 секунд совокупно |
| Wall-clock после resume | 30 секунд |
| Подтверждение stop | 3 секунды до наблюдаемого `ActiveProcesses=0` |
| Output | 8 MiB суммарно stdout+stderr на execution |
| Control journal | 16 MiB на execution с учётом обязательных terminal records |
| Одно событие | 64 KiB сериализованного UTF-8 вместе с envelope |
| Свободное место перед start | 2 GiB; reserve check не является аппаратной квотой |
| Workspace+temp | soft threshold 256 MiB, sample каждые 100 ms, overshoot неизвестен заранее |

Бюджеты и допуски закрепляются в candidate manifest перед квалификацией. Их изменение
создаёт новую profile revision и повтор затронутых проверок. Профиль заранее
резервирует в journal место terminal records; отказ носителя всё равно возможен
и обрабатывается независимым stop. Диск может изменять другой host workload;
sample-and-stop не превращается в обещание жёсткой квоты или zero overshoot.

Обычный выход root process тоже завершает execution только после принудительного
прекращения оставшихся Job descendants и наблюдаемого `ActiveProcesses=0`.
Persistent descendants после root exit не поддерживаются first-profile.
Sealed result не публикуется как успешно остановленный до этой проверки.

## 12. Сеть и будущие брокеры

First-profile — `network_none`: нет network capabilities, loopback exemptions,
переданных network handles или разрешений подключиться к host broker.
Проверяются IPv4/IPv6, loopback, внешние endpoints и унаследованные каналы.
Наличие сетевых возможностей у controller не переносится нагрузке.
Для каждого отрицательного network probe доверенный внешний positive control
доказывает доступность соответствующего endpoint/семейства до и после опыта.
Недоступный endpoint, отсутствующий IPv6 control или сбой harness означает
`UNVERIFIED`, а не доказанный запрет. Mandatory IPv4/IPv6 cases не исключаются
из квалификации профиля молча.

Сетевой провайдер модели и host-operation broker не входят в первый runtime
срез. Будущий broker требует отдельного аутентифицированного протокола,
scopes операции/назначения, защиты replay, срока полномочия, журналирования
и проверки caller identity. Нельзя открыть workload общий localhost API
controller, SSH agent, Git credential helper или Meridian DB.

Блокирование сети не означает доказанного наблюдения каждого сетевого syscall.
Результат указывает, какие probes зарегистрированы и что осталось ненаблюдаемым.
Текущий первый профиль не выдаётся за готовую сессию облачного coding agent.

## 13. Доверенный журнал и данные наблюдения

Blackbox записывают только controller/guardian вне workload token. В рабочую
область не монтируется управляющий журнал на запись. Событие содержит schema
version, lab/execution IDs и вызывающий operation ID, порядковый номер, источник, время и типизированные
данные. Время служит наблюдением; последовательность устанавливается счётчиком.

Обязательный поток: `prepare_intent`, `prepared`, `launch_intent`, `launch_ready`,
`resumed`, `stop_requested`, `tree_stopped` либо `stop_unconfirmed`,
`process_outcome`, `result_sealed`, `recovery_observation`.
Поля не приписываются задним числом: recovery-event отличается от исходного факта.

До эффектов проверяется готовность обязательного журнала. Отказ записи до
`resume` запрещает запуск; отказ после — запрещает новые операции и включает
независимую остановку. Guardian не ждёт от workload подтверждения stop.
Crash между OS-effect и записью оставляет unknown; нет атомарной транзакции
между Windows, файлами и JSONL, и ТС её не обещает.

Raw task/prompts и stdout/stderr не сохраняются без явной политики. First-profile
fixture может разрешить ограниченный capture с собственным retention.
Фильтрация чувствительных данных выполняется до persistent write; redactor
не называется универсальным детектором секретов. Частичный/утраченный вывод
обозначается явно. Output budget, rotation, export и deletion записаны в manifest.

Даже при выключенном persistent capture guardian дренирует оба output stream
с bounded buffers и применяет byte budget. Нельзя накапливать неограниченный
вывод в RAM или заблокировать workload невычитываемой pipe. Скрытые рассуждения
модели не запрашиваются как обязательный источник наблюдения.

Человекочитаемый просмотр экранирует управляющие последовательности недоверенного
вывода; обычный `logs` не исполняет terminal escape/OSC-команды. Raw artifact
при разрешённом capture сохраняет байты отдельно, с типом и размером. Replay
сырых данных требует явного выбора и отдельной политики безопасного терминала;
наличие `.cast` не делает его доверенным исполняемым содержимым.

## 14. Закрытый controller/guardian протокол

Протокол versioned, bounded и типизированный. Для локальной реализации подходят
унаследованные anonymous pipes/handles между доверенными процессами; внешний
network API/server не создаётся. Workload не получает управляющие handles.
Caller identity проверяется при создании связи; `lab_id` не заменяет полномочия.

Операции: `probe`, `prepare`, `start`, `inspect`, `stop`, `collect`, `checkpoint`,
`discard`. `restore` относится к отдельной stopped-only файловой операции.
Каждый запрос имеет version, request ID, operation ID/idempotency key,
request hash, lab ID, execution ID при обращении к исполнению, target identity,
expected metadata revision, profile/policy digest и предел размера.

Ответ содержит success/error, effective capabilities, observed state,
correlation IDs, checked revisions и точную границу подтверждения.
Минимальные ошибки: `UnsupportedPlatform`, `UnsupportedProfile`,
`UnsupportedPolicy`, `PolicyDenied`, `InvalidInput`, `IsolationUnavailable`,
`LabBusy`, `StaleRevision`, `LaunchFailed`, `WorkloadFailed`, `JournalFailed`,
`BudgetExceeded`, `StopUnconfirmed`, `RecoveryRequired`, `ArtifactInvalid`.

Ошибка setup отличается от workload exit code. Ненулевой код не превращается
в успешную проверку, а нулевой — в принятую инженерную работу.
Неизвестный ответ/версия/поле отказывает; human-readable stderr не парсится
как устойчивый протокол. Ограничиваются длины, число полей и output response.

### 14.1. Envelope и машинный CLI

Идентификатор внутреннего контракта — `petri.control/v1`; он независим от версии
документа и store V2. Закрытый envelope содержит `protocol`, `request_id`,
`operation_id`, `request_digest`, `kind`, `target`, `expected_revision`,
`payload`. Для start/inspect/stop/collect target содержит execution ID либо
controller выделяет его до start intent; lab ID не заменяет проверку полномочий.
Для prepare/checkpoint/discard достаточно соответствующей lab/checkpoint identity.

Payload различается по kind, unknown поля запрещены. Request digest вычисляется
по каноническому типизированному запросу, без transport request ID и handles.
Контроллер не доверяет digest, присланному caller, и пересчитывает его.
Максимум request — 1 MiB, event — 64 KiB; binary blobs не передаются inline.
После отклонения duplicate JSON keys и невалидного Unicode каноническая JSON
форма определяется RFC 8785; значения budget/revision — целые числа. Digest
новых request/policy/manifests — SHA-256 с префиксом алгоритма и domain/version.
Пути при хешировании не нормализуются так, чтобы изменить OS object identity.
Digest отдельных файлов считается по исходным байтам. Старый Linux rootfs
digest сохраняет алгоритм и domain v0.3, новый JSON-алгоритм его не заменяет.
Передаваемые OS handles/FD имеют отдельный allowlist и lifetime, числовое значение
handle в JSON не является полномочием или reconnect token.

Ответ содержит `protocol`, request/operation IDs, `status`, `result` либо
`error {code, stage, native_code, message, remediation}`, `warnings` и ссылки на
артефакты. У operation receipt фиксируются input revision и единственный outcome.
Ошибки `IdempotencyConflict` и неподдержанный major возвращаются до эффекта.

CLI сохраняет create/run/list/diff/checkpoint/restore/commit/merge/discard,
doctor/logs и Linux stack import. Doctor остаётся совместимой поверхностью probe.
Добавляются устойчивые inspect/stop/result/artifacts/probe. `merge` остаётся alias
публикации review-ветки, без изменения целевого HEAD. Новый машинный контракт
явно выбирается `--api-version 1 --json`: stdout содержит один envelope;
output нагрузки идёт в отдельные streams/artifacts по capture
policy. Отдельный режим `events --jsonl` выдаёт только версионированные события.
Human-readable progress разрешён в stderr, но не является машинным контрактом.

Существующее `list --json`/`diff --json` не превращается в envelope неявно:
совместимость v0.3 проверяется отдельно. Для старых форматов задаётся явная
legacy projection; неизвестные исторические поля не выдумываются. Любое
намеренное несовместимое изменение CLI отражается в compatibility matrix N01.
Приведённые ниже exit classes относятся к явно выбранному API v1; legacy-коды
не переопределяются без объявления изменения.

CLI exit classes: `0` — операция и ожидаемый успешный workload завершены;
`2` — invalid request; `3` — unsupported; `4` — policy/integrity denial;
`5` — busy/stale/idempotency conflict; `6` — setup failure;
`7` — завершённая workload с ненулевым кодом; `8` — timeout/budget stop;
`9` — unknown/recovery/stop unconfirmed; `10` — отказ обязательного журнала.
Точный workload exit code сохраняется в execution result и не заменяется этим
CLI-кодом. `run --detach` возвращает подтверждение назначения, не исход workload.

Примеры форм нового интерфейса (проект контракта, не уже существующие команды):

```text
petri --home <path> --api-version 1 --json probe --profile windows-native-python312-lpac/v1
petri --home <path> --api-version 1 --json run <lab-id> --operation-id <op-id> -- <absolute-program> <args...>
petri --home <path> --api-version 1 --json stop <execution-id> --operation-id <other-op-id>
petri --home <path> --api-version 1 --json result <execution-id>
```

Имя executable/argv проходит профильную проверку из §9. ID для идемпотентного
start сохраняется до эффекта; интеграционный caller обязан повторить тот же ID.

## 15. Восстановление и повторные запросы

Пара `operation_id + canonical request hash` обозначает одно управляющее
действие. Тот же ID с другим hash отклоняется. Перед повтором controller читает
журнал и inspect по сохранённому binding. Повтор start возвращает тот же
`execution_id`, не создавая вторую lab или процесс. Новый физический запуск
получает новый `execution_id` и новую start operation. Stop и collect того же
исполнения имеют собственные operation IDs. Checkpoint может относиться к lab
без нового исполнения. Инженерный run Meridian не приравнивается ни к одному
из этих идентификаторов.

После controller crash guardian сверяет control channel и останавливает Job.
Если guardian жив, восстановление получает факт через проверенную связь/handle.
Если остался private named Job, его открывают только с проверкой владельца,
привязки к execution/start operation и актуальности объекта. PID из файла не используют для kill.

Если Job уже закрыт и достоверного terminal receipt нет, состояние остаётся
`OutcomeUnknown`/`RecoveryRequired`. Исчезнувший root PID, истёкший lease или
отсутствующий Job не являются доказательством успешного исхода операции.
Автоматический rerun неизвестной команды запрещён.

Cleanup не уничтожает evidence и workspace до подтверждённой остановки и
применения retention. Незавершённые staging/backup сохраняются для recovery.
Повтор collect возвращает тот же sealed manifest либо явную утрату артефакта;
он не незаметно пересоздаёт доказательство под старой identity.

## 16. Результат, Git и checkpoint

Result manifest привязан к `lab_id + execution_id`; collect operation имеет
собственный ID и ссылку на этот неизменяемый результат. Manifest содержит
source repository identity/commit, exported
baseline digest, task/context refs при наличии, policy/profile version,
native toolchain или Linux stack digest, Petri binary digest, argv/env policy,
времена, setup outcome, exit status, tree-stop proof, budgets, gaps и артефакты.
Файлы артефактов имеют относительные безопасные пути, тип, размер и digest.

Seal означает: остановка подтверждена, collector безопасно прочитал объекты,
проверены digests, manifest записан в private staging и опубликован атомарным
платформенным replace с flush там, где он поддержан; receipt привязан к digest.
После публикации новое содержимое получает новую identity. Seal не является
цифровой подписью или доказательством защиты от доверенного host-пользователя.
Подпись результата — отдельное целевое расширение.

Git остаётся встроенным host-компонентом Petri. Linux lab commit и исходный
project commit имеют разные роли. Windows workload не получает Git.exe,
shared `.git`, source refs или raw Git RPC. Итоговый candidate создаётся из
безопасно прочитанного остановленного workspace и сохраняет provenance.

Host collection не использует изменяемые workload `.git`, repo configuration,
hooks, helper или `Repository::discover` из недоверенного cwd для выбора
доверенного Git store. Controller связывает private bare store с lab по
сохранённой object identity и manifest. Изменённый `.git` игнорируется либо
отклоняется по явной политике; он не перенаправляет host Git операции.
Source ref и права promotion берутся только из trusted controller metadata.
Hardlink count > 1, reparse points и ADS на collector path отклоняются;
пути output/evidence генерирует controller. Права SID/DACL защищают source
оригинал независимо от известности его абсолютного пути нагрузке.

Promotion — отдельное авторизованное host-действие после diff/review. Проверяются
base revision, protected paths и конфликтующие изменения. Оно не выполняется
автоматически по `exit 0` и не отменяет workflow внешнего Meridian.
Hooks, filters, helpers и команды из project config не запускаются на хосте.

Checkpoint/restore доступны только после подтверждённой остановки. Снимок
содержит workspace, согласованный Git state и ссылки metadata; не память процесса,
Windows token, сетевую сессию или право продолжить старую операцию.
Подготовка идёт в private staging, затем проверка и commit снимка; авария
не удаляет единственный исходник. Restore создаёт новую запись происхождения.

## 17. Схема metadata и миграция 0.3

Новая metadata имеет явный `schema_version` и tagged environment:
`LinuxRootfs`, `WindowsNativeToolchain`, `MacNativeReserved`.
Поле `stack` старой Linux lab не интерпретируется как Windows executable path.
Модель отделяет lab state, execution state и management operation state;
она хранит историю выполнений и результаты управляющих действий раздельно.

V2 store имеет отдельный layout/root и envelope, в котором прежние обязательные
root fields `Lab` 0.3 отсутствуют. Обычные старые операции не должны успешно
разобрать V2 как legacy lab. Один новый `schema_version` или marker-файл
недостаточен: прежний бинарник о нём не знает и может игнорировать unknown fields.
Legacy store читается новым controller только read-only до явного `migrate`.
Совместная RW-эксплуатация V0.3 и V2 запрещена. Миграция создаёт отдельный V2,
не модифицируя пригодный legacy source; final switch меняет явно выбранный root.
Это защита от ошибочного обычного использования, не запрет доверенному host
пользователю сознательно менять данные raw tools или старым бинарником.

Legacy 0.3 lab/stack/checkpoint и их digests остаются неизменяемыми входами.
Миграция: inventory → read-only validation → private backup → staged conversion
→ проверка связей/digests → атомарная замена metadata там, где её обеспечивает
платформа. Ошибка сохраняет backup и прежнее доступное состояние.

Миграция не объединяет независимые файловые операции в мнимую транзакцию.
Нужны журнал шагов и восстановление для обрыва между ними. Unknown old `Running`
не преобразуется в `Stopped`; старый PID не даёт полномочия kill/restart.
Реальные секреты не читаются и не переносятся для «дополнения» metadata.

`MacNativeReserved` не разрешает исполнение: capability остаётся unsupported.
Windows profile не применяет Linux rootfs policy и не запускает WSL/VM.
Linux-маршрут и старые sealed evidence проверяются на регрессию отдельно.

## 18. Пакеты реализации и трассировка приёмки

Номера — локальные пакеты новой реализации, не переименование прежних evidence.
Каждый пакет имеет отдельные область, входы, diff и проверяемый результат.

| Пакет | Результат | Приёмка ТЗ |
|---|---|---|
| N01 | Общие versioned contracts, IDs, tagged environment, миграция и backup | AC-WIN-N01 |
| W01 | Exact Windows host/toolchain manifest и truthful probe | AC-WIN-W01 |
| W02 | Подготовка lab: LPAC identity, private ACL/integrity и baseline | AC-WIN-W02 |
| W03 | Offline native Exec: suspended launch, Job, handles, native fixture | AC-WIN-W03 |
| W04 | Файловая граница, безопасные пути и NTFS-подмножество | AC-WIN-W04 |
| W05 | Source/native Git protection, diff/candidate/promotion | AC-WIN-W05 |
| W06 | Network-none IPv4/IPv6 с positive controls, broker boundary | AC-WIN-W06 |
| W07 | Stop дерева, ActiveProcesses=0, timeout/crash и owner handles | AC-WIN-W07 |
| W08 | Совокупные process/commit-memory/user CPU/wallclock limits, disk reserve | AC-WIN-W08 |
| W09 | Mandatory journal, bounded output, independent fail-journal stop | AC-WIN-W09 |
| W10 | Sealed result и stopped-only checkpoint/restore/retention | AC-WIN-W10 |
| W11 | Restart/recovery неизвестного исхода без автоматического rerun | AC-WIN-W11 |
| W12 | Поставка и обычный запуск без elevation/запасного runtime | AC-WIN-W12 |
| W13 | Повтор операции, concurrent labs, lease и resource separation | AC-WIN-W13 |
| W14 | Native toolchain registration, explicit env/argv и control protocol | AC-WIN-W14 |
| W15 | Linux regressions, сохранение baseline/evidence и Mac truthful refusal | AC-LINUX-W15 |

Сквозной набор обязательно включает positive operation, запрет host/source/
blackbox/DB доступа, blocked network, child tree, spawn-before-job guard,
journal failure до/после resume, limits, stop timeout, crash/recovery, повтор
ключа, hostile paths, stale base и восстановление snapshot.

Источники oracle находятся вне изменяемого workload workspace. Marker-файлы,
конечные OS states и readback проверяет доверенный harness. Вывод fixture
«PASS» сам по себе не даёт приёмку. Все наблюдения закреплены на exact binary,
policy, toolchain, OS build и собственных данных; ненаблюдаемое — `UNVERIFIED`.

## 19. Существующие файлы и объём изменений

| Baseline file | Использование |
|---|---|
| `src/labs.rs` | Сохранить lab store; versioned metadata/operation links и миграция |
| `src/runtime.rs` | Выделить текущий Linux backend, сохранить process setup boundary |
| `src/git.rs` | Повторно использовать native Git; проверить Windows paths/export |
| `src/stacks.rs` | Сохранить Linux content store; отделить native toolchain registry |
| `src/policy.rs` | Tagged profiles, capability validation и unknown-field refusal |
| `src/observer.rs` | Связать operation IDs, output retention и mandatory journal |
| `src/main.rs` | Выделить CLI/guardian dispatch, типизированные ответы и команды |
| `tests/lifecycle.rs` | Сохранить полезные regressions и добавить metadata scenarios |
| `tests/runtime_linux.rs` | Сохранить настоящий Linux E2E отдельно от Windows |

Не выполняется механическая замена Linux syscalls на похожие Windows функции.
Backend реализует общий наблюдаемый контракт собственными OS-механизмами.
Подписанные пакеты, независимый security review, performance и реальные агенты
имеют отдельные критерии; их готовность не выводится из первых unit tests.

## 20. Основания и открытые технические решения

Baseline: [Petri 70e0bc6](https://github.com/QahNaaRlN/petri/tree/70e0bc69c1a5be0761f073e69b6efae9a751b22d),
[Linux setup/limits](https://github.com/QahNaaRlN/petri/blob/70e0bc69c1a5be0761f073e69b6efae9a751b22d/src/runtime.rs#L665),
[Git candidate](https://github.com/QahNaaRlN/petri/blob/70e0bc69c1a5be0761f073e69b6efae9a751b22d/src/git.rs#L445).

Официальные API-основания:
[AppContainer isolation](https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation),
[process attributes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute),
[creation flags](https://learn.microsoft.com/en-us/windows/win32/procthread/process-creation-flags),
[Job objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects),
[SetInformationJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-setinformationjobobject),
[mandatory integrity](https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control),
[handle information](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfileinformationbyhandleex).

До назначения W01/W02 уточняются минимальные OS grants CPython и manifest
безопасной регистрации профиля на указанной выше API surface. До W03/W07
закрепляются ownership handles/guardian/recovery и oracle дерева. До W08
проверяются численные бюджеты и supported CPU units. Числа и доказанные версии
нельзя заменить скрытой настройкой при объявлении профиля квалифицированным.

Настоящий проект не принимает прежние спорные технические обещания автоматически:
один бинарник не исключает OS prerequisites/toolchain; нативный профиль не
означает абсолютной изоляции; snapshot не откатывает внешние эффекты; успешная
команда не доказывает корректность инженерного результата.


## Подготовка следующего macOS-пакета — 2026-10-27

[macOS ТЗ](macos-requirements.md) и [macOS ТС](macos-technical-specification.md) добавлены в `feat/macos-native-candidate`, основанную на Windows-кандидате. Первое исследуемое направление — публичный подписанный App Sandbox helper на pinned macOS 26 arm64; production-механизм не принят до доказательства обязательных свойств. Эти документы не добавляют Mac runtime, не мигрируют Windows V2 и не меняют Linux backend. [План](macos-implementation-plan.md) выделяет общие контракты отдельно от OS-specific facts и требует явного нового формата вместо переинтерпретации Job/LPAC как Darwin.
