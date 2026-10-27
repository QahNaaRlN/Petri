# ТС — подготовка нативного macOS backend Petri

Версия: **0.1-preparation**, 2026-10-27, Asia/Yekaterinburg.
Связанные документы: [ТЗ](macos-requirements.md), [API assessment](macos-api-assessment.md),
[implementation plan](macos-implementation-plan.md), [acceptance](macos-acceptance.md).

## 1. Архитектурное решение

Первый исследуемый механизм — **отдельный подписанный headless App Sandbox helper**,
доверенный Petri controller вне workload boundary и явно ограниченный native
CPython toolchain. Это выбор направления опытов, а не доказанная production
архитектура. `sandbox_init`/SBPL, Endpoint Security, VM и privileged daemon не
включаются автоматически, если публичный helper не обеспечивает требуемое.

```text
Petri controller: source Git, metadata, policy, admission, audit/results
  -> authenticated, bounded, private launch/control channel
    -> trusted signed sandbox helper: verify policy, Ready, launch native fixture
      -> native CPython + descendants: untrusted workload
  <- capability facts, lifecycle observations, stop evidence, bounded output
```

Helper является частью доверенной базы до передачи исполнения нагрузке.
Нагрузка не получает host-controller channel, control store, signing key или
полномочие вызывать через controller произвольный host executable вне sandbox.
Наследуемая возможность исполнять разрешённые ОС binaries внутри sandbox
проверяется отдельно и не считается controller broker. XPC/pipe/socket — транспорт,
не авторизация; точный вариант выбирается только после проверки launch/signing
и передачи sandbox grants. Ambient HOME, Team ID или PID не дают admission.

## 2. База и независимые форматы

В этой ветке сохраняется Windows native-v2 implementation. В ней сегодня
`EnvironmentRef`, `ResourceBinding`, `TerminalResult` и validators зависят от
Windows, хотя находятся в общих файлах. Они не считаются готовым macOS API.

План — сначала выделить общие lifecycle/idempotence/JCS/bounded writer части без
изменения Windows поведения, затем ввести **native-v3**, typed platform facts и
явно versioned macOS protocol. Предложение major protocol `petri.control/v2`
подлежит MP-00 contract review; текущий CLI этим документом не меняется.

Минимальные discriminants будущего контракта:

- `platform`: windows / macos / linux; `architecture` и pinned OS identity.
- `environment`: WindowsNative / MacNative с отдельными Mach-O/signing metadata;
  LinuxRootfs остаётся Linux-only.
- `process_status`: WindowsDword / PosixExited / PosixSignaled / NoExitEvidence.
- `resource_binding`: Job facts либо собственная macOS identity/observer binding;
  произвольный PID/PGID не является ownership proof.
- `capabilities`: для каждой защиты supported/enforced/unverified/unsupported,
  enforcement kind, scope, metric, prerequisites и evidence refs.
- `stop_evidence`: observed platform facts с provenance; ни root exit, ни число
  обнаруженных в одном обходе PID не превращаются в confirmed tree zero.

Новые store и schemas должны отвергать старые writers по layout и обязательным
полям. Старые labs не переписываются; неизвестная legacy execution не мигрирует
как stopped. Shared primitives выделяются в небольшие проверяемые изменения,
а не массовым переименованием всего runtime.

## 3. Обязательные feasibility gates

### F1 — signed launch и native инструменты

Создать минимальный доверенный helper с App Sandbox entitlement и собственный
безопасный fixture. Сначала проверить bundled arm64 CPython; отдельно проверить
внешний импорт, загрузку stdlib/native modules и relocatable distribution.
Не получать exec-доступ из факта успешного read-only bookmark. Зафиксировать
designated requirement, executable hash, entitlement set, SDK и actual OS build.

До workload helper подтверждает свой launch context и проходит независимые
negative/positive canary checks. `codesign --verify` и entitlement inspection
подтверждают артефакт, но не заменяют тест фактического runtime confinement.
Предварительные plist находятся в [packaging/macos](../packaging/macos/README.md).

### F2 — независимая lab identity

Один application identifier обычно даёт один writable app-container. Нужно
проверить две параллельные lab A/B и повторное использование identity после
предыдущего запуска: workspace, temp, caches/preferences, host grants, старые
bookmarks, открытые descriptors и исполняемые startup files.

Не принимать `HOME=lab-A`, отдельный cwd, одинаковые uid permissions 0700 или
один helper PID за разграничение доступа. Не выпускать неподписанные/широко
привилегированные per-lab bundles, чтобы обойти проблему. Возможные identity
модели фиксируются отдельным решением по результату опыта; pool/shared
container не объявляется безопасным без isolation и cleanup evidence.

### F3 — custody, stop и crash

Нужно доказать, что workload не выводит потомков из учёта через `setsid`,
`setpgid`, fork/exec, double-fork, root exit, PID reuse и внешние host services.
`killpg`, launchd group cleanup и `kqueue NOTE_EXIT` сами не являются Job.
Darwin `NOTE_TRACK` нельзя предполагать по документации FreeBSD.

Guardian должен иметь независимый stop/watchdog путь без обязательного journal
I/O. Контроллер/guardian crash проверяются раздельно; отсутствие живого
наблюдателя не создаёт синтетический receipt. Если нативная выбранная модель
не обеспечивает обязательное прекращение дерева, профиль не выпускается.
Privileged observer/Endpoint Security — возможные предметы нового ADR, не
заранее предоставленные полномочия и не незаметная зависимость кандидата.

### F4 — aggregate budgets

Зафиксировать точную Darwin memory metric, process count, CPU-time scope,
wall time, enforcement timing и реакцию на denial. Измерение RSS, `setrlimit`
одного процесса или уведомление после превышения не являются aggregate hard
limit. Если нужного механизма нет, capabilities должны возвращать Unsupported,
а admission — отвергать требующую его политику. No-root/ordinary-account
пригодность также проверяется, а не предполагается.

### F5 — network/IPC none

Проверить IPv4/IPv6, loopback, controlled LAN, DNS/direct-IP, AF_UNIX и доступные
Mach/XPC/launch services. Для каждого запрета нужен отдельный разрешённый
положительный контроль вне sandbox и собственный endpoint. Не создавать
реальные задания/службы на пользовательском хосте. Отсутствие network
entitlements не считается результатом всех IPC/FS socket опытов.

### F6 — файловая модель и host collector

Для bounded export/diff/checkpoint/result collection проверить no-follow,
object-relative traversal, symlink/hardlink, parent substitution, APFS
case sensitivity и Unicode equivalence. Отдельно определить xattrs/resource
forks/ACL/flags, executable bits, package boundaries, quarantine/signature и
clone semantics. Не копировать молча неизвестные metadata или снимать защиту.

App Sandbox default container и необходимые OS read paths входят в effective
policy. Snapshot не хранит credentials или transient sandbox grants; clone
не создаёт автоматически согласованный снимок и не является hard quota.

### F7 — audit, result и faults

До effect сохраняется intent. Ready содержит helper/runtime/policy/tool/input
binding. Workload output отделён от controller JSON. Shared bounded journal
имеет sequence/correlation/limits/terminal reserve; его отказ после launch
вызывает независимый stop. При blocked I/O watchdog не ждёт writer.

Результат публикуется staging → flush → atomic publish, затем durable terminal
record. Он различает status, stop, cleanup и инженерную приёмку. SHA-256
inventory — локальная целостность, не подпись издателя. Power-loss/directory
flush и multi-directory restore limitations отражаются явно.

### F8 — native package и regressions

Подписать все требуемые executable/Mach-O components корректными constraints,
проверить Hardened Runtime отдельно от Sandbox; затем release notarization,
quarantine/install/upgrade/uninstall. Не использовать `--deep` для скрытого
исправления подписей и не отключать library validation/JIT/TCC автоматически.
Любое необходимое расширение capabilities получает отдельный ADR/test.

Linux/Windows portable tests и прежние native qualification продолжают
проверяться отдельно. Не назначать hosted macOS build job нативной приёмкой;
выбранный Mac/аккаунт/OS build/signing должны совпадать с qualification manifest.

## 4. Жизненный цикл будущего backend

1. Проверить versioned request, operation/revision, profile и environment refs.
2. Закрепить lab lock и durable intent; запретить конкурирующие mutations.
3. Подготовить собственный workspace и toolchain без выполнения project hooks.
4. Проверить helper identity, все mandatory protections и доступные OS grants.
5. Получить authenticated Ready до любого untrusted code; подтвердить launch.
6. Наблюдать workload, bounded output и budget events; принимать typed stop.
7. Остановить и независимо подтвердить всё принадлежащее execution дерево.
8. Выполнить безопасную stopped collection, seal result, сохранить terminal.
9. Выполнить cleanup с отдельным исходом; не приравнивать его к exit 0.

Это требуемая последовательность. Конкретные launch/containment APIs остаются
блокирующим результатом F1–F4, а не заполняются несуществующими Darwin аналогами
Windows. До их выбора macOS runtime остаётся Unsupported.

## 5. Что можно сделать до доступа к Mac

Подготовить closed schemas, fixtures, parser rejection/idempotence tests,
bounded artifact code и разделение common/Windows adapters. Эти пакеты должны
сохранять Windows/legacy bytes и проходить platform regressions. Read-only
preflight можно проверить на отрицательных inputs в Linux; native факты,
entitlement effects и stop guarantees из этого не выводятся.

Следующий исполнитель начинает с MP-00 и native feasibility по плану. Он
получает собственный pinned Mac report, принимает/отклоняет gates и лишь затем
реализует выбранный macOS backend. Подмена отсутствующего host проверкой
синтаксиса или успешным cross-build запрещена критериями приёмки.
