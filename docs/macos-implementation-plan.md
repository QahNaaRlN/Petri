# План подготовки и реализации собственного macOS backend Petri

Дата: **2026-10-27 UTC**. Статус: **план подготовки; native runtime не реализован и не квалифицирован**.
Ветка `feat/macos-native-candidate` основана на Windows-линии `a26220a`: runtime `69f6009` и актуализация имён кандидатных веток. Публикация ветки не означает приёмку runtime.
Общие требования — [requirements.md](requirements.md), общий контракт —
[technical-specification.md](technical-specification.md). Уточнения macOS —
[ТЗ](macos-requirements.md) и [ТС](macos-technical-specification.md).

## 1. Цель, принятое направление и текущий предел

Подготовить macOS backend собственного Petri, повторно используя контроллер лаборатории,
Git, идемпотентность и evidence. Не создавать вторую независимую систему жизненного цикла.
Windows-кандидат и legacy Linux сохраняют свои форматы, маршруты и честные ограничения.

Для первой feasibility-проверки выбрана **подписанная App Sandbox helper application**
с публичными средствами macOS. Это кандидат механизма, а не уже пригодная граница изоляции.
Предлагаемая начальная среда — **macOS 26, arm64, обычная учётная запись**, native CPython 3.12,
собственная фиксированная offline CLI fixture. Точный patch/build, hardware, filesystem,
tool distribution и hashes закрепляются по факту подготовки настоящего Mac.
Текущие Linux-проверки или cross-compilation такие сведения не заменяют.

Следующие условия обязательны до запуска недоверенного проекта как лаборатории:
разделение лабораторий, исполнение импортированного toolchain, наследование защиты,
полнота владения потомками, остановка и принятый ресурсный профиль.
Если публичный механизм не удовлетворяет обязательному условию, результат — архитектурный
отказ/пересмотр профиля, а не ослабленный `Supported` или продолжение без защиты.

Нет неявного fallback к custom SBPL/Seatbelt SPI, Endpoint Security, WSL, VM,
Windows Sandbox, Docker, MXC или обычному host process.
ES с особыми entitlement и новыми версиями ОС не считается исходной предпосылкой.
GUI, Keychain, live cloud agent, network allowlist, PTY и произвольная установка зависимостей
не входят в первую offline fixture; остаются последующими отдельными возможностями продукта.

Этот пакет меняет документацию подготовки. Он не меняет Cargo, runtime, подписи машины,
права хоста или источники Windows evidence и не объявляет полную готовность трёх ОС.

## 2. Фактические общие части и Windows-зависимости

| Исходный файл/контракт | Что повторно используется | Что препятствует прямому macOS reuse |
| --- | --- | --- |
| [execution.rs](../src/execution.rs): `Store`, `LabState`, `begin_execution`, `with_stopped_lab` | Разные Lab/Execution/Operation IDs; атомарное состояние; lease; repeat/conflict; blocked unknown/recovery | `validate_environment` принимает только `windows-native`; `ResourceBinding` содержит Job/PID/LPAC; `TerminalResult` содержит Windows DWORD и Job-specific counters |
| `execution::record_digest` | SHA-256 domain separation; UTF-16 key ordering; integer-only safe range; запрет скрытого изменения пути перед digest | Новые домены/форматы не должны менять старые request digest; POSIX path identity нельзя свести к Windows canonical spelling |
| [native_tools.rs](../src/native_tools.rs) | Bounded inventory, exact file hashes, staged private copy, immutable content ID, verify-before-start | Normalizer требует Windows x86_64, PE32+, `python.exe`, `python312.dll/zip`, `_pth`; namespace/path guards ориентированы на NTFS и Windows aliases |
| [native_checkpoints.rs](../src/native_checkpoints.rs) | Stopped-only lock, workspace+Git copy, bounded digest, restore veto, сохранение аудита | Имена проверяются Windows validator; tree digest v1 не закрепляет POSIX executable mode, ACL/xattrs; Windows rollback ACL helper не переносим |
| [windows_cli.rs](../src/windows_cli.rs) | JSON envelope, parent/guardian separation, bounded pipes, запись ready/resumed, stop polling, artifact inventory | Windows-only dispatch, profile/tool/env validation, C-runtime quoting, runtime events, DWORD exit classes, result profile/backend labels |
| [git.rs](../src/git.rs) | Встроенный Git, независимый baseline, object-based export, candidate diff/commit | Должны быть отдельные правила материализации имён/metadata и объектной идентичности целевого volume; Windows validator не становится macOS validator |
| [runtime.rs](../src/runtime.rs), legacy [labs.rs](../src/labs.rs), [stacks.rs](../src/stacks.rs) | Существующая Linux-линия, rootfs/OCI, прежние CLI формы и regression corpus | Их перенос на native store или изменение Linux budget semantics не входят в Mac-refactor |

Название `native_*` само по себе не делает текущий формат переносимым.
Перед рефакторингом фиксируются golden JSON/digests, legacy projections и известные пробелы.
Host stop proof, удаление native identity и retention cleanup остаются разными фактами.

## 3. Архитектурные feasibility gates

Основной разбор API — [macos-api-assessment.md](macos-api-assessment.md).
Здесь задаются результаты, необходимые следующему пакету, без выдумывания доступного API.

| Gate | Вопрос и обязательное доказательство | Что не закрывает gate |
| --- | --- | --- |
| MS-01 Signing/helper launch | Подписанный helper с точными entitlements действительно получает App Sandbox; helper/child identities и signature chain записаны | Успешный `codesign`, ad-hoc signature, наличие entitlement в plist без проверки фактического процесса |
| MS-02 Toolchain execution | Явно импортированный native CPython запускается из private copied tree с нужными зависимостями и без внешнего host-tool grant | Read/write bookmark или sandbox extension: они не объявляются правом исполнять произвольный импортированный binary |
| MS-03 Per-lab isolation | Две lab не получают доступ к private данным друг друга, controller/Git/blackbox; helper identity и app-container данные не создают общий bypass | Две разные папки при общем доступном helper container; обещание изолировать labs только по строковым IDs |
| MS-04 Descendant custody/stop | Закрытая модель принадлежности охватывает разрешённых потомков, fork/spawn/setsid/daemon attempts; stop/timeout/controller loss дают проверяемый конец дерева | Direct-child exit, PID reuse checks отдельно, периодический process scan, один PGID или session sweep сами по себе |
| MS-05 Resource profile | Для RAM/process/CPU/wall/disk/output известны scope, hard/observed semantics и поведение отказа; обязательное гарантируется или профиль отклоняется | `setrlimit` на отдельный процесс как aggregate limit дерева; sampling как hard quota; перенос названий Windows Job counters |
| MS-06 File boundary | Зафиксированы APFS/path alias правила, private store permissions, чтение tools/oracle и запрет host/sibling writes; отрицательные и положительные controls | `canonicalize`/string-prefix check до позднего open; ASCII lowercase как Unicode/APFS equivalence |
| MS-07 Network none/IPC | Проверены IPv4/IPv6, loopback и унаследованные handles/IPC; нет доступа к controller/broker и Keychain | Неудачный DNS при недоступном endpoint; отсутствие `HTTP_PROXY`; network entitlement omission без настоящих probes |
| MS-08 Packaging/launch context | Точный signed bundle/CLI/helper путь работает обычному пользователю; известны Gatekeeper/quarantine и launch-context ограничения | Portable CI, запуск из Xcode с отличающимися entitlements, отключение Gatekeeper/SIP или скрытый admin repair |

MS-01/02/03/04/05 — блокирующие развилки выбора механизма.
Каждый опыт сохраняет fixture, source/binary hashes, host manifest, наблюдения и результат
`PASS/FAIL/UNVERIFIED` с охватом. `Supported` не выводится из одного успешного опыта.
Неудача gate не разрешает автоматически переключаться на иной механизм.

Если осуществим только single-process diagnostic, он получает отдельное имя и ограничение;
это не принятие лаборатории с разрешённым деревом процессов и не готовая сессия агента.
Контролируемое отсутствие hard disk quota может быть явно принято только в ограниченной fixture;
оно не допускает произвольную real-world нагрузку под обещанием полного resource containment.

## 4. Предлагаемые общие интерфейсы

Это проект интерфейса для следующего пакета, не существующий API и не разрешённый runtime path.
Сначала отделяется текущая логика без изменения формата; новые типы вводятся отдельно.

### 4.1. Platform-aware domain

Общий слой содержит только данные и решения переходов:

```text
TargetPlatform = { os, architecture, filesystem_profile }
EnvironmentRefV3 = WindowsNative(...) | MacosNative(...)
ProcessStatusV3 = WindowsDword(u32)
                | PosixExited { code: u8, raw_wait_status: i32 }
                | PosixSignaled { signal: i32, core_dumped: bool, raw_wait_status: i32 }
BackendBindingV3 = WindowsJob(...) | MacosQualifiedBinding(...)
```

`MacosQualifiedBinding` получает закрытые поля только после MS-04; placeholder JSON/PID
не принимается как авторитетный ресурс. Новый Linux-variant не вводится ради этого пакета:
legacy Linux остаётся на своём контракте до отдельного решения.
Setup failure/unknown остаются outcome с отсутствующим process status, а не synthetic exit code.
Все 32 бита Windows кода сохраняются; POSIX signal не сводится к `128 + signal` в evidence.

`StopEvidenceV3` различает `whole_owned_tree`, `known_descendants_only`, `root_only`
и `unknown`, механизм, identity и время наблюдения. Только первое с принятым доказательством
останавливает veto на mutation/new start. Нулевой process count без полноты ownership
не становится `Confirmed`. Cleanup state не повышается при одном только tree-stop proof.

Resource request содержит scope/units/required semantics. Effective capabilities и measurements
отдельны: Windows committed Job memory и user CPU 100ns не переименовываются в macOS RSS/CPU.
Нет значения ноль вместо неизвестного счётчика. Backend отклоняет обязательную несовместимую
семантику до workload; диагностический sampling не выполняет hard-limit требование.

### 4.2. Execution boundary

Предлагаемый фасад контроллера:

```text
probe(ProfileRequest) -> CapabilityReport
prepare(StartRequestV3) -> DurableIntent
start(DurableIntent, ControlChannel, EventSink) -> BackendResultV3
inspect(VerifiedBinding) -> OwnershipObservation
stop(VerifiedBinding, Deadline) -> StopEvidenceV3
```

Точные методы backend уточняются после feasibility gates. Неподдержанная операция имеет typed
отказ, а не пустой successful response. `EventSink` failure после запуска требует независимого
stop-пути; отсутствие удачной записи не скрывает неизвестный OS-effect.
CLI не вызывает новый backend прямо из многопоточного desktop-процесса.
Guardian/helper остаётся отдельным доверенным процессом с закрытым versioned control channel.
Транспорт не является общим localhost server и не доступен коду проекта.

`NativeBackend` описывает границу, а не обещает, что Windows Job и Mac helper одинаковы.
Windows adapter сначала оборачивает существующий проверяемый путь без его переписывания.
Не переносить Windows LPAC flags, quoting и ACL в общий domain ради одинаковых сигнатур.

### 4.3. CLI и result contracts

Windows `petri windows` и `petri.control/v1` сохраняются без неявной замены result shape.
Для нового native-контракта предлагается явная версия, например
`petri macos --api-version 2 --json ...` с `petri.control/v2`; окончательный синтаксис
фиксируется в MP-00 до кода и связывается с accepted profile.
Результат нового слоя получает свой `petri.native-result/v2`.
Проекция Windows V1 остаётся отдельным adapter и сохраняет DWORD, error classes и предупреждения.
Human diagnostics, workload bytes и machine envelope не смешиваются.
Существующий substring-based CLI error classifier не размножается в macOS:
новый общий boundary использует typed error; старый output сохраняется projection-тестами.

## 5. Storage и совместимость

Общий будущий native store — **V3**, отдельный `native-v3/` с собственным marker/version.
Это согласованное направление плана, не уже выполненная миграция.
Windows V2 находится в `native-v2/`, legacy Linux — в прежнем namespace.
Новый Mac-код не принимает чужой environment и не запускает Windows workload через адаптацию пути.

Правила перехода:

1. Извлечь существующий V2 reader/writer с сохранением сериализации и digest domains.
2. Добавить V3 types/reader/writer в новом namespace. Не открывать V2 как V3 по сходству полей.
3. Оставить Windows CLI на V2 до отдельного migration-пакета; Mac-кандидат может читать/писать V3.
4. Старые записи показывать через read-only historical projection. Исходные Windows paths
   читаются как данные своей платформы, не `canonicalize`-ятся на Mac и не становятся local binding.
5. Если нужен перенос, сформировать explicit copy/migration plan с source digest, stop state,
   mapping и отдельным подтверждением; исходные terminal receipts/checkpoints не переписывать.
6. Записи unknown/unconfirmed и restore markers сохраняют veto. Смена ОС не доказывает stop.

V3 записывает target OS/arch/profile, backend identity, environment revision, typed process status,
resource semantics и stop evidence. Request digest включает target/profile и payload version;
operation key имеет явно объявленную область. Повтор с другим target/request даёт конфликт.
Нельзя дописывать новый формат так, чтобы старый V2 writer молча его принял.

`record_digest` сохраняет safe-integer/Unicode правила, но новые payload используют новые
domain/version. Исторические hashes не пересчитываются новым нормализатором.
Пути хешируются по объявленной representation; normalization для UI не изменяет object identity.

## 6. Filesystem и checkpoints на macOS

Предлагаемый первый filesystem profile — локальный APFS с записанными case/volume facts.
Case-sensitive и case-insensitive APFS — разные проверяемые конфигурации.
HFS+, network/FUSE, iCloud/File Provider/offline files, aliases и другие volume types
не получают поддержку автоматически; неподдержанное отклоняется явно.

Нужны отдельные проверки:

- Unicode/canonical-equivalent names, case collisions и фактическое lookup-поведение volume;
- symlinks, hardlinks, mount boundaries, special files и path replacement во время коллекции;
- ACL/xattrs/resource forks/file flags и их влияние на digest, executable identity и права;
- held directory/file identity через native descriptor-relative операции; parent path rename
  не делает ранее проверенную строку безопасной для последующего open;
- приватность owner/mode/ACL без изменения source, system или global user paths;
- executable bits и Git mode semantics в copied workspace и stopped checkpoint.

Политика первой fixture может явно ограничить поддержанные типы/имена, пока сложные формы
не квалифицированы. Ограничение фиксируется до опыта; произвольная «очистка» имён запрещена.
Отказ сохраняет исходные данные и объясняет непредставимый snapshot.

Новый checkpoint format/digest V2 закрепляет согласованные mode/metadata semantics и platform
profile. Старый `petri.native-checkpoint/v1` не переименовывается и не объявляется Mac-полным.
Restore проверяет env/platform/profile, hashes и stop proof под тем же lab lock, не откатывает
audit/execution history и сохраняет veto при crash между файловыми переключениями.
ACL/permissions восстанавливаются по принятому шаблону текущего sandbox, не как скрытый перенос
дополнительных полномочий из старого snapshot.
Copy-on-write APFS clone не объявляется независимым checkpoint без проверки writable isolation.

## 7. Mac toolchain, подписи и поставка

Mac importer получает новый tagged manifest, не фиктивный Windows `ToolchainManifest`.
Общее ядро inventory/copy/hashing может быть тем же, platform validator — отдельный.
Native CPython 3.12 distribution должна быть явно выбрана и пригодна для copied/private layout.
Windows `_pth`, zip/DLL обязательности и PE headers не применяются к ней.

Manifest фиксирует target architecture, Mach-O executable/dependencies, exact patch,
entrypoint/flags, package/file digests, licenses, provenance, необходимую signing identity
и разрешённые metadata. Universal binary проверяется на нужную slice; Rosetta не fallback.
Framework paths, `@rpath`/install names и системные dylib считаются частью MS-02,
а не поводом дать read/execute всему пользовательскому или системному диску.

Integrity hashes, code signature, hardened runtime, App Sandbox entitlements и notarization
отвечают на разные вопросы. Проверяются actual child entitlement/inheritance и helper bundle,
а не только подпись внешнего CLI. Dynamic sandbox extension не обещает executable grant.
Если публичный механизм требует изменить форму доставки toolchain, это оформляется решением
до implementation; существующий imported-tree контракт не обходится неявно.

Artifact signing/упаковка выполняются до вычисления финального inventory и его закрепления.
После signing/relocation нельзя оставить прежние hashes. Не удалять quarantine, не отключать
Gatekeeper/SIP и не пересигнировать пользовательскую программу скрыто ради успешного запуска.
Developer diagnostics и shipping signature — разные профили, evidence не взаимозаменяемы.
Один установщик может содержать CLI/helper bundle; это не обещание, что все Python/SDK входят
в Petri или что проект можно поставить одним неподписанным executable.

## 8. Work packages и владение файлами

Пакеты ниже — последовательные reviewable units, а не новые Cargo packages.
Постоянные персональные назначения этим документом не вводятся; интегратор назначает исполнителей.
Один файл в конкретном пакете имеет одного владельца изменений. Роли в таблице нужны для handoff.

| Пакет | Зависимости | Владелец / файлы | Завершённый проверяемый результат |
| --- | --- | --- | --- |
| MP-00 Контракты и baseline | Нет | Архитектор; Mac requirements/TS/assessment/acceptance и эта карта | Profile proposal, gate criteria, V2 golden records/CLI, V3 schema/version decision; список остающихся Unknown |
| MP-01 API/host feasibility | MP-00; настоящий Mac для опытов | macOS исследование + qualification; отдельные bounded spike fixtures/evidence | MS-01…08 с реальными результатами; неподтверждённый механизм остаётся unavailable, никакой general runtime |
| MP-02 Безопасное извлечение общего кода | MP-00 | Контракты/controller; `src/execution.rs` → proposed `src/execution/{mod,model_v2,store_v2,digest}.rs`; выделение journal/result helpers из `windows_cli.rs` | Поведение/bytes/domains Windows V2 сохранены; Linux не маршрутизирован в новый store; build/tests зелёные |
| MP-03 V3 domain/store | MP-02; решения target/resource/stop из MS | Контракты/controller; proposed `src/execution/{model_v3,store_v3,compat}.rs` | Закрытые tagged types, atomic V3 store, old writer rejection, read-only projections, unknown/recovery и typed errors; runtime ещё unavailable |
| MP-04 Mac filesystem/tools/checkpoints | MP-03 + MS-02/06 | FS/toolchain; platform helpers, native_tools split, native_checkpoints V2; Git materialization adapter | Bounded APFS imports и stopped copies с mode/alias/metadata policy; Windows PE validator и checkpoint V1 неизменны |
| MP-05 Signed helper lifecycle | MP-01 blocking gates + MP-03 | macOS backend; proposed `src/macos_native/`, helper target/bundle, target-specific bindings | Закрытый helper protocol, identity, launch readiness, inherited security, custody/stop/resource path; no weakening fallback |
| MP-06 Shared guardian + Mac CLI | MP-04/05 | CLI/guardian; common controller helpers, proposed Mac CLI, existing Windows projection | Новая explicit API version; bounded outputs/events, repeat/conflict, cancellation, immutable results; Windows V1 unchanged |
| MP-07 Actual qualification | MP-06 + accepted manifest | Qualification; [macos-acceptance.md](macos-acceptance.md), native fixtures/harness/CI | Executed positive/negative controls на точном Mac; independent oracle; FAIL/UNVERIFIED не становятся PASS |
| MP-08 Signing/package integration | MS-08 + MP-07 | Release/integrator; target-specific packaging, подписанные artifacts/SBOM/install docs | Обычная установка/удаление, точные финальные hashes, подписанный CLI/helper и проверенный tool acquisition path |
| MP-09 Reconciliation/release evidence | MP-07/08 | Архитектор/integrator; status/testing/security/compatibility docs | Readiness matrix по ОС/profile, сохранённые Windows/Linux evidence, открытые gaps, ограниченная owner acceptance |

MP-01 и MP-02 могут идти параллельно после MP-00: механизмы не угадываются ради рефакторинга.
В MP-02 разрешён только перенос без изменения поведения; новые особенности идут в MP-03+.
MP-04 и MP-05 имеют разные файловые области после согласования V3 interface.
Root composition (`main.rs`, `lib.rs`, Cargo/build scripts) меняет один интегратор по готовым интерфейсам.
Пакет MP-05 не начинается как принятый sandbox implementation, пока его механизм не прошёл
блокирующие gate; допустимы только отдельно обозначенные безопасные feasibility fixtures.

## 9. Порядок commits и проверок без потери bisectability

Каждый шаг должен собираться; недоступный backend возвращает typed Unsupported.
Не коммитить половину module move с несуществующим module path или повисшими feature flags.

1. Зафиксировать baseline fixtures/compatibility assertions до переноса.
2. Перенести digest/model helpers и переэкспортировать прежний Windows API без изменения callers.
3. Ввести V3 model/store и negative compatibility tests; Mac probe пока сообщает unavailable.
4. Ввести platform file/tool adapters с inert import tests без обещания sandbox qualification.
5. Добавить отдельный signed helper прототип только после его gate decision; guard остаётся закрыт.
6. Соединить CLI/guardian с accepted Mac profile и regression suite; guard открывается по явному
   accepted manifest, не по `cfg(target_os = "macos")` или положительному compile.
7. Сохранить настоящие qualification artifacts; затем включить упаковку/публикационный маршрут.

Для MP-02/03 обязательны meaningful regressions: V2 bytes/digests, DWORD `0xc0000005`,
POSIX exit versus signal, unknown stop veto, idempotent repeat/no relaunch, conflicting target,
stopped mutation lock, interrupted restore marker и невозможность старого writer принять V3.
Для MP-04 — mode-only changes, case/Unicode collisions, aliases/xattrs policy, stale tool hashes,
bounded copy и interrupted checkpoint/restore. Положительный контроль должен быть исполним.
Ни один portable unit test не называется доказательством Mac isolation.

## 10. CI, evidence и передача следующему исполнителю

Имеющийся `macos-14` portable job проверяет сборку/host data tests; он не становится native
macOS 26 arm64 qualification job и не определяет минимальную поддержанную ОС нового профиля.
Target/profile-specific runner выбирается после наличия настоящего пригодного Mac.
Не менять runner label на неподтверждённый и не добавлять постоянный self-hosted runner скрыто.
Signed release workflow/secrets вводятся отдельно; никакие signing credentials не попадают в repo.

[preflight-macos.sh](../scripts/preflight-macos.sh) выполняет только read-only inventory.
Он не устанавливает компоненты, не исправляет подписи/ACL, не запускает недоверенный workload
и сохраняет isolation readiness `UNVERIFIED`. Даже полностью доступный host inventory не снимает gates.
Реальные правила и матрица — [macos-acceptance.md](macos-acceptance.md).

В evidence каждого настоящего опыта нужны source/candidate SHA, OS patch/build, hardware/arch,
filesystem/case profile, signature/notarization facts, helper/tool/fixture hashes,
policy/capability revisions, executed counts, controls и известные ограничения.
Skipped/inapplicable mandatory case не закрывает кандидата; зелёный workflow без executed controls
не принимается как доказательство. Ошибка инфраструктуры отделяется от политики и workload exit.

Следующее готовое поручение: MP-00 сверяет закрытые V3 интерфейсы и acceptance gates с этой картой,
затем MP-01 получает read-only preflight настоящего выбранного Mac и план безопасных опытов;
MP-02 извлекает общий код с неизменными Windows V2/legacy Linux regression expectations.
Эта документация готова к handoff; она не выдаёт неподтверждённые Apple API за работающий backend.
