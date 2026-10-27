# macOS native: оценка API и обязательные исследования

Дата проверки источников: **2026-10-27 UTC**. Статус: **PREPARATION / NOT IMPLEMENTED**.
Это архитектурная оценка для следующего macOS-пакета, а не приёмка backend.
Runtime-код, запуск недоверенной нагрузки, подпись, установка, изменение TCC/ACL
и настройка компьютера этим документом не выполнялись.

Предлагаемый первый qualification target — **одна точная сборка macOS 26,
Apple silicon / arm64, локальный APFS, обычный пользователь без elevation**.
Read-only preflight фиксирует OS/patch/build, architecture/account и optional
Petri/helper code-file metadata. Hardware, Xcode/SDK, полный toolchain manifest
и signing provenance собираются отдельно назначенным build/qualification шагом;
preflight оставляет SDK `NOT_QUERIED`. Все факты закрепляются до опыта. Это
выбранный охват первого кандидата, **не минимальная версия всех перечисленных API**.
Intel/x86_64 и другие версии macOS остаются отдельными квалификациями.

## 1. Решение подготовки

Первым проверить **публичный App Sandbox с отдельным подписанным helper**,
минимальными entitlements и доверенным controller вне workload boundary.
Профиль предполагает headless native CPython 3.12, собственный CLI fixture,
одну лабораторию, затем два одновременных изолированных опыта; сеть `none`.
Точный patch Python и пригодность его поставки пока не выбраны.

App Sandbox — обоснованный кандидат для ограничения ущерба от недоверенного
кода, но не готовая замена произвольного Linux namespace/Windows Job API.
Полное production-решение нельзя выбрать до macOS feasibility spikes ниже.
До их приёмки `MacNativeReserved`/будущая macOS capability возвращают
`Unsupported`, а не разрешают запуск по наличию подписи или символа API.

Исключены MXC, Docker, Linux guest/WSL/VM и неограниченное исполнение на хосте.
Custom Seatbelt/SBPL допускается здесь только как отдельно описанная
архитектурная альтернатива с риском совместимости. Она не является запасным
путём при неудаче App Sandbox. Endpoint Security также не включается молча.

## 2. Публичные факты и границы вывода

| Механизм | Подтверждённое назначение | Что ещё не следует из API |
|---|---|---|
| App Sandbox | Ограничение доступа приложения к системным ресурсам, данным, сети и hardware через entitlements | Произвольный динамический per-lab профиль, независимость двух экземпляров одного app/helper, полная совместимость toolchains |
| Подписанный helper и inheritance | Apple документирует embedded CLI, `posix_spawn`/`NSTask`, наследование sandbox; XPC подходит для разделения полномочий | Любой импортированный executable запускается по одному read-only bookmark; основной controller может передать ребёнку все свои права |
| Custom `sandbox_init` / `sandbox-exec` и SBPL | На существующих ОС применяются custom Seatbelt profiles | Поддерживаемый и стабильный Apple контракт языка политики; право обещать его наличие в будущей ОС |
| `posix_spawn` с suspended launch и явными file actions | Начальное управление собственным child, ограничение inherited descriptors | Неотделимая принадлежность всех произвольных потомков к одному объекту остановки |
| `kqueue` / `EVFILT_PROC` | Наблюдение событий конкретного процесса | Полный registry рождений всех потомков, остановка их эффектов, доказательство пустого дерева |
| `launchd` cleanup / process groups | Очистка процессов с тем же PGID в задокументированном случае | Windows Job с запретом breakaway; остановка потомка, изменившего group/session |
| Darwin resource limits | Отдельные process resource controls с собственными scope и semantics | Hard aggregate memory/process/CPU/disk budgets всей lab или всех её потомков |
| `es_new_descendants_client` | ES auth/notify events для descendant subtree; новые API относятся к macOS 27 | Sandbox deny-by-default для всех операций, готовность на target macOS 26, доступность restricted entitlement у команды |

API/framework исторически могут существовать раньше qualification target.
Примеры Apple для embedded helper используют Intel target 10.15 и arm64 target
11.0; эти числа не устанавливают нижнюю границу поддержки Petri. Новые SDK/API
нужно проверять по установленным публичным headers и availability annotations,
не по имени ОС, результату веб-поиска или наличию похожего enum.

## 3. App Sandbox: важные ограничения первого кандидата

### 3.1. Executable access не равен read-only доступу

Apple DTS описывает static entitlements и dynamic sandbox extensions отдельно.
Публичные user-selected extensions дают read-only либо read-write доступ;
dynamic extension для executable access в указанном источнике отсутствует.
Следовательно, bookmark на импортированный Python-каталог не доказывает право
запустить его бинарник или загрузить произвольные native extensions.

До выбора поставки нужно проверить альтернативы внутри App Sandbox:
встроенный и подписанный инструмент либо другая точно разрешённая схема
регистрации/исполнения. Не допускаются скрытая переподпись пользовательских
бинарников, снятие quarantine, широкий доступ к `$HOME` или изменение SDK/OS ACL
ради прохождения опыта. Перемещение framework-based CPython может нарушить
ссылки, подпись, `@rpath` и загрузку stdlib/DLL-эквивалентов; эти свойства
не переносятся из успешного Windows PE import.

### 3.2. App identity не является lab identity

Приложение имеет доступ к своему app-container. Несколько запусков одного
helper с той же identity не получают автоматически независимые контейнеры
данных. `cwd`, `HOME` и отдельный PID не меняют kernel access policy.

Spike обязан доказать отсутствие доступа из lab A к workspace/temp/артефактам
lab B и control metadata. Общий writable app-container не должен становиться
источником настроек, startup hooks, исполняемых инструментов или управляющих
сообщений другой lab. Если это нельзя обеспечить публичной выбранной моделью,
результат — architectural blocker, а не неявное ослабление per-lab требования.

### 3.3. Полномочия helper и controller разделены

Собственный workload launcher включает `com.apple.security.app-sandbox`.
Встроенные children, использующие entitlement inheritance, следуют точно
документированным signing constraints Apple; `inherit` не назначается
основному launcher как универсальный способ запуска. Важная деталь: child
наследует sandbox родителя и без маркера `inherit`, если его executable не
просит создать несовместимый новый App Sandbox. Нельзя считать отсутствие
entitlement у `/bin/sh` или native tool способом выхода из ограничений.

Первый профиль не включает network client/server, Apple Events/automation,
широкие application groups, Keychain grants, доступ к пользовательским
каталогам, GUI, debugger, Simulator, Xcode GUI или облачного агента. Добавление
такой возможности требует собственного capability contract и отрицательного
сценария. Администратор, Full Disk Access, отключение SIP/TCC и произвольные
temporary exceptions не являются средствами исправления отказа профиля.

Controller не получает от нагрузки произвольный путь к source Git/control
store или команду для исполнения вне sandbox. Доступ к broker, если он позже
появится, требует проверки caller identity и конкретного operation binding.
Один PID, UID, Team ID или факт владения socket не являются таким допуском.

## 4. Descendants, остановка и ресурсы — отдельный blocker

Публичный `posix_spawn` позволяет контролировать начальное создание child.
Флаг `POSIX_SPAWN_CLOEXEC_DEFAULT` с явными file actions полезен для закрытия
неразрешённых descriptors; suspended launch полезен для первоначального
binding. Ни то ни другое само не удерживает все будущие descendants.

Darwin `kqueue` агрегирует события. В Apple XNU `event.h` прямо отмечено, что
child PID из внутреннего `NOTE_FORK` hint не передаётся в результирующий
`kevent`. Не следует переносить FreeBSD `NOTE_TRACK`/process-descriptor
семантику на macOS. Наблюдение NOTE_EXIT root-процесса не доказывает отсутствие
внуков и daemonized children.

Задокументированный `launchd` cleanup касается оставшихся процессов с **тем же
PGID**. Поэтому `killpg`, exit helper, закрытие XPC connection, PID-file и
несколько обходов списка процессов не называются доказанной остановкой дерева.
Нужно исследовать `setsid`, `setpgid`, fork/exec без shell, double-fork,
потерю промежуточного parent до передачи identity, сбой controller/guardian,
PID reuse, background children и отсутствие новых эффектов после stop receipt.

Per-process rlimits и периодический подсчёт RSS не выдаются за обязательные
aggregate hard limits. До реализации фиксируются exact scope, единицы CPU,
какой OS механизм запрещает spawn/allocation сверх бюджета, и чем наблюдатель
подтверждает исход. Если нужного механизма нет, соответствующий обязательный
профиль возвращает `Unsupported`; изменение требований проходит отдельное
решение. Disk reserve, APFS free-space check и bounded output не являются
hard disk quota.

## 5. Почему новые Endpoint Security API не закрывают вопрос автоматически

Apple DTS и документация описывают `es_new_descendants_client` как новое
направление macOS 27. Проверенная API-страница помечена Beta. Указан
`com.apple.developer.endpoint-security.client`; отсутствие необходимости root
и TCC approval для этого descendants API не отменяет entitlement/signing
requirements. Наличие ключа в локальном plist не означает grant Apple.

ES получает только поддержанные auth/notify события. Notification сообщает
факт, authorization позволяет решать конкретную операцию; одно нельзя
выдавать за другое. API не объявляет полное покрытие файлов, IP/AF_UNIX/Mach,
сетевых обходов, resource budgets и надёжный Job-подобный tree handle.
Потери событий, deadline/queue failure и crash клиента требуют собственного
fail-closed доказательства. Target macOS 26 не должен зависеть от OS 27 API.

ES может стать отдельно принятым усилением или другим native-кандидатом,
когда доступны стабильные OS/SDK, нужный grant, квалифицированная поставка и
матрица покрытия. До этого он не заменяет основной feasibility gate.

## 6. Обязательные spikes и критерии прекращения выбранного пути

| Gate | Что доказать на собственных данных | Условие остановки/нового ADR |
|---|---|---|
| M-API | Exact OS/SDK/arch/signing; helper действительно стартует в App Sandbox до эффекта нагрузки | Потребовался недекларированный SPI, elevation, TCC/SIP/host ACL workaround |
| M-EXEC | Mach-O arm64 Python 3.12 и native fixture запускаются; subprocess наследует ограничения; argv/env/cwd/stdlib закреплены | Нельзя исполнить зарегистрированный toolchain без широкого исключения/неразрешённой переподписи |
| M-FS | Разрешённая запись проходит; host/source/control/tool/oracle запрещены; A/B не читают и не меняют друг друга | Shared app-container либо dynamic grants дают доступ к соседней lab/управлению |
| M-NET | Positive control связи и отрицательные IPv4/IPv6/LAN/host loopback/AF_UNIX/Mach probes; нет скрытого transport | Network-none сформулирован шире фактически предотвращённых операций |
| M-TREE | Точное начальное binding, lifecycle descendants, stop и crash cleanup с hostile detach cases | Возможен ненаблюдаемый/неостановленный descendant или stop подтверждён только по root PID |
| M-RES | Каждый mandatory budget имеет OS enforcement либо честный отказ; measurement и stop имеют отдельные oracle | Monitoring назван hard quota; per-process предел назван aggregate |
| M-REC | Сбой до/после запуска, отказ журнала, restart/reconcile и повтор operation ID не повторяют неизвестный эффект | Повтор команды или fabricated success после потери связи |
| M-DIST | Проверенная собственная signed/notarized поставка и воспроизводимый install/uninstall scope | Тест ad-hoc build выдан за подтверждение распространяемой поставки |

Все gates сейчас **UNVERIFIED**. Готовая таблица/скрипт inventory не даёт PASS.
Полная спецификация должна заранее назначить позитивный контроль, конкретный
отрицательный опыт, trusted oracle, expected effect и retained evidence.
Невозможность mandatory gate останавливает выбранный runtime-путь; это не
повод автоматически пробовать SBPL, ES, VM, Docker или unrestricted host.

Правило следующего решения: сохранить исходный неуспех; уточнить конкретное
невыразимое свойство; оценить альтернативный native API/поставку; отдельно
принять новую архитектуру либо изменённую границу профиля. Никакая альтернатива
не повышает прежнюю capability до `Supported` задним числом.

## 7. Что переиспользовать из Windows-кандидата

Переносимы смысл operation/execution IDs, canonical request hash,
идемпотентность, журнал intent/result, `Unknown`/`Unconfirmed` outcome,
bounded artifact manifest, stopped-only checkpoints и отсутствие автоматического
promotion. Это не означает, что текущий Windows-only код уже provider-neutral.

- `src/execution.rs`: отделить общий lifecycle от `windows-native` validation,
  LPAC/Job facts, Windows CPU-time units и OS-specific private storage.
- `src/native_tools.rs`: переиспользовать принцип инертного bounded verified
  import; Windows PE/NTFS/ASCII path rules нельзя назвать Mac Mach-O/APFS
  registration. Добавить отдельный manifest/signature/dependency contract.
- `src/native_checkpoints.rs` и `src/git.rs`: сохранить правила provenance,
  bounded copy и hostile-object refusal; квалифицировать Darwin `openat`/
  no-follow object-relative traversal, APFS case/Unicode/xattrs/resource forks,
  hardlinks и snapshot/clone semantics. APFS clone не является hardlink и сам
  не доказывает согласованный stopped checkpoint или очистку секретов.
- `src/windows_cli.rs`: отделить общий protocol envelope от Windows guardian
  dispatch. Mac adapter не вызывает Windows API и не переинтерпретирует V2
  Windows metadata как Mac lab.
- `src/windows_native.rs` и `src/windows_native/win.rs`: служат источником
  наблюдаемого контракта; LPAC SID, DACL/Low IL, mandatory Job и
  `ActiveProcesses=0` остаются платформенными механизмами Windows.

Рефакторинг контрактов, изменение metadata и миграция требуют собственных
пакетов/тестов; текущий Windows/Linux результат сохраняется. Имена веток и
подготовленная Mac документация не являются реализацией Mac backend.

## 8. Первичные источники

Ниже — проверенные **2026-10-27** Apple docs, Apple DTS и опубликованный Apple
исходный код. Исторические примеры и текущие framework страницы различаются;
перед native-опытом повторно фиксируются SDK headers/availability на target.

1. [App Sandbox — Apple Developer Documentation](https://developer.apple.com/documentation/security/app-sandbox).
   Назначение защиты и entitlement-based access control; не обещание отдельного
   lab/container и не API произвольной динамической SBPL policy.
2. [Embedding a command-line tool in a sandboxed app](https://developer.apple.com/documentation/xcode/embedding-a-helper-tool-in-a-sandboxed-app).
   Native helper, signing/inheritance constraints, внешняя сборка и различные
   architecture deployment targets в примере Apple.
3. [Enabling App Sandbox — archived entitlement reference](https://developer.apple.com/library/archive/documentation/Miscellaneous/Reference/EntitlementKeyReference/Chapters/EnablingAppSandbox.html).
   Static child inheritance, bookmarks и рекомендации XPC. Это архивная
   справка, которую нужно сопоставить с текущим SDK/helper guide.
4. [On File System Permissions — Apple DTS](https://developer.apple.com/forums/thread/678819).
   Пост создан 2021-04, relevant update 2026-09-18: static/dynamic sandbox,
   отсутствие dynamic executable extension, inheritance, MAC/TCC и ES.
5. [Crashing in sandbox-exec — Apple DTS](https://developer.apple.com/forums/thread/777509).
   Объяснение 2025-03 и follow-up 2026-09: custom SBPL не является
   поддерживаемым third-party API, App Sandbox пригоден и для non-app кода;
   новые descendants ES API имеют отдельные ограничения.
6. [es_new_descendants_client — Apple API documentation](https://developer.apple.com/documentation/endpointsecurity/es_new_descendants_client(_:_:)).
   Auth/notify scope, entitlement, no-root/no-TCC notes и текущий Beta status;
   OS 27 attribution дополнительно подтверждается предыдущим DTS источником.
7. [kqueue(2) — Apple archived manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kqueue.2.html)
   и [Apple XNU event.h](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/event.h).
   Process observation/aggregation и ограничение передачи child PID в
   NOTE_FORK; это исходники/документация механизма, не тест нашего target.
8. [launchd.plist(5) — Apple published source](https://github.com/apple-oss-distributions/launchd/blob/main/man/launchd.plist.5).
   `AbandonProcessGroup` описывает cleanup того же process group, не
   неотделимую принадлежность всех descendants.
9. [Darwin resource.h — Apple published source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/resource.h).
   Декларации resource controls; наличие декларации не заменяет измерение
   scope/enforcement на принятой версии ОС.
10. [Process.swift — Swift Foundation source](https://github.com/swiftlang/swift-corelibs-foundation/blob/main/Sources/Foundation/Process.swift).
    Применение Darwin `POSIX_SPAWN_CLOEXEC_DEFAULT` с file actions. Пример
    безопасного управления descriptors не доказывает custody произвольных
    descendants и не является готовым Petri runtime.
