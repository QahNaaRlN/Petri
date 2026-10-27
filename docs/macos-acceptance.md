# macOS: план приёмки собственного native backend

Дата: **2026-10-27**. Статус: **подготовка; runtime не реализован и не квалифицирован**.

Предлагаемый первый профиль — `macos-native-python312-arm64/v1`: **macOS 26,
Apple Silicon arm64, обычный пользователь вне группы admin**, собственный
offline CPython 3.12 CLI fixture и его потомки. Точный product version,
build, Python patch и digests получают на реальном выбранном Mac и закрепляют
в candidate manifest. Здесь нет выдуманного build, аккаунта, signing identity
или свидетельства успешного macOS-запуска.

Этот документ задаёт подготовку и будущие oracles. Он не разрешает установку,
подписание, смену ACL/TCC/SIP, выдачу entitlement, создание аккаунта или запуск
недоверенной нагрузки. Реальный прогон требует отдельного назначения пригодной
машины и собственного fixture. Windows-кандидат и Linux не получают новый смысл
от появления этого документа.

## 1. Решения, которые должны предшествовать исполнению

1. Проверить осуществимость отдельного нативного App Sandbox helper через
   поддержанные Apple API, подпись и минимальные entitlements. Это кандидат,
   пока helper не способен прочитать RX toolchain и работать с private workspace
   при заявленной изоляции. Само наличие framework, symbol или sandbox tool
   не доказывает возможность установить нужную политику.
2. Зафиксировать способ раздельной identity лабораторий, открытия разрешённых
   путей, IPC и владения процессным деревом. Подписанный общий helper автоматически
   не даёт per-lab изоляцию; общий app container не называется отдельной lab.
3. Принять доказуемые scope лимитов CPU/RAM/process/disk, реакцию и допуски.
   POSIX process group и RLIMIT не выдаются за Windows Job или групповую квоту.
4. Отдельно решить совместимость и lifecycle. Перевод режима на deprecated
   `sandbox-exec`/SBPL не является автоматическим fallback; нужны собственные
   обоснование, ограниченный профиль и решение о поддерживаемом контракте.
5. Сохранить native направление: Windows/Linux VM, Docker, MXC или запуск
   непосредственно без обязательной защиты не заменяют неготовый macOS backend.

Endpoint Security, управляемые entitlements и будущие версии API не включаются
в prerequisites первого профиля по одному упоминанию в документации. Возможности
наблюдения и enforcement оцениваются отдельно на реально доступном SDK/host.
Подробные API-кандидаты и gates находятся в [оценке macOS API](macos-api-assessment.md).

## 2. Что делает preflight

[`preflight-macos.sh`](../scripts/preflight-macos.sh) выполняет только read-only
inventory. Он читает `uname`, `sw_vers` и минимальные account facts; не печатает
имя пользователя, список групп, keychain, credentials или пользовательские файлы.
Проверяются явно заданные exact version/build/architecture и standard account.
Root/admin не исправляются через sudo или изменение политики.

Developer tools проверяются **на наличие**. `xcrun`/compiler не вызываются,
чтобы неподготовленная машина не перешла к запросу установки. Версия SDK остаётся
`NOT_QUERIED`; её закрепит отдельно назначенная сборка собственного helper.
Наличие `/usr/bin/sandbox-exec` регистрируется без вызова и без выбора backend.

Для явно указанных абсолютных regular code-file paths script может вычислить
SHA-256, прочитать тип подписи и выполнить статический `codesign --verify`.
Он не запускает бинарник, не создаёт подпись, не ищет signing identities,
не обращается к `security find-identity`, Gatekeeper или notarization service.
Каталог домашнего пользователя и произвольные helper paths не обнаруживаются
автоматически. Отсутствие helper отражается `not_provided`.

Пример после выбора владельцем точных наблюдённых значений:

```sh
sh scripts/preflight-macos.sh \
  --profile macos-native-python312-arm64/v1 \
  --expected-version "$PETRI_MAC_VERSION" \
  --expected-build "$PETRI_MAC_BUILD" \
  --expected-arch arm64
```

Переменные примера — task-specific значения, введённые после read-only inventory;
они не являются заранее заданными фактами. Без полного pin script возвращает
`PROFILE_NOT_PINNED`/`UNSUPPORTED_HOST`, exit 2. Ошибка аргументов — exit 1.
Exit 0 означает **только завершение запрошенного inventory**. Во всех случаях
`runtime_probe=NOT_RUN`, `isolation_verified=false`, runtime/descendant-stop/
aggregate-resources/release acceptance остаются `UNVERIFIED`.

JSON выводится в stdout одним документом; сохранение в выбранное evidence место
выполняет вызывающий. `--help` не выполняет inventory. Portable unit tests
проверяют truthfulness отказа, JSON/argument handling и отсутствие скрытого
исполнения; они не дают положительного macOS security результата.

## 3. Требуемая инфраструктура реального прогона

Нужен собственный Mac с закреплённым macOS 26 build и arm64 процессом без Rosetta
для первого профиля. Запуск проводится в выделенном standard non-admin аккаунте;
его существование и доступность подтверждает владелец машины. Сведения об аккаунте
в отчёте ограничены свойствами, нужными для проверки, без секретов и профиля.

На машине заранее доступны разрешённые build tools/SDK, скопированный доверенный
CPython toolchain, собственные source/Git canaries и отдельное место артефактов.
Подготовка этих зависимостей не является побочным действием preflight.
Регистрируются свободное место, состояние обязательных API и политика подписи.
OS prerequisites не понижаются для прохождения тестов.

Оркестратор/harness и oracles располагаются вне изменяемого workspace. Для
отрицательных файловых/IPC/network опытов используются только собственные
canaries и controllable endpoints. Реальные SSH keys, keychains, документы,
credentials, рабочие БД и чужие процессы не используются как тестовые цели.

До первого запуска публикуется закрытый перечень критериев и fault points.
Каждая проверка содержит positive control, действие, независимый oracle,
точный policy/helper/toolchain digest и допустимую неопределённость.
Ненаблюдаемое, отсутствующая предпосылка и сбой harness дают `UNVERIFIED`.
Обязательный критерий нельзя закрыть `N/A` или исключить после неудобного отказа.

## 4. Матрица приёмки кандидата

Все строки ниже сейчас **UNVERIFIED**; таблица не является выполненным отчётом.

| ID | Положительный контроль и отрицательный опыт | Независимый oracle / evidence |
|---|---|---|
| MAC-01 Host/profile | Exact version/build/arm64/standard account совпадают; mismatch, admin и недоступный API отказывают до workload | OS/account facts, candidate manifest, отсутствие workload marker; compiler/API presence отдельно от enforcement |
| MAC-02 Signed helper/toolchain | Закреплённый native CPython читает stdlib и выполняет свой script; подмена helper/toolchain/entitlements не допускает start | Digests, signature/entitlement inventory, source of each tool; никакого исполнения import-каталога |
| MAC-03 Lab identities | Две lab имеют раздельные writable areas и effective authority; A не получает private state B | Own cross-lab canaries, actual sandbox/container identity, effective access, handles and policy refs |
| MAC-04 Files and aliases | RX tools, RW workspace/temp/private profile работают; source/controller/blackbox/DB canaries закрыты на чтение/запись | Host digests до/после, object identity, RO-write denial, symlink/hardlink/reparse-equivalent/late rename/case/Unicode/normalization matrix |
| MAC-05 Native environment | CLI получает exact argv/cwd и минимальное окружение, читает stdlib, создаёт child | Exact tool/SDK/OS/runtime metadata; host secret canary отсутствует; config/hooks из source не выполняются на хосте |
| MAC-06 Network none | Собственные IPv4/IPv6 TCP/UDP/DNS/loopback controls доступны снаружи; workload их не достигает | Endpoint counters/packet or supported OS observations до/после; отсутствие сети/IPv6 у harness не является PASS запрета |
| MAC-07 IPC/services | Явно разрешённая controller/helper связь и необходимый закрытый allowlist OS services работают; workload не получает неразрешённый доступ к control/чужим Mach/XPC/Unix sockets, keychain/agent/broker services | Own service endpoints и caller identity, denied requests, отсутствие inherited control/network handles; реальные секреты не используются |
| MAC-08 Tree ownership/stop | Fixture создаёт child/grandchild и пробует setsid/daemon/double-fork; stop и timeout прекращают всё принадлежащее дерево | Независимая ownership graph и retained OS handles/identity; отсутствие effects после срока; один завершённый root/process group недостаточен |
| MAC-09 Controller/helper crash | Убивается только собственный процесс по удержанному handle и подтверждённой identity; нагрузка останавливается | External member observations отдельно от durable receipt; потерянное свидетельство остаётся Unknown и блокирует rerun/cleanup |
| MAC-10 Resources | Заявленные process/RAM/CPU-time/wall/output budgets выполняются на ветвящемся fixture; непригодная policy отказывает | Exact scope/units, whole-tree counters, пороги, stop latency; per-process RLIMIT/soft disk scan не называются aggregate hard caps |
| MAC-11 Mandatory journal | Допущенный capture сохраняет bounded events/output; отказ записи до/после эффекта останавливает исполнение | Protected host verifier, sequence/order/digests, независимый stop path при отказавшем журнале, никаких выдуманных terminal append |
| MAC-12 Git/result/checkpoint | Source HEAD/dirty/untracked сохранены; stopped snapshot восстанавливает workspace/Git, не audit; stale promotion отказана | Host private embedded Git metadata identity, before/after trees, trusted manifest, fault boundaries; project `.git` не выбирает host Git target |
| MAC-13 Recovery/idempotency | Повтор operation key возвращает прежний execution; crash between intent/effect/result не повторяет неизвестную команду | Frozen request hash, execution/operation IDs, external markers, journal/reconcile, запрет конкурирующих writers |
| MAC-14 Packaging/signatures | First-party controlled build и явный отказ неподдержанных OS/tool versions; стандартный пользователь не устанавливает helper через скрытый sudo | Build/signature/entitlement/notarization evidence с разделёнными scopes; отсутствие Docker/MXC/VM fallback и host ACL/TCC/SIP repair |
| MAC-15 Cross-platform compatibility | Linux baseline и Windows V2 данные/CLI остаются прежними; Mac environment tagged отдельно | Byte/digest fixtures, native refusal на другой ОС, migration backup/recovery; Mac compile не называется native E2E |

Полная native IDE, GUI, терминал/PTY, live model provider, Vault, расширенные
allowlists, GPU и многопользовательская служба не входят в первый offline CLI
профиль. Их future scenarios не закрываются автоматически MAC-01…MAC-15.

## 5. Остановка и ресурсы — обязательные feasibility gates

Перед реализацией обещаний MAC-08…MAC-10 нужно выбрать OS-механизм, который
ограничивает и обнаруживает всё дерево недоверенного arbitrary code. Знание
родительского PID и `killpg` не доказывает containment после ухода descendant
в другую session. PID reuse и повторная привязка к чужому процессу исключаются
через подтверждённую ownership/OS identity. Неподдерживаемая гарантия отказывает.

Контроллер не должен ждать добровольного ответа агента для stop. При потере
журнала независимый stop продолжает работать. Crash evidence различает
запрос остановки, наблюдаемое прекращение всего собственного fixture дерева
и неизвестный исход. Внешняя проверка не переписывает потерянный durable receipt.

Численные budgets закрепляются после feasibility и до квалификации, с явными
units и stop tolerance. Windows Job values не переносятся механически на macOS.
Если доступны только per-process limits, это именованный ограниченный профиль,
а не выполнение прежнего aggregate требования. Soft scan/reservation не является
жёсткой дисковой квотой; overshoot/неизвестное показываются в отчёте.

## 6. Ad-hoc разработка и подписанная поставка

Локальный ad-hoc helper может участвовать только в явно ограниченном собственном
development spike, если реальный macOS допускает его sandbox/entitlements.
Это проверяется, а не предполагается. Успех ad-hoc spike не доказывает стабильную
identity после пересборки, обновление профиля, доверие Gatekeeper или release.
Unsigned helper не получает исключения/понижение защиты ради зелёного теста.

Отдельный release gate требует реально существующей разрешённой signing identity,
проверенной подписи helper+controller, согласованных entitlements и требуемой
notarization/distribution проверки. Документ не предполагает наличие Developer
ID, Apple account или выданного управляемого entitlement. При их отсутствии
release gate остаётся `UNVERIFIED`; preflight не пытается их создать или найти.

`codesign --verify` подтверждает только соответствующий статический code-signature
факт. Он не доказывает App Sandbox activation, правильную policy, network-none,
stop descendants или notarization. Смена подписи/entitlements/toolchain создаёт
новый candidate digest и повтор затронутой qualification.

## 7. Форма будущего отчёта

Отчёт включает profile revision; exact OS/build/architecture/account facts;
controller/helper/toolchain/source/policy/harness hashes; SDK/compiler version;
signature/entitlement mode; case IDs; positive controls; OS observations;
ожидаемое и фактическое поведение; exit/status; limits/peaks/latency; durable
и external proof; artifacts/digests; gaps; `PASS`/`FAIL`/`UNVERIFIED` по критерию.

Итог ограниченного spike и полнота родительской спецификации — разные поля.
Один happy path, отсутствие marker, зелёная unit matrix или статическая сборка
не закрывают всю матрицу. Нет отчёта с пригодного Mac — нет native qualification.

## 8. Основания для уточнения API

- [App Sandbox](https://developer.apple.com/documentation/security/app-sandbox): публичная модель sandbox приложения; конкретный helper требует feasibility.
- [App Sandbox entitlements](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.app-sandbox): факт entitlement не заменяет проверку effective restrictions.
- [Apple Code Signing Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/Introduction/Introduction.html): подпись и designated identity оцениваются отдельно от policy.
- [Notarizing macOS software](https://developer.apple.com/documentation/security/notarizing-macos-software-before-distribution): самостоятельный distribution gate, не результат inventory.
- [Endpoint Security](https://developer.apple.com/documentation/endpointsecurity): отдельная возможность, не обещанный обязательный механизм первого offline helper.

Конкретные supported APIs, доступность SDK и ограничения публикуются по
результату отдельной оценки, а не по сходству названий с Windows/Linux механизмами.
