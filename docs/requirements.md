# ТЗ — Petri: нативные лаборатории, v0.4-draft1

Дата: 2026-10-26 UTC. Статус: **DRAFT — для архитектурного ревью и приёмки требований**.
Это предложение новой редакции требований; оно не удостоверяет готовность реализации.
Реализация Windows-кандидата ведётся отдельно в ветке `feat/windows-native-candidate`; фактическая готовность и проверки приведены в [статусе](status.md).
`v0.4-draft1` — версия этих документов, а не назначенное изменение версии CLI или выпуск.
Технические контракты и решения вынесены в [ТС](technical-specification.md).

## 1. Назначение и исходная точка

Petri — лаборатория для выполнения программ и задач кодирующих агентов под контролем пользователя.
Лаборатория объединяет изолированное исполнение, независимый Git workspace, инструменты,
наблюдения, остановку, восстановление и явное принятие результата.
Пользователь должен понимать, что запущено, с какими полномочиями и что изменилось.

Целевой продукт исполняет Windows-программы на Windows, Linux-программы на Linux,
macOS-программы на macOS через собственные платформенные backend Petri.
Цель — переносимая модель лаборатории с проверенными гарантиями каждой платформы.
Совпадение имён команд не означает одинаковые механизмы защиты или одинаковые бинарники.

Сравнительная исходная точка: репозиторий Petri, ветка `feat/petri-v0.3`, commit
[`70e0bc69c1a5be0761f073e69b6efae9a751b22d`](https://github.com/QahNaaRlN/petri/tree/70e0bc69c1a5be0761f073e69b6efae9a751b22d).
Это подготовленный Linux-кандидат; полная продуктовая приёмка не заявляется.
`main`/`dev` на момент исследования не содержат эту реализацию.

Исходные [ТЗ v0.3](https://github.com/QahNaaRlN/petri/blob/70e0bc69c1a5be0761f073e69b6efae9a751b22d/docs/requirements.md),
[ТС v0.3](https://github.com/QahNaaRlN/petri/blob/70e0bc69c1a5be0761f073e69b6efae9a751b22d/docs/technical-specification.md)
и [оригинальные документы](https://github.com/QahNaaRlN/petri/tree/70e0bc69c1a5be0761f073e69b6efae9a751b22d/docs/sources)
сохраняются без изменения как источники происхождения требований.

## 2. Решения редакции и границы

| ID | Требование |
| --- | --- |
| PT-NATIVE-01 | Базовый запуск лаборатории не требует Docker, установленного `git.exe`/системного Git или MXC как runtime-зависимости. Встроенная Git-библиотека допустима. |
| PT-NATIVE-02 | Backend использует нативные средства выбранной ОС. Нет автоматического исполнения через WSL, VM, Docker, MXC или неограниченный хост при ошибке защиты. |
| PT-NATIVE-03 | Поддержка трёх ОС — обязательная цель продукта; приёмка Windows-кандидата не закрывает Linux/macOS и весь продукт. |
| PT-NATIVE-04 | Выбор механизма macOS остаётся предметом отдельного backend-кандидата. Нативная цель обязательна; доступность будущего публичного API или конкретного SBPL-интерфейса не обещается. |
| PT-NATIVE-05 | Один установщик Petri не означает отсутствие предпосылок ОС, установку всех языков/SDK или включение виртуализации. Предпосылки проверяются и объясняются. |
| PT-NATIVE-06 | Платформенное отсутствие обязательной защиты завершает запуск отказом до недоверенной нагрузки; предлагаемая пользователю диагностика не ослабляет политику. |

Собственное решение вправе использовать документированные native OS API и обычные библиотеки,
включая libgit2. Запрет MXC как основания не является запретом Windows API Microsoft.

Редакция заменяет прежнее направление VM/WSL для Windows/macOS нативными backend.
Linux rootfs/OCI-путь сохраняется отдельной возможностью Linux, а не универсальным определением Stack.
Полный план ниже задаёт целевое поведение. Наличие требования не означает его реализацию; первый пакет Windows и оставшиеся ограничения перечислены в [статусе](status.md).

## 3. Пользовательская модель и доверие

**Lab** — устойчивый объект с идентификатором, workspace, Git baseline, окружением,
политикой, попытками исполнения, наблюдениями и снимками.
**Execution** — одна попытка запуска; повтор команды создаёт отдельную историю исполнения.
**Stack** — закреплённый состав инструментов и окружения для конкретной ОС/архитектуры.
**Checkpoint** — снимок остановленного workspace и его Git-состояния; не память процесса.
**Broker** — доверенный host-компонент для узко разрешённых внешних операций.
**Evidence** — проверяемые данные с происхождением, временем, execution ID и digest.

Недоверенны команда, задача, проектная конфигурация, исходники, вывод нагрузки и импортируемые архивы.
Доверенная база включает Petri, выбранные ОС/ядро, установленную политику и явно выбранные инструменты.
Хеш подтверждает идентичность содержимого; подпись и доверие издателю проверяются отдельно.
Защита от скомпрометированного ядра, администратора или самого Petri вне модели.
Полное автоматическое обнаружение любых секретов в исходниках не обещается.
Вывод агента не становится управляющей командой или доказательством успеха без проверки.

Petri — подсистема исполнения Meridian и самостоятельная CLI-поверхность того же
контракта. Petri владеет lab/execution/runtime facts; Meridian владеет постановкой,
actor/role, надзором, handoff, интерпретацией evidence, приёмкой и решением об
интеграции. Публикация review-ветки Petri не означает инженерную приёмку Meridian.

| ID | Требование интеграционной границы |
| --- | --- |
| PT-MER-01 | Lab, физическая execution и execution-run Meridian имеют разные идентичности; они связываются явными correlation refs. |
| PT-MER-02 | Petri применяет аутентифицированный допуск и сообщает эффективные ограничения; роль, модель, текст задания и exit code сами не предоставляют полномочий. |
| PT-MER-03 | Результат возвращается как versioned manifest с точными входами, runtime facts, digests и gaps; raw output не становится принятой нормой или решением. |
| PT-MER-04 | Первый Windows-кандидат проверяется через собственный CLI/fixture. Реальное подключение Meridian и запуск сменяемого агента — отдельный последующий пакет; существующие механизмы приёмки Meridian не дублируются в Petri. |

## 4. Жизненный цикл и пользовательский контроль

| ID | Требование |
| --- | --- |
| PT-LAB-01 | Пользователь выбирает repo/base, задачу, платформенный Stack, политику и явную команду либо поддержанный адаптер агента. |
| PT-LAB-02 | Prepare создаёт независимое пространство из закреплённого committed snapshot; dirty/untracked исходника не копируются молча. |
| PT-LAB-03 | Идентификаторы lab/execution/checkpoint не являются путями. Все операции ограничены принадлежащими Petri объектами. |
| PT-LAB-04 | Состояния различают подготовку, установку защиты, исполняемую нагрузку, завершение, отказ и неизвестный исход. Создание supervisor не доказывает успешный sandbox setup. |
| PT-LAB-05 | Stop/timeout прекращают всё принадлежащее исполнению дерево процессов; освобождение ресурсов подтверждается наблюдением backend. |
| PT-LAB-06 | После аварии приложение не предполагает отсутствие процессов по PID-файлу и не повторяет неизвестную команду автоматически. |
| PT-LAB-07 | Повтор управляющего запроса с тем же ключом возвращает прежний результат/статус; другое содержимое с тем же ключом даёт конфликт. |
| PT-LAB-08 | Пользователь может исследовать результат, сохранить stopped checkpoint, возобновить новую execution, экспортировать кандидат или удалить свою остановленную лабораторию. |
| PT-LAB-09 | Checkpoint/restore/discard конфликтуют с активным исполнением; гонка не приводит к частичному снимку или удалению чужих данных. |
| PT-LAB-10 | Неуспех workload, setup, контроля бюджета и записи обязательного журнала различаются. `exit 0` не означает приёмку результата пользователем. |

## 5. Изоляция и ресурсы

| ID | Требование |
| --- | --- |
| PT-ISO-01 | Нагрузка видит только явно разрешённые файлы/каталоги и необходимую нативную среду. Хостовые личные данные и соседние проекты недоступны. |
| PT-ISO-02 | Запись разрешена только в workspace и выделенные временные/служебные области нагрузки. Toolchain и защищённый test oracle доступны лишь с назначенными правами. |
| PT-ISO-03 | Исходный repo, его refs/config/hooks/filters, host Git metadata, supervisor и управляющий журнал не доступны нагрузке на запись. |
| PT-ISO-04 | Политика учитывает alias, symlink/reparse/junction, hardlink, пути устройств и особенности имён/регистра ОС. Неподдержанные формы отклоняются явно. |
| PT-ISO-05 | Environment формируется явно; credentials, исходный HOME и произвольные inherited handles не переносятся. Необходимые переменные ОС документируются. |
| PT-ISO-06 | Default network = none, включая внешний egress, host loopback, LAN, IPv4/IPv6 и неподдержанные обходные transport. Неподдерживаемая обязательная гарантия запрещает старт. |
| PT-RES-01 | Для каждой execution задаются суммарные пределы числа процессов и памяти дерева, wall-clock timeout и определённый предел CPU-time. В первом Windows-профиле CPU-time — учитываемое Job суммарное user-mode время; оно не называется полным user+kernel CPU временем. Scope и единицы отражаются в manifest. |
| PT-RES-02 | Per-process limits не выдаются за aggregate budgets. Backend сообщает фактически установленный механизм, измерение и ограничения счётчиков. |
| PT-RES-03 | До prepare/start проверяется резерв диска; записываются бюджеты workspace/checkpoints/logs и действия при исчерпании. Резерв свободного места не объявляется hard quota. |
| PT-RES-04 | Невыполнимая обязательная hard quota приводит к Unsupported. Кандидат может явно исключить hard disk quota из своей гарантии, сохранив резерв, предел output и наблюдаемый отказ. |
| PT-RES-05 | Детерминированные deadline/output/journal бюджеты включают независимую остановку дерева. Жёсткие memory/process limits запрещают превышение средствами ОС; наблюдённое нарушение включает stop. Kernel enforcement и доступность уведомления проверяются отдельно: отказ allocation/spawn не объявляется автоматическим завершением Job. |

Исходные Linux namespaces/Landlock/seccomp и rlimits описаны в
[runtime baseline](https://github.com/QahNaaRlN/petri/blob/70e0bc69c1a5be0761f073e69b6efae9a751b22d/src/runtime.rs).
Его per-process ограничения остаются честно обозначенными; эта редакция не объявляет aggregate Linux budgets уже реализованными.

## 6. Git, результат и восстановление

| ID | Требование |
| --- | --- |
| PT-GIT-01 | Базовые Git-операции выполняются встроенной библиотекой без внешних hooks/helpers/filters и без runtime-зависимости системного Git. |
| PT-GIT-02 | Workspace имеет независимые host-only Git metadata. Writable refs исходника не разделяются с лабораторией. |
| PT-GIT-03 | Diff включает additions/modifications/deletions против неизменного baseline, в том числе уже закоммиченные внутри lab изменения. |
| PT-GIT-04 | Сохраняются source revision, baseline representation, исключённые пути и особенности materialization; потеря executable mode или коллизии имён не маскируются. |
| PT-GIT-05 | `.env`, `.env.*`, `.ssh`, Docker socket и объявленные защищённые пути не экспортируются. Их отсутствие объяснимо и не считается полным secret scan. |
| PT-GIT-06 | Принятие — отдельное host-действие после просмотра результата. Оно создаёт проверяемый кандидат/review branch и не перезаписывает dirty source или HEAD. |
| PT-GIT-07 | Устаревшая source base, неизвестное происхождение или неподдержанный объект дают отказ без потери данных. Submodules поддерживаются только после отдельной приёмки. |
| PT-GIT-08 | Push/PR/remote mutation возможны только через будущий типизированный broker с разрешением remote/ref; агент не получает эти полномочия по факту запуска. |
| PT-CP-01 | Stopped checkpoint содержит согласованные workspace/Git данные, metadata и digests; writable hardlinks к оригиналу запрещены. |
| PT-CP-02 | Restore не откатывает управляющий audit; память, открытые credentials, TCP-сессии и выполнявшиеся процессы не восстанавливаются. |
| PT-CP-03 | Обрыв snapshot/restore оставляет распознаваемое состояние и ограниченный recovery; частичная операция не выдаётся за завершённую. |

## 7. Tool hub и платформенные стеки

| ID | Требование |
| --- | --- |
| PT-TOOL-01 | Tool hub перечисляет доступные инструменты, версии, OS/arch, источник, digest и пригодность для выбранного backend. |
| PT-TOOL-02 | Одинаковый логический Stack на трёх ОС может иметь разные native binaries/digests. Эквивалентность поведения проверяется сценариями, а не совпадением имени. |
| PT-TOOL-03 | Поддерживаются явно выбранные локальные инструменты и офлайн-артефакты; изменившийся toolchain обнаруживается до запуска. |
| PT-TOOL-04 | Общие immutable данные можно переиспользовать; writable workspace не разделяет writable backing с ними или другой lab. |
| PT-TOOL-05 | Импорт проверяет размеры, digest, archive traversal и file types до публикации. Integrity не подменяет publisher authenticity. |
| PT-TOOL-06 | Linux rootfs/OCI import сохраняется; native Windows/macOS Stack не изображается Linux rootfs и не исполняется скрыто в Linux guest. |
| PT-TOOL-07 | Python, Node/JS и Rust входят в последующие реальные toolchain milestones; GUI, Xcode/SDK и специальные devices получают отдельную квалификацию. |
| PT-TOOL-08 | Builder/registry/signatures/SBOM/provenance — сохраняемые цели полного продукта; неподдержанные команды сообщают Unsupported. |

## 8. Наблюдаемость, секреты и сеть полного продукта

| ID | Требование |
| --- | --- |
| PT-OBS-01 | Host-only журнал связывает lab/execution/operation, sequence, время, попытку, backend/version, policy и Stack digests, argv, base и завершение. |
| PT-OBS-02 | Setup evidence отделено от workload output; stdout/stderr и output truncation/loss обозначаются явно. Output не исполняется как инструкция. |
| PT-OBS-03 | Capture/replay сообщает свой режим. PTY включает размеры/resize/input/output только после собственной реализации; pipe cast не называется PTY. |
| PT-OBS-04 | Пользователь видит состояние, отказ, код выхода, расход бюджета, diff и известные пробелы наблюдений. Неизвестные стоимость/токены не показываются нулём. |
| PT-OBS-05 | Полный file/exec/network/provider trace требует собственных адаптеров; имеющиеся события не объявляются полным наблюдением ОС. |
| PT-OBS-06 | Для task, metadata, logs, snapshots и экспортов задаются retention, access и deletion. Raw task/вывод не публикуются автоматически. |
| PT-OBS-07 | Удаление lab не уничтожает требуемую историю молча: явно выбирается export/retention/discard по принятой политике. |
| PT-OBS-08 | Наблюдаются действия, вызовы инструментов и доступные ответы; скрытые рассуждения модели не являются требуемым источником. Намерение или объяснение модели отделяется от зарегистрированного факта исполнения. |
| PT-OBS-09 | Просмотр недоверенного вывода безопасен по умолчанию: terminal control/OSC-последовательности экранируются; raw capture/replay требуют явной политики и не исполняются автоматически на хосте. |
| PT-SEC-01 | Vault Class A: signing key остаётся в host-keystore; broker разрешает конкретную подписываемую операцию, а не выдаёт private key агенту. |
| PT-SEC-02 | Vault Class B: bearer может быть скопирован получателем; TTL/revoke обеспечивает provider. Tmpfs/memfd/scrub не считаются отзывом токена. |
| PT-SEC-03 | Broker аутентифицирует запрос, ограничивает действие/адресата/срок/размер, журналирует решение и не является произвольным host shell. |
| PT-SEC-04 | OS keychain/1Password/биометрия/hardware keys проверяются отдельными реальными сценариями. До реализации реальные секреты не сохраняются в plaintext-заглушках. |
| PT-SEC-05 | Маскирование логов дополняет минимизацию доступа, не гарантирует zero exposure. Не сохраняются полный host env и credentials. |
| PT-NET-01 | Следующий сетевой кандидат реализует enforcement разрешённого egress/proxy и provider access; proxy environment без блокировки direct sockets недостаточен. |
| PT-NET-02 | Network policy определяет DNS, loopback, IPv4/IPv6, inbound, credential transport и отказ брокера; невозможность enforcement ведёт к отказу. |
| PT-NET-03 | Полная agent session требует отдельного теста provider/adapter, полномочий, остановки и результата. Успешная offline команда такого доказательства не создаёт. |

## 9. Совместимость и выпускная цель

Docker API/Compose/devcontainer/IDE остаются опциональными milestone полного продукта.
Поддержанный протокол публикует точные методы; неподдержанное возвращает явный отказ/501.
Наличие discovery API не объявляет полную Compose-совместимость.
Поддержка Docker-форматов не вводит Docker daemon как обязательный runtime Petri.

| ID | Требование |
| --- | --- |
| PT-REL-01 | Подписанные пакеты Petri, проверяемые Stack artifacts/SBOM и security review относятся к итоговой готовности; наличие draft или CI не означает их прохождение. |
| PT-REL-02 | Установка/удаление документированы для обычного пользователя; необходимые admin-managed OS prerequisites названы до запуска и не устанавливаются скрыто. |
| PT-REL-03 | Цели размера <250 МБ для runtime-поставки Petri и тёплого старта <2 с Linux/<4 с Windows/macOS сохраняются для измерения. Runtime/helper assets считаются вместе; toolchains, исходники и пользовательские данные измеряются отдельно, как и полный объём установки. Методика закрепляется до вывода PASS. |
| PT-REL-04 | Цели p95 <4 с и FS overhead <10% проверяются на объявленной нагрузке/host baseline; cold download/toolchain installation измеряются отдельно. |
| PT-REL-05 | Покрытие >80%, dependency/native audit, fuzz/chaos и три недели JS/Python/Rust dogfooding остаются целями полной готовности. Число тестов не заменяет измерение покрытия. |
| PT-REL-06 | Необнаруженная утечка в проверках не называется доказательством невозможности утечки. Готовность указывается по платформе, backend, workload и гарантии. |

## 10. Первый Windows-кандидат

**Назначение кандидата:** проверить собственный native Windows backend и контракты лаборатории
на одной закреплённой offline CLI нагрузке, сохранив Linux baseline.
**Предлагаемая первоначальная среда:** Windows 11 24H2 x64, стандартная учётная запись без elevation,
собственный подготовленный native Python 3.12 CLI fixture.
Точный servicing build/patch, hardware, filesystem, tool version, hashes, Petri build и policy
попадают в qualification manifest по факту подготовки; значения здесь не выдумываются.
Непригодная версия ОС фиксируется как Unsupported, не заменяется WSL/VM.

Кандидат включает только offline command, собственные fixtures/canaries и ограниченные negative probes.
Это контролируемая проверка фиксированной нагрузки, не допуск произвольных реальных агентов/проектов.
Не входят live cloud agent, provider credentials, Vault, GUI/IDE, Rust build, Node/Xcode,
полная Docker/Compose-совместимость и полная квалификация macOS.
Они остаются последующими milestone и не превращаются в блокеры этого кандидата.
PTY и полный provider trace не выдаются за реализованные по захвату stdout/stderr.

Aggregate process/committed-memory/wall-time и суммарный Job user-mode CPU-time входят в обещания Windows-кандидата. Job committed memory не выдаётся за RSS, а CPU rate не заменяет CPU-time.
Hard disk quota не обещается до проверяемого native enforcement: резерв свободного места,
лимит захваченного вывода и ограниченный snapshot/import обязательны; остаточный disk risk виден.
Такой кандидат не доказывает устойчивость хоста к произвольному заполнению workspace диска.
Полные жёсткие ресурсные профили продукта остаются отдельной незавершённой работой;
контролируемый offline PASS не разрешает произвольную нагрузку без требуемого disk containment.

## 11. Правила приёмки и доказательств

Каждый AC выполняется на точном manifest; Given/When/Then, oracle и evidence обязательны.
Oracle — доверенный host-check вне writable workspace; агент не может изменить ожидаемый результат.
Положительный control подтверждает, что probe способен выполнить проверяемое действие без запрета.
Negative probe не направляется на реальные секреты; используются собственные canaries.
Неизвестное, неподдержанное, skipped и неисполненное не считаются PASS.
Ошибочный запуск проверяется по отсутствию workload marker, а не только по exit code.
Сбой инфраструктуры отделяется от отказа защиты и требует нового пригодного прогона.
Evidence включает исходный fixture digest, manifest, точную команду, результат oracle и journal refs.
AC имеет статус PASS/FAIL/UNVERIFIED/NOT_APPLICABLE с причиной; обязательный AC не закрывается N/A.
AC-WIN-* относятся к Windows; AC-LINUX-W15 — к совместимости прежнего Linux backend.

### N01 — AC-WIN-N01: контракт и миграция

**Given:** metadata/config baseline v0.3 и новый draft с перечнем capabilities.
**When:** новая версия читает прежние записи и неподдержанный native policy request.
**Then:** прежние данные не переписываются молча; понятны совместимость/явная миграция/Unsupported.
**Oracle:** byte/digest-сравнение исходных записей и проверка закрытого результата валидатором.
**Evidence:** compatibility matrix, before/after digests, отказ неизвестного поля, журнал миграционного плана.

### W01 — AC-WIN-W01: probe пригодности

**Given:** стандартный пользователь, закреплённый host и запрошенная обязательная policy.
**When:** выполняется probe на пригодном host и negative prerequisite fixture.
**Then:** capability result объясняет возможности; невозможная защита отказывает до workload.
**Oracle:** host capability check и защищённый workload marker, отсутствующий в negative case.
**Evidence:** host/patch manifest, typed capability report, причина отказа, marker check.

### W02 — AC-WIN-W02: prepare

**Given:** свой committed repo, dirty/untracked canaries и закреплённый Python Stack.
**When:** создаётся лаборатория без запуска команды.
**Then:** workspace независим, source base закреплена, запрещённые/незакоммиченные данные не скопированы.
**Oracle:** сравнение Git tree и явно объявленной экспортной projection на хосте.
**Evidence:** source/baseline/Stack digests, исключения, lab ID, неизменность dirty source.

### W03 — AC-WIN-W03: offline execution

**Given:** подготовленная lab, явные argv/env/cwd и собственный Python CLI fixture.
**When:** выполняются успешная, ненулевая и setup-failure команды.
**Then:** коды/состояния различаются, workload marker появляется лишь после успешного setup.
**Oracle:** host reader сверяет ожидаемые fixture результаты, argv/env/cwd без раскрытия секретов.
**Evidence:** execution IDs, setup journal, exit/signal/result, stdout/stderr и marker digest.

### W04 — AC-WIN-W04: файловая граница

**Given:** RW workspace, RO tools/oracle; отдельные read/write canaries вне lab, в source, control-state и соседней lab; работоспособный положительный control.
**When:** fixture читает/пишет разрешённое и пытается отдельно читать запрещённые данные и изменять RO/outside, в том числе через aliases, созданные после старта.
**Then:** разрешённое работает; outside read и write предотвращены; непокрытая форма отклонена при импорте либо при runtime-действии без запрещённого эффекта. Preflight-обход не считается доказательством runtime containment.
**Oracle:** host-check результатов чтения и отказов, canary digests/ACL и защищённый эталон. Один неизменный digest не доказывает запрет чтения.
**Evidence:** отдельные read/write результаты, позднее создание alias, policy, digests и граница покрытого NTFS-подмножества.

### W05 — AC-WIN-W05: source и Git

**Given:** dirty source, независимая lab и позднее изменённая source base.
**When:** строятся diff/commit/review candidate и выполняется попытка публикации устаревшего результата.
**Then:** source HEAD/dirty files сохраняются, полный baseline diff виден, stale publication отказана.
**Oracle:** встроенный host Git reader сравнивает trees/refs/status; `git.exe` отсутствует в runtime PATH.
**Evidence:** before/after Git facts, diff digest, provenance, stale refusal и отсутствие hook side effects.

### W06 — AC-WIN-W06: network none

**Given:** lab без network и контролируемые host/LAN/IPv4/IPv6 endpoints с положительным control.
**When:** native fixture пробует DNS, direct TCP/UDP, loopback и заявленные transport families.
**Then:** запрещённые соединения не достигают endpoints. Для обязательных IPv4/IPv6, loopback и LAN направлений положительный control должен достичь endpoint; отсутствие family/endpoint даёт UNVERIFIED либо непригодную среду, не PASS.
**Oracle:** доверенные endpoint counters/packet observation и результаты control вне lab.
**Evidence:** topology, capability scope, endpoint logs, probe results, installed policy и отказ unsupported.

### W07 — AC-WIN-W07: дерево процессов и остановка

**Given:** fixture создаёт child/grandchild с readiness marker и попыткой отделиться.
**When:** пользователь вызывает stop; отдельно истекает timeout и аварийно завершается supervisor.
**Then:** stop/timeout подтверждённо прекращают принадлежащие процессы; неизвестный исход честно блокирует cleanup/relaunch и не закрывает гарантию остановки как PASS.
**Oracle:** native host ownership/process observation после срока, а не только завершение direct child.
**Evidence:** membership facts, stop reason/times, readiness controls и подтверждённое освобождение ресурсов.

Отдельный собственный host IPC/service canary проверяет отказ запроса на запуск вне sandbox identity/Job. Обычная проверка child breakaway не заменяет проверку внешнего process broker; реальные системные задания, службы и чужие процессы для опыта не создаются.

### W08 — AC-WIN-W08: суммарные бюджеты

**Given:** ограниченные process/RAM/CPU-time/wall-time budgets и достаточный диск.
**When:** своё разветвлённое fixture дерево пытается превысить каждый бюджет; отдельно не хватает disk reserve.
**Then:** memory/process hard limits не допускают запрещённое превышение; CPU/wallclock исчерпание и наблюдённое нарушение включают stop с подтверждением дерева. Неподдержанное требование/недостаток резерва отказывает; kernel enforcement не подменяется ненадёжным уведомлением.
**Oracle:** независимые native counters всего дерева и host disk check с объявленными допусками.
**Evidence:** scope/units, thresholds/observed peaks, stop latency, disk reservation; hard quota не выдумана.

### W09 — AC-WIN-W09: журнал и вывод

**Given:** вывод обоих streams, output budget и механизм собственного fault injection журнала.
**When:** вывод переполняется или запись обязательного audit намеренно становится недоступна.
**Then:** execution останавливается; отказ/потеря вывода видимы, лаба не может переписать host audit.
**Oracle:** host journal verifier и process ownership check; итог не зависит от текста stdout.
**Evidence:** operation/execution IDs, sequence/digests, output counts, fault marker и причина остановки в доступном ответе/внешнем test harness; невозможный append журнала не выдумывается.

### W10 — AC-WIN-W10: stopped checkpoints

**Given:** остановленная lab с двумя версиями файлов/Git; отдельно работающая lab.
**When:** checkpoint/restore выполняются штатно и с обрывом контролируемого этапа.
**Then:** восстанавливается согласованный snapshot; audit не откатывается; active snapshot отказан.
**Oracle:** trusted snapshot manifest, workspace/Git digests и непрерывность управляющего журнала.
**Evidence:** checkpoint ID, staged/recovered states, before/after hashes и active-operation refusal.

### W11 — AC-WIN-W11: restart и неизвестный исход

**Given:** остановка Petri на границах prepare/start/result, включая неизвестный исход команды.
**When:** Petri запускается вновь и выполняется явный inspect/reconcile.
**Then:** неизвестная команда не повторяется; обнаружены принадлежащие ресурсы и разрешён ограниченный recovery.
**Oracle:** monotonic execution counters/markers и host ownership check, независимые от PID-файла.
**Evidence:** fault points, durable intents/results, повтор ключа, conflict и решение reconcile.

### W12 — AC-WIN-W12: поставка обычному пользователю

**Given:** чистая стандартная учётная запись на квалифицированной ОС и подготовленный Python fixture.
**When:** Petri устанавливается и выполняет W02/W03 без Docker/Git.exe/MXC/WSL/VM.
**Then:** нет скрытого elevation/host-policy repair; недостающая предпосылка объяснена до исполнения.
**Oracle:** независимый inventory зависимостей/процессов и контроль учётной записи/предпосылок.
**Evidence:** package digest, install/uninstall log, dependency inventory и отсутствие fallback launch.

### W13 — AC-WIN-W13: повтор и параллельность

**Given:** две lab с разными canaries и одноимёнными файлами; повтор ключей управляющих операций.
**When:** выполняются параллельные команды, конфликтующие операции одной lab и повтор прежнего запроса.
**Then:** lab не читают/меняют друг друга; ключ не дублирует действие; busy/conflict различимы.
**Oracle:** host resource ownership, execution counts и before/after digests обеих лабораторий.
**Evidence:** interleaving schedule, IDs, lock/conflict outcomes и отсутствие чужих изменений.

### W14 — AC-WIN-W14: реальный native toolchain

**Given:** закреплённый native Python 3.12 и собственная CLI задача с защищённым oracle.
**When:** выполняется разрешённая файловая задача; отдельно подменяется tool digest/запрашивается запрещённый доступ.
**Then:** native задача даёт ожидаемый артефакт, подмена/запрет выявлены; никакой Linux guest не запускается.
**Oracle:** host binary identity/architecture check и проверка результата отдельным неизменным эталоном.
**Evidence:** tool/fixture hashes, runtime manifest, positive artifact и отрицательные результаты.

### W15 — AC-LINUX-W15: Linux compatibility regression

**Given:** закреплённый Linux baseline70e0bc6 и пригодный настоящий isolation runner.
**When:** новый кандидат проходит прежние Git/lifecycle/stack/output и реальные Linux isolation сценарии.
**Then:** baseline semantics сохранены либо отклонение явно принято; прежние gaps не объявлены закрытыми.
**Oracle:** старые ожидаемые результаты и независимые host checks; host lifecycle tests не заменяют isolation E2E.
**Evidence:** baseline/candidate SHAs, host capabilities, executed counts, PASS/FAIL/UNVERIFIED и diff отклонений.

## 12. Последующие рубежи и условие готовности

После Windows offline-кандидата отдельно назначаются: network/provider agent session; PTY;
Vault/signing/bearer broker; расширенные Python/Node/Rust workloads; native macOS backend;
Linux aggregate budgets; hard disk quotas; registry/builder/signatures/SBOM; Docker/IDE adapters.
Порядок уточняется владельцем; список не является автоматическим поручением исполнителю.

Полная готовность требует применимых требований и evidence на трёх ОС, согласованных ограничений,
security review, измерений и пользовательской приёмки. Частичный PASS не меняет цель задним числом.
Для начала кода необходим принятый ограниченный контракт, назначение и точная область изменений.
Исходные источники и исторические FAIL/UNVERIFIED сохраняются; новая редакция их не переписывает.
