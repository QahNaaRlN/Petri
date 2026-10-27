# Инженерный security review v0.3

Дата: 2026-10-25 UTC. Это внутренний review реализации и модели угроз, выполненный в ходе разработки. Он **не является независимым профессиональным аудитом**, сертификацией или доказательством отсутствия уязвимостей. Для релиза по-прежнему требуется отдельный review и настоящий E2E на поддерживаемых хостах.

## Проверенная область

Рассмотрены границы Git/workspace/host blackbox, Linux namespace/mount/seccomp/Landlock setup, inherited file descriptors, идентичность родителей/потомков, политика YAML, сеть, safe archive import, CLI переходы состояния и отличия текущего среза от исходных гарантий. Ключевые проектные решения описаны в [ADR-001…022](decisions.md).

## Найденные проблемы и изменения

| Находка | Риск | Внесённое усиление / проверка |
| --- | --- | --- |
| Унаследованные host FDs и доступ через `/proc/1/fd` | Утечка доступа к файлам/сокетам вне нового rootfs | Обязательный `close_range` перед namespace init и перед exec; управляющий setup pipe отделён от stdin/out/err. Неподдержанный syscall даёт отказ, а не продолжение с лишними FDs. |
| Окно между fork и установкой PDEATHSIG, включая PID namespace | Оставшиеся процессы после гибели родителя | Ожидаемый parent PID фиксируется до fork; pidfd/poll используется для проверки жизни init/worker и закрытия гонки регистрации. Supervisor→sandbox также требует parent-death signal. |
| `AF_VSOCK` не изолируется обычным network namespace | Обход предположения «network namespace запрещает любой канал к хосту» | Seccomp допускает socket domains только UNIX/INET/INET6; socketpair — UNIX; VSOCK/PACKET/NETLINK запрещены. Добавлен тест вычисления BPF-профиля. |
| Сложная логика после fork в многопоточной диагностике | Риск deadlock аллокатора/библиотек | Namespace probe использует raw-syscall-only путь дочернего процесса, не произвольную Rust-логику с аллокациями. |
| Custom `deny_paths` принимаются без enforcement во всех snapshots | Ложная гарантия пользовательского правила | Нестандартный список отклоняется до сквозной реализации; обязательные default exclusions остаются. |
| Mutable host-side стек после импорта | Digest в metadata может перестать соответствовать исполняемому rootfs | Read-only seal не считается защитой от хостового UID. Нужны повторная проверка digest и проверка границы mount при запуске; факт проверки должен подтверждаться актуальным кодом/тестом. |
| Отдельный background supervisor и lock handoff | Конкурирующие start/run/restore либо ложное Running | Блокировки должны удерживаться при переходе к supervisor; при занятой лабе операция завершается LabBusy. Проверка lifecycle не заменяет stress/crash-тест всех гонок. |
| Writable blackbox внутри лабы | Агент мог бы изменять историю и результат аудита | Host blackbox не монтируется внутрь; `/logs` — пустой read-only каталог rootfs. |

Синтетический тест seccomp проверяет ветвление программы BPF на разрешённых/запрещённых значениях. Он не доказывает реальную установку фильтра ядром, корректность всех workload syscalls или отсутствие kernel уязвимостей.

## Остаточные ограничения

- Ядро хоста разделяется с sandbox; kernel exploit выходит за заявленную гарантию. Нужен актуальный поддерживаемый kernel.
- Unix mode 0700/0600 не разделяет недоверенные процессы на хосте под тем же UID. Хостовый пользователь и его процессы находятся вне текущей модели защиты.
- RLIMIT_AS/CPU/NPROC не ограничивают суммарные память/CPU/PIDs всего namespace как cgroup v2. Нет полных disk/log quotas; resource DoS остаётся существенным открытым вопросом.
- Импортированный стек является executable input. SHA-256 не подтверждает издателя; поддержанный OCI subset ограничен, подписи/SBOM/registry trust не реализованы.
- Нет Vault, реального scrub pipeline, provider revoke и биометрии. Не следует помещать секреты в исходный код, stack или command arguments с ожиданием автоматической защиты Petri.
- Pipe capture не является PTY и не создаёт полного следа всех file/process/network действий. Вывод недоверенной программы может содержать terminal escape sequences.
- Checkpoint/restore имеет rollback обычных ошибок, но ещё не полноценный crash-recovery journal. Supervisor state после аварии может требовать ручной диагностики.
- Конкурентное изменение хостового source/store тем же UID, TOCTOU и пределы количества файлов требуют дальнейшего hardening и stress/fuzz tests.
- macOS/Windows VM isolation не реализована; переносимая сборка не расширяет Linux-гарантии на эти ОС.

## Что считается доказательством

Review привёл к коду и unit-тестам перечисленных защит, но успешного native E2E в текущей ограниченной среде не получено: Landlock/userns могут быть запрещены host policy. Это остаётся открытым gate, даже когда `cargo test` зелёный. [Тестовая инструкция](testing.md) описывает opt-in проверку на пригодном Linux runner, а [status.md](status.md) фиксирует фактические результаты интеграции.

До включения новых backend/сетевых/секретных возможностей каждый срез должен обновить threat model, этот журнал и тесты реального enforcing механизма. Наличие параметра конфигурации или успешный mock недостаточны.

## Финальная проверка зависимостей

RustSec выявил informational unsound RUSTSEC-2026-0183/0184 в git2 0.20 и unmaintained RUSTSEC-2024-0449 в unsafe-libyaml. Зависимости обновлены: git2 0.21, serde-saphyr 2 (deserialize-only; include/properties отключены). Повторный cargo audit: 0 vulnerabilities, 0 warnings; исключения advisory не добавлялись.

## Уточнение после проверки в CI

На `251cd325aa53a3b983cc89930ae55df64d7d5f22` реальный Linux E2E прошёл на GitHub Ubuntu runner (1 passed, 0 ignored); это подтверждает проверенный сценарий, не отсутствие всех путей побега. В последующем усилении init получает `PR_SET_DUMPABLE=0` до fork payload; E2E дополнен отрицательной проверкой открытия `/proc/1/mem`. Проверки новых коммитов видны в PR №1.


## Внутреннее ревью Windows-кандидата — 2026-10-27

Проверены контракты и исходники нового пакета; это не внешний аудит и не подтверждение нативных эффектов на Windows. В ходе реализации исправлены: доверие к workspace `.git`, Windows ADS/reparse/hardlink и case aliases, точная проверка LPAC SID/capability set, fresh environment, уничтожение suspended root при setup error, сброс прав прежнего workspace после restore, общий бюджет журнала с terminal reserve, лимиты обхода пустых каталогов, независимый watchdog при блокировке observer, staging-публикация result manifest и гонка ACL общего toolchain между лабами.

Квалификация LPAC/IPC/network/Job crash на Windows здесь не выполнялась. Программный disk observer не даёт hard quota; системные private AppContainer filesystem/registry области входят в модель и требуют квалификации. Неизвестный исход блокирует новые исполнения; автоматическое восстановление отсутствующего guardian и cleanup остаются отдельными работами. Подробные границы и выполненные проверки перечислены в [статусе](status.md) и [руководстве](windows-native-candidate.md).
