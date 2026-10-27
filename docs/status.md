# Статус реализации и проверки

Дата: 2026-10-27. Общая линия объединяет Linux-кандидат, экспериментальный Windows native backend и подготовку macOS. Исходные SHA и маршрут `dev` → `main` описаны в [записи интеграции](branch-integration.md). Версия CLI — 0.3.0; `0.4-draft1` — редакция [ТЗ](requirements.md) и [ТС](technical-specification.md).

Windows-кандидат реализован для контролируемой офлайн-нагрузки. Он **не прошёл нативную квалификацию Windows** в текущей Linux-среде. Наличие исходников, Windows-бинарника или успешного portable CI не является доказательством изоляции.

## Реализованный пакет

| Компонент | Реализация | Граница |
| --- | --- | --- |
| Linux | Существующие namespaces/pivot_root/Landlock/seccomp и legacy CLI сохранены | Per-process rlimits прежние, cgroup aggregate budgets не добавлены |
| Windows native | Собственные публичные Win32 bindings: LPAC с уникальным AppContainer SID лабы, процесс suspended, проверка токена/Job перед resume | Windows 11 24H2 x64 client, обычный пользователь; фактическая совместимость CPython и ACL требует запуска qualification suite |
| Job | Kill-on-last-handle-close, без breakaway; групповые committed memory, process count, user CPU time; wall/output limits guardian | Hard-limit enforcement и реакция supervisor различаются; CPU — user time, не CPU bandwidth/RSS |
| Права и пути | Owner-only control ACL, RW workspace/temp/private profile, RX copied tools, Low integrity writable objects; отказ на reparse/hardlink/ADS/опасных именах | Первый профиль ограничивает имена файлов ASCII; не меняет ACL системных/сторонних инструментов и исходника |
| Нативное хранилище | `native-v2/laboratories` отдельно от legacy `labs`; отдельные Lab/Execution/Operation IDs, целая атомарно заменяемая запись состояния | Автомиграция старых labs не реализована; старые записи не переписываются |
| Управление | Идемпотентный start/stop, Ready перед resume, Running после resume, полный DWORD, остановка по потере stdin lease | Неизвестный исход блокирует повторный запуск; нет автоматического доказательства остановки после crash без живого guardian |
| Tools | Offline manifest, полный file inventory/SHA-256, PE x64, изолированный CPython 3.12 layout, staging и content identity | Импорт каталога не проверяет отсутствующий архив или подпись издателя; package SHA в manifest — заявленное происхождение |
| Git | Встроенный libgit2, committed HEAD export, независимые metadata, безопасные diff/commit | Нет системного Git, Git passthrough, push/Vault; `.git` workload не определяет host repository |
| Checkpoint/restore | Остановленные workspace+Git, digest, private copies, durable restore intent, rollback обычных ошибок, журнал не откатывается | Нет process state; crash между несколькими rename оставляет RecoveryRequired; прежние деревья сохраняются закрытыми для workload |
| Наблюдения | Host JSONL, ограниченные pipe stdout/stderr, result manifest с provenance/digests и явными gaps | Нет ConPTY/input/GUI, полного syscall/network/FS аудита, скрытого reasoning агента или цифровой подписи |
| Диск | Проверка свободного места и ограниченное программное наблюдение writable областей | Нет hard disk quota; overshoot и resource DoS полностью не исключены |

Нативный AppContainer имеет созданные ОС private filesystem/registry области помимо явно переданных путей. Backend сообщает filesystem profile path, учитывает его при soft disk scan; изменение `HOME` само по себе не является файловым барьером. Registry storage не считается полноценной дисковой квотой. Очистка профиля — отдельная операция после подтверждённой остановки.

## Проверки этой ветки

Фактический итог команд записывается в [руководстве кандидата](windows-native-candidate.md). Выполняются Rust tests/clippy/format, Linux release build, cross-build Windows x64 GNU, Python governance tests, синтаксис qualification harness и сохранность оригинальных документов.

Windows native qualification запускается отдельно через [manual workflow](../.github/workflows/windows-native.yml) на подготовленном Windows 11 24H2 runner. Неподдержанная ОС/учётная запись/отсутствующие инструменты дают UNVERIFIED/ненулевой код. Успех назначенной ограниченной suite не закрывает всю ТС.

Linux E2E требует доступных rootless namespaces и Landlock ABI >=3. Историческое подтверждение базового Linux E2E относится к [CI run старого кандидата](https://github.com/QahNaaRlN/Petri/actions/runs/40242644431), а не к этой ветке. Новый результат CI не предполагается по наличию workflow.

## Что не закрыто

- Нативная Windows-квалификация, adversarial IPC/service/late-alias проверки, fault injection журналов и развёртывание на реальном обычном аккаунте.
- Полный controller transport из ТС: универсальная типизированная входная схема, expected revision и идемпотентность всех mutating операций. Текущий `petri windows` — ограниченная CLI-поверхность; start/stop имеют operation IDs.
- Реальное подключение Meridian/агентского адаптера, политика сетевого доступа/provider broker, Git broker и Vault.
- Автоматическое recovery с наблюдением сохранившегося Job; crash restore требует явного разбора оставленного intent. Cleanup state не приравнивается к наличию нулевого process count.
- Полноценный нативный macOS backend, дополнительные Windows стеки и GUI/ConPTY.
- Linux cgroups, hard disk quota, подписанные установщики, registry/builder/SBOM, внешний аудит и обновления.
- Полная Docker API/Compose совместимость, release coverage/perf/dogfooding.

Это остаток продукта из ТЗ, а не скрытая функциональность, включаемая флагом ослабления sandbox.


## Подготовка macOS — 2026-10-27

Общая линия содержит [пакет подготовки](macos-native-candidate.md): отдельные ТЗ/ТС, оценку публичных API Apple, MP-00…09 plan, 15 групп критериев приёмки, минимальные feasibility entitlements и read-only preflight. Он не исполняет helper, не подписывает/устанавливает код и не меняет TCC/SIP. Mac backend остаётся NOT IMPLEMENTED/UNVERIFIED.

Первый исследуемый профиль — macOS 26 arm64, обычный non-admin account, native CPython 3.12 offline fixture. Точный build/patch и signing identities определяются на реальном Mac. Перенос Job/LPAC, per-lab App Sandbox containers, исполнение imported tools, контроль detached descendants и aggregate budgets не предполагаются существующими: это блокирующие исследования. Полный путь к runtime указан в плане, без скрытого fallback к SBPL, Endpoint Security или VM.

Read-only preflight и его portable contract tests подтверждают только честный inventory/refusal/JSON, а не native isolation. Ранее перечисленные Windows проверки относятся к исходному кандидату; новые результаты подготовки записаны на входной странице macOS.
