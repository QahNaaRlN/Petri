# Windows native кандидат

Дата: 2026-10-27. Рабочая ветка: `feat/windows-native-candidate`, база: `70e0bc69c1a5be0761f073e69b6efae9a751b22d`.

Этот пакет реализует собственный Windows backend рядом с подготовленным Linux-кандидатом. Windows исполняет Windows-процессы, Linux — Linux-процессы. MXC, Docker, WSL и VM не требуются и не используются как fallback.

Полная цель и контракты находятся в [ТЗ](requirements.md) и [ТС](technical-specification.md). Здесь описывается реализуемый первый пакет; квалификация на Windows учитывается отдельно от компиляции.

## Профиль

Первый профиль — офлайн CPython 3.12 x64, стандартная библиотека, явный script из независимого workspace. Нет GUI, ConPTY, удалённой модели, произвольного host shell, сетевого allowlist или выдачи секретов. Нативные инструменты импортируются отдельно от Linux rootfs/OCI.

LPAC ограничивает права доступа, Job Objects владеет деревом процессов и применяет групповые лимиты. Guardian создаёт процесс suspended, устанавливает обязательные ограничения и пишет ready-событие перед resume. Контроллер не передаёт workload ключи, свой environment, дескриптор Job или управляющие файлы. Остановка подтверждается через счётчик активных процессов Job.

Потеря контроллера закрывает приватный stdin-канал guardian и требует остановки workload. Потеря guardian закрывает последний Job handle (`KILL_ON_JOB_CLOSE`); при отсутствии живого наблюдателя это свойство ОС не заменяет сохранённое свидетельство `ActiveProcesses == 0`. Неизвестный исход блокирует повторный запуск.

## Состояние проверки

В этой Linux-среде можно проверить переносимую логику и собрать Windows-бинарник. Запуск LPAC, права ACL, изоляцию IPC/сети и остановку Job требуется проверить на Windows 11 24H2 x64 под обычным пользователем. До публикации соответствующего отчёта этот кандидат **не квалифицирован для запуска произвольных агентов**.

Дисковая защита остаётся ограничением: программное наблюдение объёма не является hard quota. LPAC использует общее ядро Windows; внешняя служба или ошибочно предоставленная capability может изменить границу безопасности. Интеграции с host-сервисами в первом профиле не разрешаются.


## Подготовка и команды

Используйте обычную учётную запись Windows 11 24H2 x64 (build 26100), не elevated и не split-token администратора. Нужен локальный NTFS и минимум 2 GiB свободного места. `doctor` проверяет предпосылки версии/аккаунта; фактический LPAC token, capability set, Job membership и лимиты проверяются перед resume.

Подготовьте доверенный portable CPython **3.12 с точным patch version**, x64, без site-packages. Manifest находится вне его каталога и перечисляет **все** файлы: относительный путь, размер и SHA-256; также содержит `format_version: 1`, `id`, `platform: windows`, `architecture: x86_64`, `python_version`, `entrypoint: python.exe`, `source`, `package_sha256`, `license`, `files`. Обязательны `python312.dll`, stdlib zip/encodings и файл лицензии; активные import-строки `_pth` отклоняются. Полная схема — `ToolchainManifest` в [native_tools.rs](../src/native_tools.rs).

Petri не запускает файлы при импорте и не исправляет права исходного Python installation. Он копирует проверенные байты в собственное хранилище. Проверка SHA-256 подтверждает выбранные байты; доверие издателю и происхождение archive проверяются независимо. Из импорта каталога нельзя вывести подлинность заявленного `package_sha256`.

Пример PowerShell; `smoke.py` должен быть tracked-файлом выбранного committed HEAD:

```powershell
$petri = '.\target\release\petri.exe'
$state = Join-Path $env:LOCALAPPDATA 'PetriNativeCandidate'
& $petri --home $state windows doctor --json
$tool = (& $petri --home $state windows tool import 'C:\VerifiedTools\Python312' --manifest 'C:\VerifiedTools\python312-manifest.json') | ConvertFrom-Json
$lab = (& $petri --home $state windows create --repo 'C:\Projects\OwnedFixture' --tool $tool.result.id) | ConvertFrom-Json
& $petri --home $state windows run $lab.result.lab_id --script smoke.py -- 'argument with spaces'
& $petri --home $state windows diff $lab.result.lab_id
& $petri --home $state windows checkpoint $lab.result.lab_id 'after smoke'
```

Команды возвращают один JSON envelope `petri.control/v1`; stdout/stderr workload хранятся отдельными файлами и не смешиваются с JSON. Для каждого запуска выдаётся `execution_id`; `status`, `stop` и `result` принимают `--execution`. `run --operation-id op-<32 lowercase hex>` повторяет ту же управляющую операцию без нового физического запуска; другое содержимое с тем же ID даёт конфликт. Изменение workspace не превращает прежний operation ID в новую задачу — используйте новый ID.

`--detach` явно Unsupported: первое исполнение удерживает foreground controller lease. После crash неизвестная execution блокирует новые запуски. Не выдавайте ручное редактирование state.json за recovery. Автоматический discard/удаление профиля в CLI пока отсутствует; cleanup остаётся Pending даже после доказанной остановки Job.

`checkpoint`/`restore` захватывают файлы и отдельный Git, сохраняют audit и environment; они не восстанавливают память процесса и не отменяют историю execution. При обнаружении `restore-intent.json` штатные операции отказывают с RecoveryRequired. Это обнаружение незавершённой транзакции, а не автоматический crash recovery.

Бюджеты по умолчанию: 8 процессов, 512 MiB суммарной committed memory Job, 10 секунд суммарного **user CPU time**, 30 секунд wall time, 3 секунды ожидания stop, 8 MiB stdout+stderr, 16 MiB управляющего журнала с резервом 128 KiB для stop/terminal. Soft scan проверяет 256 MiB writable filesystem данных, но не является hard quota и может остановить нагрузку консервативно при неподдержанном alias/sharing состоянии.

## Реальная квалификация

В отдельном обычном Windows аккаунте, с подготовленным portable Python и независимо закреплённым manifest:

```powershell
$env:PETRI_WINDOWS_NATIVE_E2E = '1'
$env:PETRI_WINDOWS_PYTHON_HOME = 'C:\VerifiedTools\Python312'
$env:PETRI_WINDOWS_TOOLCHAIN_MANIFEST = 'C:\VerifiedTools\python312-manifest.json'
cargo test --locked --test windows_native -- --ignored --nocapture --exact windows::owned_offline_native_qualification
```

Suite использует только собственные canary-файлы и endpoints, проверяет положительные контроли отдельно от запретов, сохраняет артефакты при отказе. До реального запуска результат здесь **UNVERIFIED**. Полная ТС остаётся UNVERIFIED и при успехе ограниченной suite: IPC/service escape, полный fault injection, late aliases, packaging и прочие незакрытые AC проверяются отдельно.


## Выполнено в этой сессии — 2026-10-27

| Проверка | Результат |
| --- | --- |
| `cargo test --locked --all-targets --all-features` на Linux | 61 unit + 6 lifecycle + 2 Windows refusal = **69 passed**; один Linux native E2E явно ignored в обычном прогоне |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --locked --all-targets --all-features -- -D warnings` | PASS на Linux |
| Тот же clippy для `x86_64-pc-windows-gnu` | PASS; Windows-only code/tests скомпилированы, не исполнены |
| `cargo build --locked --release` | PASS, Linux x86_64 |
| `cargo build --locked --release --target x86_64-pc-windows-gnu` | PASS, Windows x64 GNU; PE import table содержит системные DLL, без внешнего Docker/Git/MXC |
| Python governance tests | **55 passed** |
| Синтаксис qualification harness/fixture | PASS; ресурсные/аварийные workload modes на хосте не запускались |
| `docs/sources/SHA256SUMS` | 8/8 оригинальных документов совпали |
| Локальные Markdown-ссылки и `git diff --check` | PASS |
| Отдельный настоящий Linux E2E с static BusyBox | **НЕ ПРОЙДЕН в этой среде**: SandboxUnavailable, Read-only file system (os error 30). Doctor также сообщает Landlock ENOSYS, supported=false. Host policy не изменялась, fallback не включался |
| Настоящий Windows native suite (14 назначенных сценариев) | **UNVERIFIED: Windows-хост отсутствует**, профиль не квалифицирован |

Свежий внешний security audit, покрытие, perf и нативная совместимость всех инструментов этими командами не подтверждаются. Для Windows требуется следующий реальный прогон на подготовленном аккаунте; инструкция выше и manual workflow уже добавлены.
