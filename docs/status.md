# Матрица реализации и приёмки

Редакция 0.3, 2026-10-25 UTC. Полный продукт из исходных документов **не завершён**. Здесь отдельно указаны реализованный код, функциональные ограничения и требования, которым ещё нет подтверждения. Компиляция и unit-тест не заменяют настоящий E2E изоляции.

## Срез реализации

| Компонент | Реализованный код | Граница |
| --- | --- | --- |
| CLI и lab store | Create/prepare/run, foreground/background supervisor, list, private state, блокировки, metadata | Автовосстановление состояния после произвольного crash требует доработки; записанный PID не является безопасной stop-ручкой |
| Git | Встроенный libgit2, независимые метаданные, export HEAD, diff, commit, локальная review-ветка | Нет системного Git в runtime; нет Git RPC/agent shim, network push и PR API; merge не двигает main |
| Linux runtime | Native libc namespaces, pivot_root, rootfs RO, workspace/tmp/dev, Landlock ABI>=3, seccomp, no_new_privs, cap-drop, explicit env | Реальная доступность зависит от host policy; никаких fallback; E2E подтверждается отдельно |
| Ресурсы | RLIMIT_AS, RLIMIT_CPU, RLIMIT_NPROC | Нет cgroup aggregate CPU/RAM/PIDs; защита от любого resource exhaustion не обещается |
| Сеть | Отдельный network namespace без внешнего интерфейса | Allowlist/eBPF/slirp/pasta отсутствуют, непустой network отклоняется |
| Конфигурация | Строгий YAML, известные поля, лимит размера, безопасные defaults | Custom deny_paths отклоняются до сквозного enforcement; baseline secret exclusions обязательны |
| Стеки | Offline rootfs/OCI import, SHA-256/size/diff_ids, безопасная распаковка, content-addressed rootfs | Только поднабор OCI; whiteout/hardlink/device/sparse entries не поддержаны; нет registry pull/build/cosign/SBOM |
| Снимки | Workspace+Git copy, stopped-only checkpoint/restore, staging и rollback обычных ошибок | Не process checkpoint; нет полного crash-recovery journal; не overlay-only snapshot |
| Blackbox | Host-only управляющие JSONL events, pipe output cast, timed replay | Нет PTY/input/resize, точного interleaving stdout/stderr, fanotify/eBPF/agent trajectory/token accounting |
| Docker discovery | Unix socket, ping/version/info/list/inspect, явные 501 | Нет create/start/stop/remove/images/networks/volumes/exec/build/log streams; Compose не поддерживается |
| Vault | Явный статус недоступности и Unsupported команды | Нет хранилища реальных секретов, broker authentication, signing, bearer issuance/revocation, биометрии |
| macOS/Windows | Переносимые host-side части и заготовка интерфейса отказа | Нет VM/WSL runtime, настоящего cross-platform E2E и пакетов |

## Покрытие исходных AC

| Исходный критерий | Статус | Что ещё требуется для полного AC |
| --- | --- | --- |
| AC-1 Жизненный цикл | Частично | Реальный запуск на подходящем kernel runner и измеренная скорость; stock host без готового стека требует отдельного bootstrap |
| AC-2 Git-иммутабельность | Частично | Локальные операции и защита исходного refs реализованы; полноценный авторизованный агентский Git broker/push отсутствует |
| AC-3 Изоляция | Код есть, kernel E2E — отдельный gate | Реальные тесты host path/network/escape на поддерживаемой конфигурации; полноценный аудит network_blocked отсутствует |
| AC-4 Vault | Не реализован | Keychain/1Password, signing protocol, authorization, revoke, audit, real TouchID/Hello |
| AC-5 StackHub | Частично | Локальный OCI/rootfs и reuse есть; registry node22 catalog, подписи, SBOM, reproducible build и OCI совместимость шире поднабора отсутствуют |
| AC-6 Наблюдаемость | Частично | Host events и захват вывода есть; полноценный PTY replay, FS/process/network event collection и upper-layer diff не реализованы |
| AC-7 Docker | Только read-only discovery | Полный заявленный Docker API, запуск workloads, Compose E2E и import Docker volumes/images |
| AC-8 Три ОС | Не выполнен | Backend macOS VM и Windows WSL2, подходящие runners, реальный AC-1…AC-4 на каждой ОС |

## Проверки текущего изменения

Проверено локально на Linux x86_64, Rust 1.99.1:

| Проверка | Фактический результат |
| --- | --- |
| `cargo test --all-targets --all-features --locked` | 37 unit + 6 integration = **43 passed**, 0 failed; 1 native E2E явно ignored |
| `cargo fmt --all --check` | Успешно |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | Успешно, без предупреждений |
| `cargo build --release --locked` | Успешно; Linux ELF **4,071,880 bytes** (3.88 MiB) |
| `cargo audit --json --no-fetch --file Cargo.lock` | **0 vulnerabilities, 0 warnings**, после обновления git2 и YAML-парсера; база RustSec загружена в этом сеансе |
| Хеши оригиналов | 8/8 совпадают с SHA256SUMS |
| Локальные Markdown-ссылки | Все разрешаются |
| `petri doctor` вне ограничений tool sandbox | namespace probe available; Landlock ABI -1, `Function not implemented (os error 38)`; **supported=false** |

Native E2E не объявлен пройденным: хост не предоставляет Landlock. Успешно проверен отдельный отрицательный integration test: при недоступной изоляции/неполном стеке команда не исполняется на хосте, маркер не создаётся, статус становится Failed и записывается аудит. Linux E2E вынесен в отдельную CI job с реальным static BusyBox; результат GitHub CI на момент этой записи ещё не получен. Компиляция/выполнение на macOS и Windows локально не проверялись. Coverage и perf не измерены.
Внешний контейнер/ограниченный executor может запрещать Unix socket либо user namespaces. Разрешение tool sandbox на локальный socket не равняется выдаче capabilities внутри лабы. Неуспешный syscall probe должен остаться диагностическим отказом, а не поводом ослабить профиль.

## Открытые релизные гейты

- Настоящий Linux E2E изоляции на документированной конфигурации, включая процессы-потомки, сигналы и filesystem escape fixtures.
- Групповые cgroup limits, circuit breaker и проверенный механизм ограниченной сети.
- Типизированный Git broker/adapter агента и безопасный authenticated Vault.
- VM/WSL2 backends; реальные macOS/Windows runners и ручная биометрия.
- Полный целевой OCI/registry/builder/signature/SBOM pipeline.
- Заявленное покрытие Docker API, migration и devcontainer integration.
- Покрытие >80% по отчёту, актуальный dependency audit и fuzz/chaos campaigns.
- Измеренные cold/warm startup p95, FS overhead, binary/package sizes по методике.
- Подписанные release packages, независимый security review, план обновления/отката.
- Три недели dogfooding на трёх реальных JS/Python/Rust проектах и проверка журналов на утечки.

Эти пункты не скрываются за 501 или документацией: явная ошибка — корректное поведение отсутствующей возможности, но не выполнение исходного функционального требования.
