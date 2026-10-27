# Petri

CLI на Rust для лабораторий кодовых агентов. Текущий срез — **0.3.0, экспериментальная реализация**. Это не завершённый релиз 1.0: [матрица требований и остаток работ](docs/status.md) отделяет реализованное от неподдерживаемого и непроверенного.

Petri сохраняет независимый Git-снимок исходного HEAD и журнал на хосте. Подготовленный Linux-кандидат запускает программу внутри namespaces; новый Windows-кандидат использует нативные LPAC и Job Objects. Ошибка настройки изоляции прекращает запуск. Исходный репозиторий не монтируется; публикация результата создаёт отдельную review-ветку только после `--yes`.

- [ТЗ нативных лабораторий v0.4-draft1](docs/requirements.md)
- [ТС нативного ядра v0.4-draft1](docs/technical-specification.md)
- [Инженерные решения и границы безопасности](docs/decisions.md)
- [Исходные документы v0.1/v0.2](docs/sources/README.md)
- [Проверки и ограничения](docs/status.md)
- [Ветки, защита и клонирование на Windows](docs/repository-governance.md)
- [Внутреннее ревью безопасности](docs/security-review.md)

## Сборка

Нужны Rust **1.99.1**, C toolchain и zlib development headers для встроенного libgit2. Системный Git и Docker для работы CLI не требуются. Зависимости зафиксированы в Cargo.lock.

```sh
cargo build --release --locked
cargo test --locked --all-targets
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo audit
```

На Linux `petri doctor` проверяет поддержку namespaces и Landlock ABI ≥3 (Linux ≥6.2, разрешённый хостом). Полный запуск дополнительно проверяет mount_setattr, pidfd, close_range, seccomp и содержимое стека. UID хоста должен быть непривилегированным. `doctor` не сертифицирует безопасность стека. Нативный Windows-кандидат вынесен в `petri windows` (см. [руководство](docs/windows-native-candidate.md)); он использует LPAC и Job Objects. На macOS нативный запуск пока явно не реализован. Поддержка Linux rootfs на Windows не добавляется.

## Пример

Подготовьте доверенный минимальный Linux rootfs с `/bin/sh` и нужными инструментами либо offline OCI Image Layout. При импорте проверяются пути, SHA-256 и поддерживаемые типы слоёв. Подписи издателей пока не проверяются; импортируйте только доверенные данные. OCI whiteouts и hardlinks пока отклоняются.

```sh
petri doctor
petri stack import-rootfs node22 /path/to/trusted/rootfs
# либо: petri stack import-oci node22 /path/to/oci-layout
petri create 'исправить тесты' --repo /path/to/repository --stack node22 --prepare
petri list
petri run lab-<id> -- /bin/sh -c 'node --version; npm test'
petri diff lab-<id>
petri checkpoint lab-<id> 'тесты исправлены'
petri commit lab-<id> -m 'Fix tests'
petri merge lab-<id> --yes
petri discard lab-<id>
```

`lab-<id>` замените фактическим идентификатором из `create`. Источник должен иметь начальный коммит; экспортируются только файлы HEAD, без untracked/dirty файлов и без `.env`, `.env.*`, `.ssh`, `docker.sock`. Diff показывает все изменения относительно baseline, включая уже закоммиченные в лабе. Merge создаёт `petri/review-*`, сохраняя main, рабочие файлы и секреты исходного репозитория. Push и открытие PR выполняются отдельно пользователем.

Для создания и немедленного запуска:

```sh
petri create 'выполнить тесты' --repo /path/to/repository --stack node22 -- /bin/sh -c 'npm test'
```

`--detach` запускает отдельный supervisor; его диагностический stderr находится рядом с meta.json. Повторный запуск, diff, commit, checkpoint, restore и discard одной лабы сериализуются блокировкой. Снапшоты возможны только после остановки. После аварийного завершения supervisor статус может остаться Running; автоматическое восстановление пока не реализовано. Не удаляйте активную лабу вручную.

## Конфигурация

```yaml
stack: node22
policy:
  network: []
  deny_paths: [".env", ".env.*", ".ssh"]
  memory_bytes: 1073741824
  cpu_seconds: 300
  max_processes: 128
```

Неизвестные поля, сетевые allowlist и пользовательские deny_paths отклоняются, поскольку их полное обеспечение пока отсутствует. Исключения файлов относятся к экспорту и Git-снапшотам; агент может создавать собственные файлы с такими именами, но они не принимаются в Git-снапшот.

`memory_bytes` ограничивает виртуальную память **отдельного процесса**, `cpu_seconds` — его CPU-время. Это не суммарный бюджет лаборатории: cgroup-лимиты, дисковая квота и автоматический circuit breaker пока отсутствуют. Локальный хост и сам runtime входят в доверенную базу; защита от уязвимостей ядра не заявляется.

Файлы состояния находятся в каталоге данных платформы: Linux `$XDG_DATA_HOME/petri` или `~/.local/share/petri`. Можно задать `--home /path` или `PETRI_HOME`. Каталог должен быть приватным и находиться вне репозитория и импортируемого rootfs.

## Журналы и Docker API

`petri logs <id>` читает захваченный stdout/stderr, `--replay` воспроизводит тайминги. Формат asciicast v2 записывает **pipe output**, без PTY, интерактивного ввода и полной agent trajectory. Журнал хоста не доступен на запись из лабы. Vault отсутствует: не передавайте секреты в task, аргументах или выводе, они могут попасть в метаданные и журналы. Вспомогательный redactor не является защитой секретов.

`petri compat up` открывает приватный Unix socket `<home>/docker.sock` и реализует только read-only discovery/list/inspect. Любая мутация возвращает HTTP 501. Это **не поддержка Docker Compose**. Существующий socket никогда не удаляется автоматически; после аварии проверьте отсутствие сервиса перед ручной очисткой.

## Приёмка

Обычный test suite проверяет Git-защиту, политики, OCI, журналирование, Docker read API и жизненный цикл данных. Реальный Linux E2E запускается отдельно на хосте, где доступны обязательные механизмы:

```sh
PETRI_E2E_BUSYBOX=/bin/busybox cargo test --test runtime_linux -- --ignored --nocapture
```

Требуется статически собранный BusyBox. CI содержит отдельную обязательную Linux job для этого теста; portable matrix не выдаётся за E2E трёх ОС. Coverage >80%, fuzz/chaos, аудит внешними специалистами, биометрия, подписанные установщики, perf и dogfooding остаются отдельными незакрытыми требованиями.
