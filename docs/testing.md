# Проверка Petri

Этот документ описывает воспроизводимые команды. Фактически полученные результаты приведены отдельно в [status.md](status.md); инструкция не является отчётом об успешном запуске.

## Обычная сборка и host-side тесты

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
cargo build --locked --release
```

Host-side тесты используют настоящие локальные Git objects и rootfs/OCI fixtures: исходный HEAD и dirty source не меняются при публикации review-ветки; снимок восстанавливает workspace вместе с Git; audit не откатывается; ошибочные имена, небезопасные ссылки, blobs с неверным hash и неподдержанные архивные entries отклоняются. Они не требуют системного Git и не заменяют kernel isolation E2E.

На ограниченном executor тест Unix socket может получить EPERM от внешнего tool sandbox. Такой тест следует запускать в подходящей среде, а отказ не скрывать. Для socket test не требуется давать самому Petri root либо менять профиль sandbox агента.

## Реальная Linux-изоляция

Для настоящего E2E нужны Linux >=6.2 с включённым Landlock ABI >=3, доступные user/mount/PID/network namespaces и статический BusyBox для минимального rootfs. Требования ядра не равны достаточности: LSM/контейнерная политика может запрещать userns. Сначала изучите вывод `petri doctor`.

```sh
PETRI_E2E_BUSYBOX=/bin/busybox cargo test --locked --test runtime_linux -- --ignored --nocapture
```

Тест создаёт одноразовый rootfs и лабораторию, проверяет отсутствие host env/host Git/blackbox внутри, невозможность записи в rootfs/run, отсутствие внешней сети, успешную запись workspace и неизменность хостовых маркеров. Он не содержит разрушительной команды на хосте. Обычный `cargo test` оставляет этот тест ignored: число skipped тестов нельзя выдавать за успешный isolation test.

На пользовательском компьютере не следует автоматически менять sysctl/LSM ради прохождения проверки. Пример CI делает такие изменения только на одноразовом hosted runner и не является инструкцией изменять рабочую машину. Отказ userns должен давать ошибку до исполнения команды; запрещён fallback на host exec.

Этот E2E ещё не доказывает устойчивость к всем kernel exploits, полную работу PID1/reaping/signals, отсутствие ресурсного DoS, совместимость всех stacks, Landlock ABI на старых ядрах или поддержку macOS/Windows.

## Дополнительные релизные гейты

Покрытие измеряется отдельным coverage tool с опубликованным отчётом; порог >80% не выводится из количества тестов. `cargo audit` требует актуальной базы advisories и не анализирует автоматически все дефекты vendored C-кода. Fuzz/chaos, perf, подписанные пакеты, реальная биометрия и dogfooding выполняются отдельно.

Сравнение perf должно фиксировать CPU/RAM/ядро/файловую систему, cold/warm stack, длительность команды, число запусков и способ расчёта p95. Сравнивать metadata-only `--prepare` с настоящим container startup некорректно. Скачивание стека учитывается отдельно от тёплого старта.

## Целостность исходных документов

```sh
cd docs/sources
sha256sum -c SHA256SUMS
```

Эти хеши проверяют сохранённые копии, а не авторство или подпись исходных документов.


## Windows native candidate

`cargo test` на Linux/macOS проверяет переносимую логику и явный отказ Windows namespace. Cross-compile Windows проверяет типы и linking; это не запуск LPAC. Реальная suite использует [отдельный qualification harness](../scripts/qualify-windows.py) и требует обычный Windows 11 24H2 x64 аккаунт, доверенный portable CPython 3.12 и независимый manifest. Точная команда и ограничения приведены в [руководстве кандидата](windows-native-candidate.md). Ignored/skipped не считаются успехом изоляции. Manual workflow не запускается автоматически на произвольном self-hosted runner.
