# macOS native candidate — пакет подготовки

Дата: **2026-10-27, Asia/Yekaterinburg**. Ветка `feat/macos-native-candidate`.
Основа: Windows-кандидат `69f6009` + актуализация имён веток `a26220a`.
Статус: **PREPARED / runtime NOT IMPLEMENTED / native qualification UNVERIFIED**.

## Материалы для следующего исполнителя

| Документ | Назначение |
| --- | --- |
| [ТЗ](macos-requirements.md) | Цель, профиль, обязательные свойства, пределы первого пакета |
| [ТС](macos-technical-specification.md) | Helper/controller, контракты, gates, lifecycle и evidence |
| [Оценка Apple API](macos-api-assessment.md) | Подтверждённые возможности и ограничения с первичными источниками |
| [План MP-00…09](macos-implementation-plan.md) | Порядок кодовых пакетов, зависимости и правила совместимости |
| [Приёмка](macos-acceptance.md) | 15 групп сценариев, independent oracles и инфраструктура |
| [Feasibility packaging](../packaging/macos/README.md) | Минимальные entitlement plist без signing identities или установки |
| [Read-only preflight](../scripts/preflight-macos.sh) | OS/build/account inventory и optional static code inspection |

## Принятое направление

Нативная macOS без Docker, MXC и Linux guest. Первым исследуется публичный
App Sandbox с отдельным подписанным helper. Первый qualification target —
macOS 26 / arm64 / локальный APFS / обычный non-admin account / собственный
headless CPython 3.12 offline fixture. Exact build, Python patch, SDK и signing
выбираются и фиксируются на реальном Mac, а не подставляются из этой Linux-среды.

До production/backend admission необходимо доказать: исполнение выбранных
инструментов, разграничение лабораторий, владение/остановку всех потомков,
принятый ресурсный профиль, network/IPC policy и безопасный collector. Нельзя
заменить это наличием подписи, отдельным cwd, общим app-container или `killpg`.
Неудача обязательного gate приводит к architectural blocker, а не к скрытому
fallback на deprecated policy API либо запуску нагрузки без ограничений.

Windows native-v2/control-v1 и Linux legacy сохраняются. Общие интерфейсы V3
и macOS protocol остаются проектом следующего code package. В текущем CLI
команда macOS runtime не добавлена и возможность её запуска не объявляется.

## С чего начать реализацию

1. Выполнить MP-00: закрепить модель угроз, единицы и mandatory capabilities,
   входы опытов, точный host/signing profile и versioned common contracts.
2. На собственном выбранном Mac снять read-only preflight. Для незакреплённого
   profile утилита вернёт inventory и ненулевой статус; это ожидаемое поведение.
3. Выполнить MS-01…08 по плану на собственных canaries. Отдельно принять либо
   отклонить механизм; сохранить факты, fixture и hashes.
4. Реализовать common refactoring, macOS adapter/toolchain/storage/CLI только
   в соответствующих пакетах, не меняя смысл Windows/Linux metadata.
5. Провести настоящую macOS qualification; package signing/notarization и
   real-agent admission остаются отдельными проверками.

Read-only пример после выбора actual values:

```sh
sh scripts/preflight-macos.sh \
  --profile macos-native-python312-arm64/v1 \
  --expected-version "$PETRI_MAC_VERSION" \
  --expected-build "$PETRI_MAC_BUILD" \
  --expected-arch arm64
```

Preflight не запускает и не сертифицирует sandbox. Даже exit 0 означает только
завершение inventory, с `isolation_verified=false`. Чтение планов и запуск
read-only inventory не требуют подписи или установки helper из этого пакета.

## Выполненные проверки подготовки

Проверено на Linux: 69 Rust tests и 64 Python tests (в том числе 8 новых preflight contract tests) прошли; fmt, strict clippy и release build прошли без изменения runtime-кода. Shell syntax, оба plist и все локальные Markdown-ссылки проверены. На Linux preflight даёт UNSUPPORTED_HOST с isolation_verified=false; Mac workload не запускался.

Native macOS host,
helper/signing effects, process-tree containment и aggregate resource limits
здесь **не проверены**. Нет результата CI по macOS isolation и нет release.
