# GitHub → Petri Human View

Этот bridge дописывает события PR и результаты workflow в существующие базы `Petri Human View/WorkNode` и `Evidence`. [Petri Live](https://krmiftakhov.fibery.io/Petri_Human_View/43) читает эти записи и обновляет диаграммы. Старые whiteboard остаются отдельными визуальными срезами.

Bridge не переписывает ожидания, решения, готовность реализации или человеческую приёмку. `PASS` означает только `conclusion=success` указанного workflow. Содержимое test logs и native qualification reports не анализируется: `Наблюдалось нативное исполнение=false`, включая metadata workflow Windows. Для `CI` используется `portable_ci`; metadata Windows native qualification хранится как `source` без присвоения native proof.

## Установка

Пути в репозитории:

| Подготовленный файл | Путь после установки |
| --- | --- |
| `fibery_sync.py` | `scripts/sync_fibery.py` |
| `test_fibery_sync.py` | `tests/test_fibery_sync.py` |
| `fibery-sync.yml` | `.github/workflows/fibery-sync.yml` |
| этот документ | `docs/human-view-sync.md` |

Изменения проходят рабочую ветку → PR в `dev` → promotion PR в `main`, как требует repository governance. Новый sync workflow не добавляется к пяти required checks и не заменяет ни один из них. События `pull_request_target` / `workflow_run` начинают работать после появления файла в default `main`. Тесты Python подхватывает существующая portable CI команда `python -m unittest discover -s tests -p 'test_*.py' -v`.

1. В Fibery создайте API token для отдельного пользователя/сервисной учётной записи с доступом только к нужному workspace и базам Human View, насколько позволяет ваш тариф. Bridge читает Spec/PlanVersion и enum options; создаёт WorkNode/Evidence, заполняет их документы и добавляет связь Evidence. На уровне bridge запрещены изменения остальных сущностей. Сам API token может иметь более широкие права пользователя — не считайте ограничения скрипта отдельным scope токена.
2. В [Actions secrets Petri](https://github.com/QahNaaRlN/petri/settings/secrets/actions) добавьте repository secret **`FIBERY_API_TOKEN`**. Значение вводится только в защищённую форму GitHub, не в чат, код, `.env` коммит или командную строку с историей. Токен Fibery Custom App Dev для этой задачи не подходит.
3. Откройте workflow **Petri Human View sync** в GitHub Actions и выполните **Run workflow**. Ручной запуск только читает схему/enum options и возвращает `read_only_configuration_check_passed`, записей — 0. Он проверяет доступ чтения и конфигурацию; фактическая запись проверяется первым аннотированным событием.
4. Добавьте привязку в настоящий PR и проверьте появление двух связанных записей в Fibery. После этого события PR и CI этого PR импортируются автоматически. До настройки service token рабочий импорт не считается включённым.

## Явная связь с планом

Вне блока кода и HTML-комментария в PR body укажите активную строку:

```text
Petri: S-001 @ PV-001-2
```

Пример выше показывает синтаксис. Используйте реальные ключи изменяемой спеки и той версии ожиданий, к которой относится работа. Для нескольких спек укажите отдельную строку для каждой. Альтернатива для одной привязки — две строки `Petri-Spec: S-001` и `Petri-Plan: PV-001-2`.

Упоминания вроде «относятся к S-001», один ключ в названии, примеры внутри code fences, отступного Markdown-кода (четыре пробела или таб), quoted blocks или HTML-комментариев не назначают версию. Спека и версия должны уже существовать, а версия — принадлежать выбранной спеке. Неизвестная или конфликтующая привязка останавливает импорт до исправления; Spec.current_plan никогда не используется для ретроспективного угадывания.

Для CI bridge читает явные строки в `workflow_run.head_commit.message` и в title/body связанных PR, полученных через read-only GitHub API. PR body отражает момент импорта, поэтому provenance прямо отмечает эту аналитическую привязку и не выдаёт её за историческое назначение. Если GitHub не передал PR association и commit не аннотирован, событие пропускается. Сопоставления по имени ветки и скрытого backfill нет. В частности, promotion PR следует аннотировать отдельно, если его CI нужно отнести к конкретной спеке.

Не добавляйте действующие примеры `Petri:` в общий PR template: они будут означать реальную привязку каждого нового PR. В template можно оставить пояснение и пример внутри fenced code или HTML-комментария.

## Повторные запуски и история

PR observation получает ключ из repository/номер/action/source updated_at/HEAD SHA/снимка title+body. CI observation — из repository/run id/run attempt. Новый attempt получает новую запись, предыдущий результат сохраняется. Повторная доставка того же события использует те же ключи.

Перед записью проверяются все bindings. При частичном сбое повторный запуск дописывает отсутствующую сущность, пустые документы и связь. Непустые документы, включая человеческие замечания, не заменяются. Конфликт неизменяемых URL/SHA/вердикта/привязки останавливает импорт. Bridge не создаёт predecessor/causes: соседство PR и CI само по себе не доказывает причину или реальный порядок всех действий.

Проверка пустоты документа — отдельный GET перед PUT, без подтверждённого API compare-and-swap. Она сохраняет уже записанный человеческий текст, но не гарантирует атомарной защиты от одновременного редактирования между этими запросами. Первичное заполнение и repair пустых документов следует выполнять без параллельной ручной правки этих же новых документов; это правило работы, не immutable ACL.

В workflow отдельный шаг вычисляет event-specific concurrency key без секретов. Разные события не делят одну pending-очередь GitHub, а точные дубликаты сериализуются. Native unique constraint на поле ключа в Fibery не создаётся; обнаруженные дубликаты требуют review. Для параллельного запуска скрипта вне этого workflow обеспечьте такую же сериализацию одного source event. Обработчик не является гарантированным журналом всех событий GitHub: он зависит от доставки Actions; для пропущенного события используйте повторный запуск его sync workflow. Историческая миграция событий отдельно не выполнена.

Скрипт не исполняет PR-код, не читает workflow artifacts, не обращается к URL из PR body и не печатает event text или HTTP response bodies. В обеих jobs checkout выполняется с защищённой default branch; GitHub token имеет только `contents/actions/pull-requests: read`. Fibery credential передаётся только последнему Python шагу. Действия service account и scope токена остаются границей доверия.

## Локальная проверка

Python 3.10+; сторонние пакеты не нужны:

```sh
python -m unittest discover -s tests -p 'test_fibery_sync.py' -v
python scripts/sync_fibery.py --event /path/to/event.json --event-name pull_request_target --dry-run
```

Dry run не записывает в Fibery. Для workflow-run с PR association нужен read-only `GITHUB_TOKEN`, чтобы прочитать явные annotations. Ни локальные unit tests, ни read-only configuration check не доказывают, что реальный API credential уже разрешает создание сущностей и документов; это подтверждается фактическим аннотированным импортом.
