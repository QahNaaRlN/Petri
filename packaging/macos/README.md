# macOS feasibility packaging

Эти plist — **входы первого signing/launch spike**, не release-конфигурация и
не доказанная per-lab policy. Runtime в этой ветке не добавлен.

`feasibility-runner.entitlements.plist` запрашивает только App Sandbox.
`feasibility-child.entitlements.plist` содержит только App Sandbox + inherit
для соответствующего embedded CLI inheritance опыта Apple. Второй файл не
назначается главному controller/launcher.

Нет network client/server, app groups, пользовательских файлов, automation,
Keychain, debugger, JIT, отключения library validation или temporary exceptions.
Такой минимальный набор может оказаться недостаточным для выбранного Python:
это результат spike, а не повод добавлять широкие права автоматически.

Bundle identity, Team ID, source/signature requirements, launch mode и per-lab
container model выбираются и фиксируются до опыта. Здесь нет выдуманного
сертификата, ключа или provisioning profile. Не выполняется автоматическая
подпись, импорт identity, установка пакета или изменение компьютера.

Ad-hoc/локальный prototype не объявляется Developer ID/notarized выпуском.
Наличие entitlement в подписи не подтверждает его runtime effect. Следуйте
[macOS ТС](../../docs/macos-technical-specification.md) и
[оценке API](../../docs/macos-api-assessment.md).
